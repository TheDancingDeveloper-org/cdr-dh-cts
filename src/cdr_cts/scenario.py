"""Scenario model, registry and execution context."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, ClassVar, NoReturn

import httpx

from .config import CertPair, Config
from .fapi import FapiClient, oauth_error

if TYPE_CHECKING:
    from .ecosystem import Ecosystem
    from .jose import SigningKey


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"
    #: Steps only: recorded for the report, does not affect the outcome.
    INFO = "INFO"


class Requirement(str, Enum):
    DATA_HOLDER = "data_holder"
    ECOSYSTEM = "ecosystem"
    CLIENT = "client"
    AUTHORIZATION = "authorization"
    RESOURCE = "resource"
    MTLS_EDGE = "mtls_edge"
    ALTERNATE_CERT = "alternate_cert"


REQUIREMENT_HINTS = {
    Requirement.DATA_HOLDER: "set dh.discovery_url",
    Requirement.ECOSYSTEM: "start the mock ecosystem and set ecosystem.admin_url",
    Requirement.CLIENT: "a registered client: run Create Client Registration (4) or set adr.client_id",
    Requirement.AUTHORIZATION: "set authorization.adapter",
    Requirement.RESOURCE: "set dh.resource_base_url",
    Requirement.MTLS_EDGE: "set mtls_edge: true and tls.client.cert/key",
    Requirement.ALTERNATE_CERT: "set tls.alternate_client.cert/key (a second CDR certificate)",
}


@dataclass
class Step:
    title: str
    status: Status
    detail: str = ""

    def to_dict(self) -> dict:
        return {"title": self.title, "status": self.status.value, "detail": self.detail}


@dataclass
class ScenarioResult:
    number: int
    id: str
    title: str
    section: str
    status: Status
    steps: list[Step] = field(default_factory=list)
    reason: str = ""
    duration: float = 0.0

    def to_dict(self) -> dict:
        return {
            "number": self.number,
            "id": self.id,
            "title": self.title,
            "section": self.section,
            "status": self.status.value,
            "reason": self.reason,
            "duration_seconds": round(self.duration, 3),
            "steps": [s.to_dict() for s in self.steps],
        }


class SkipScenario(Exception):
    pass


class StepFailed(Exception):
    pass


class Scenario:
    """One CTS scenario. Subclasses set the metadata and implement ``run``."""

    number: ClassVar[int]
    id: ClassVar[str]
    title: ClassVar[str]
    #: Section of the CTS Data Holder Technical Guidance 5.3.0.
    section: ClassVar[str]
    requires: ClassVar[tuple[Requirement, ...]] = ()
    #: Scenarios whose state this one uses; they run first and must pass.
    depends_on: ClassVar[tuple[int, ...]] = ()

    def run(self, ctx: ScenarioContext) -> None:
        raise NotImplementedError


REGISTRY: dict[int, type[Scenario]] = {}


def scenario(cls: type[Scenario]) -> type[Scenario]:
    """Class decorator registering a scenario under its test-plan number."""
    if cls.number in REGISTRY:
        raise ValueError(f"scenario {cls.number} registered twice ({REGISTRY[cls.number].__name__}, {cls.__name__})")
    REGISTRY[cls.number] = cls
    return cls


def all_scenarios() -> list[type[Scenario]]:
    from . import scenarios  # noqa: F401  (importing registers them)

    return [REGISTRY[n] for n in sorted(REGISTRY)]


_SECRET = re.compile(r'("?(?:access_token|refresh_token|id_token|client_assertion|request|software_statement)"?\s*[:=]\s*"?)([A-Za-z0-9._~+/=-]{16,})')


def redact(text: str) -> str:
    """Mask bearer material in text bound for a report."""
    return _SECRET.sub(lambda m: f"{m.group(1)}<redacted>", text)


def describe(response: httpx.Response, limit: int = 300) -> str:
    body = redact(response.text.strip().replace("\n", " "))
    return f"HTTP {response.status_code}" + (f": {body[:limit]}" if body else "")


class ScenarioContext:
    """State shared by the scenarios of one run, plus the step-recording API."""

    def __init__(
        self,
        config: Config,
        *,
        adr_key: SigningKey,
        ecosystem: Ecosystem | None,
        adapter: Callable[..., str] | None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.config = config
        self.adr_key = adr_key
        self.ecosystem = ecosystem
        self.adapter = adapter
        self.transport = transport
        self.state: dict[str, Any] = {}
        self.steps: list[Step] = []
        self.results: dict[int, ScenarioResult] = {}
        self._client: FapiClient | None = None
        self._extra_clients: list[FapiClient] = []
        self._ecosystem_ok: bool | None = None

    # ------------------------------------------------------------- clients

    @property
    def client(self) -> FapiClient:
        if self._client is None:
            self._client = FapiClient(self.config, self.adr_key, transport=self.transport)
        return self._client

    def client_with(self, cert: CertPair | None) -> FapiClient:
        """The simulated ADR presenting a different (or no) client certificate."""
        other = self.client.with_cert(cert)
        self._extra_clients.append(other)
        return other

    def close(self) -> None:
        for c in [self._client, *self._extra_clients]:
            if c is not None:
                c.close()
        if self.ecosystem is not None:
            self.ecosystem.close()

    # ------------------------------------------------------------- prerequisites

    def satisfies(self, requirement: Requirement) -> bool:
        cfg = self.config
        if requirement is Requirement.DATA_HOLDER:
            return bool(cfg.dh.discovery_url)
        if requirement is Requirement.ECOSYSTEM:
            if self._ecosystem_ok is None:
                self._ecosystem_ok = self.ecosystem is not None and self.ecosystem.reachable()
            return self._ecosystem_ok
        if requirement is Requirement.CLIENT:
            return bool(self.client.client_id)
        if requirement is Requirement.AUTHORIZATION:
            return self.adapter is not None
        if requirement is Requirement.RESOURCE:
            return bool(cfg.dh.resource_base_url)
        if requirement is Requirement.MTLS_EDGE:
            return cfg.mtls_edge and cfg.tls.client.present
        if requirement is Requirement.ALTERNATE_CERT:
            return cfg.tls.alternate_client.present
        return False

    # ------------------------------------------------------------- step recording

    def record(self, title: str, status: Status, detail: str = "") -> None:
        self.steps.append(Step(title, status, redact(detail)))

    def info(self, title: str, detail: str = "") -> None:
        self.record(title, Status.INFO, detail)

    def check(self, title: str, ok: bool, detail: str = "", *, fatal: bool = True) -> bool:
        self.record(title, Status.PASS if ok else Status.FAIL, detail)
        if not ok and fatal:
            raise StepFailed(title)
        return ok

    def fail(self, title: str, detail: str = "") -> NoReturn:
        self.record(title, Status.FAIL, detail)
        raise StepFailed(title)

    def skip(self, reason: str) -> NoReturn:
        raise SkipScenario(reason)

    def expect_status(
        self, title: str, response: httpx.Response, expected: Iterable[int], *, fatal: bool = True
    ) -> bool:
        expected = set(expected)
        ok = response.status_code in expected
        return self.check(title, ok, "" if ok else f"expected {_codes(expected)}, got {describe(response)}", fatal=fatal)

    def expect_oauth_error(
        self,
        title: str,
        response: httpx.Response,
        allowed: Sequence[tuple[Iterable[int], Iterable[str]]],
        *,
        fatal: bool = False,
    ) -> bool:
        """Pass when (status, ``error``) matches one of the ``allowed`` combinations."""
        error = oauth_error(response)
        ok = any(response.status_code in set(codes) and error in set(errors) for codes, errors in allowed)
        if ok:
            return self.check(title, True, f"HTTP {response.status_code} {error}", fatal=fatal)
        wanted = " or ".join(f"{_codes(set(c))} {'/'.join(sorted(set(e)))}" for c, e in allowed)
        return self.check(title, False, f"expected {wanted}; got {describe(response)}", fatal=fatal)


def _codes(codes: set[int]) -> str:
    if codes and codes == set(range(min(codes), max(codes) + 1)) and len(codes) > 3:
        return f"HTTP {min(codes)}-{max(codes)}"
    return "HTTP " + "/".join(str(c) for c in sorted(codes))

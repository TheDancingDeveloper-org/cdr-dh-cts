"""Client for the mock ecosystem's admin API (simulated Register + simulated ADR endpoints)."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import Any

import httpx

from .errors import CtsError
from .ssa import Participant


class Ecosystem:
    def __init__(self, admin_url: str, timeout: float = 30.0) -> None:
        self.admin_url = admin_url.rstrip("/")
        self.http = httpx.Client(base_url=self.admin_url, timeout=timeout)

    def close(self) -> None:
        self.http.close()

    def _call(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            response = self.http.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise CtsError(f"mock ecosystem unreachable at {self.admin_url}: {exc}") from exc
        if response.status_code >= 400:
            raise CtsError(f"mock ecosystem {method} {path} returned HTTP {response.status_code}: {response.text[:200]}")
        return response.json() if response.content else None

    def health(self) -> dict:
        return self._call("GET", "/admin/health")

    def now(self) -> float:
        """The mock's clock: request-log timestamps are compared against this, not the harness's."""
        return float(self.health()["time"])

    def reachable(self) -> bool:
        try:
            self.health()
        except CtsError:
            return False
        return True

    def set_participant(self, participant: Participant) -> None:
        self._call("PUT", "/admin/participant", json=participant.to_dict())

    def mint_ssa(self, overrides: Mapping[str, Any] | None = None) -> str:
        return self._call("POST", "/admin/ssa", json={"overrides": dict(overrides or {})})["ssa"]

    def set_software_product_status(self, status: str) -> None:
        self._call("PUT", "/admin/status/software-product", json={"status": status})

    def set_data_recipient_status(self, status: str) -> None:
        self._call("PUT", "/admin/status/data-recipient", json={"status": status})

    def requests(self, *, since: float | None = None, path_contains: str | None = None) -> list[dict]:
        params: dict[str, Any] = {}
        if since is not None:
            params["since"] = since
        if path_contains:
            params["path_contains"] = path_contains
        return self._call("GET", "/admin/requests", params=params)["requests"]

    def callbacks(self, state: str | None = None) -> list[dict]:
        return self._call("GET", "/admin/callbacks", params={"state": state} if state else {})["callbacks"]

    def wait_for(
        self,
        fetch: Callable[[], list[dict]],
        timeout: float,
        poll: float = 2.0,
    ) -> list[dict]:
        """Poll ``fetch`` until it returns a non-empty list or ``timeout`` elapses."""
        deadline = time.monotonic() + timeout
        while True:
            found = fetch()
            if found or time.monotonic() >= deadline:
                return found
            time.sleep(min(poll, max(0.0, deadline - time.monotonic())))

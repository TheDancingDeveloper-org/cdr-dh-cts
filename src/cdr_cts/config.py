"""Harness configuration.

Loaded from YAML. Unknown keys are an error (a typo should not silently fall back
to a default), ``${VAR}`` references are expanded from the environment so secrets
stay out of the file, and relative paths resolve against the config file's
directory.
"""

from __future__ import annotations

import dataclasses
import os
import types
import typing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Union

import yaml


class ConfigError(ValueError):
    """The configuration file is missing, malformed or inconsistent."""


@dataclass
class CertPair:
    """A client certificate and its private key (PEM files)."""

    cert: Path | None = None
    key: Path | None = None

    @property
    def present(self) -> bool:
        return bool(self.cert and self.key)


@dataclass
class DataHolderConfig:
    #: ``/.well-known/openid-configuration`` URL of the DH brand under test.
    discovery_url: str = ""
    #: Base of the CDR resource APIs, e.g. ``https://mtls.dh.example/cds-au/v1``.
    resource_base_url: str = ""
    #: Path of Get Customer below ``resource_base_url``.
    get_customer_path: str = "/common/customer"
    #: ``x-v`` sent to Get Customer.
    get_customer_version: str = "1"


@dataclass
class EcosystemConfig:
    #: How the DH reaches the mock Register and simulated ADR (must be reachable from the DH).
    public_base_url: str = "http://localhost:8080"
    #: How the harness reaches the mock's admin API.
    admin_url: str = "http://localhost:8080"


@dataclass
class AdrConfig:
    #: Directory holding ``adr.pem`` (and, for the mock, ``register.pem``).
    keys_dir: Path = Path("keys")
    key_file: str = "adr.pem"
    legal_entity_id: str = "8a2e7c4d-0000-4000-8000-00000000a001"
    legal_entity_name: str = "CTS Harness Data Recipient"
    brand_id: str = "8a2e7c4d-0000-4000-8000-00000000b001"
    brand_name: str = "CTS Harness Brand"
    software_product_id: str = "8a2e7c4d-0000-4000-8000-00000000c001"
    software_product_name: str = "CTS Harness Software Product"
    #: Scopes the software product holds (the SSA ``scope`` claim).
    scope: str = "openid profile common:customer.basic:read cdr:registration"
    #: Scopes requested in authorisation requests. Never ``cdr:registration``: that scope is
    #: only for client-credentials access to the DCR endpoints, not for consumer consent.
    authorization_scope: str = "openid profile common:customer.basic:read"
    #: ``sharing_duration`` in seconds; > 0 makes the consent ongoing (refresh token issued).
    sharing_duration: int = 7776000
    acr: str = "urn:cds.au:cdr:2"
    #: Use a client the DH already registered; empty means scenario 4 registers one.
    client_id: str = ""
    #: ``aud`` of client assertions: ``endpoint`` (URL being invoked) or ``issuer``.
    assertion_audience: str = "endpoint"


@dataclass
class TlsConfig:
    #: CDR client certificate used for all mTLS traffic and bound to issued tokens.
    client: CertPair = field(default_factory=CertPair)
    #: CA bundle used to verify the DH's server certificates.
    ca_bundle: Path | None = None
    verify: bool = True
    #: A second, valid CDR certificate *not* bound to the access token (scenario 6).
    alternate_client: CertPair = field(default_factory=CertPair)
    #: Negative certificates for scenario 2.
    expired_client: CertPair = field(default_factory=CertPair)
    self_signed_client: CertPair = field(default_factory=CertPair)
    revoked_client: CertPair = field(default_factory=CertPair)


@dataclass
class AuthorizationConfig:
    #: ``module:function`` completing consumer authentication and consent.
    adapter: str = "cdr_cts.authorize:direct_redirect"
    options: dict = field(default_factory=dict)


@dataclass
class HooksConfig:
    #: ``module:function(arrangement_id, options)`` that makes the DH revoke an
    #: arrangement (scenario 11). Empty means wait for an operator to do it.
    dh_revoke_arrangement: str = ""
    options: dict = field(default_factory=dict)


@dataclass
class TimeoutsConfig:
    http: float = 30.0
    #: How long the DH has to poll the Register after a status change (CTS allows 5 minutes).
    register_poll: float = 300.0
    #: How long to wait for a DH-side action (DH-initiated revocation).
    dh_action: float = 300.0
    #: How long the ``ecosystem_callback`` adapter waits for the redirect.
    authorization: float = 300.0


@dataclass
class Config:
    plan: str = "5.3.0"
    #: Identifies this DH brand in mock URLs, as the CTS Conformance ID does.
    conformance_id: str = "00000000-0000-4000-8000-000000000000"
    #: Industry segment used in Register paths (``banking``, ``energy``, ``all``).
    industry: str = "banking"
    #: Whether the DH enforces mTLS on its secured endpoints (scenarios 2 and 6).
    mtls_edge: bool = True
    out_dir: Path = Path("out")
    dh: DataHolderConfig = field(default_factory=DataHolderConfig)
    ecosystem: EcosystemConfig = field(default_factory=EcosystemConfig)
    adr: AdrConfig = field(default_factory=AdrConfig)
    tls: TlsConfig = field(default_factory=TlsConfig)
    authorization: AuthorizationConfig = field(default_factory=AuthorizationConfig)
    hooks: HooksConfig = field(default_factory=HooksConfig)
    timeouts: TimeoutsConfig = field(default_factory=TimeoutsConfig)
    #: File the configuration was loaded from, if any.
    source: Path | None = None

    # ---- simulated ecosystem URLs, as the DH sees them -----------------------

    @property
    def register_base_url(self) -> str:
        return f"{self.ecosystem.public_base_url.rstrip('/')}/cts/{self.conformance_id}/register"

    @property
    def adr_base_url(self) -> str:
        return f"{self.ecosystem.public_base_url.rstrip('/')}/cts/{self.conformance_id}/dr"

    @property
    def adr_jwks_uri(self) -> str:
        return f"{self.adr_base_url}/jwks"

    @property
    def redirect_uri(self) -> str:
        return f"{self.adr_base_url}/signin"

    @property
    def adr_revocation_uri(self) -> str:
        return f"{self.adr_base_url}/arrangements/revoke"

    @property
    def adr_key_path(self) -> Path:
        return self.adr.keys_dir / self.adr.key_file

    @classmethod
    def load(cls, path: str | Path) -> Config:
        path = Path(path)
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except FileNotFoundError as exc:
            raise ConfigError(f"configuration file not found: {path}") from exc
        except yaml.YAMLError as exc:
            raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
        config = cls.from_dict(raw, base_dir=path.resolve().parent)
        config.source = path
        return config

    @classmethod
    def from_dict(cls, data: dict, base_dir: Path | None = None) -> Config:
        if not isinstance(data, dict):
            raise ConfigError("configuration root must be a mapping")
        base_dir = base_dir or Path.cwd()
        config = _build(cls, data, base_dir, "config")
        _resolve_paths(config, base_dir)
        return config


def _expand(value: Any) -> Any:
    return os.path.expandvars(value) if isinstance(value, str) else value


def _convert(tp: Any, value: Any, base_dir: Path, where: str) -> Any:
    origin = typing.get_origin(tp)
    if origin in (Union, types.UnionType):
        args = [a for a in typing.get_args(tp) if a is not type(None)]
        if value is None or value == "":
            return None
        return _convert(args[0], value, base_dir, where)
    if dataclasses.is_dataclass(tp):
        if not isinstance(value, dict):
            raise ConfigError(f"{where} must be a mapping")
        return _build(tp, value, base_dir, where)
    value = _expand(value)
    if tp is Path:
        resolved = Path(value)
        return resolved if resolved.is_absolute() else (base_dir / resolved).resolve()
    if tp is bool:
        if isinstance(value, str):
            if value.lower() in ("true", "yes", "1"):
                return True
            if value.lower() in ("false", "no", "0"):
                return False
        if isinstance(value, bool):
            return value
        raise ConfigError(f"{where} must be a boolean")
    if tp in (int, float):
        try:
            return tp(value)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{where} must be a number") from exc
    if tp is str:
        return "" if value is None else str(value)
    if tp is dict or origin is dict:
        if not isinstance(value, dict):
            raise ConfigError(f"{where} must be a mapping")
        return {k: _expand(v) for k, v in value.items()}
    return value


def _build(cls: type, data: dict, base_dir: Path, where: str) -> Any:
    hints = typing.get_type_hints(cls)
    names = {f.name for f in dataclasses.fields(cls) if f.init and f.name != "source"}
    unknown = set(data) - names
    if unknown:
        raise ConfigError(f"unknown key(s) in {where}: {', '.join(sorted(unknown))}")
    kwargs = {name: _convert(hints[name], value, base_dir, f"{where}.{name}") for name, value in data.items()}
    return cls(**kwargs)


def _resolve_paths(instance: Any, base_dir: Path) -> None:
    """Resolve every relative path, including defaults of sections absent from the file."""
    for f in dataclasses.fields(instance):
        if f.name == "source":
            continue
        value = getattr(instance, f.name)
        if isinstance(value, Path) and not value.is_absolute():
            setattr(instance, f.name, (base_dir / value).resolve())
        elif dataclasses.is_dataclass(value):
            _resolve_paths(value, base_dir)

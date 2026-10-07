"""The simulated Accredited Data Recipient: a FAPI 1.0 Advanced client for the CDR profile.

Every request the CTS makes of a Data Holder goes through ``FapiClient``. Methods
return the raw ``httpx.Response`` so scenarios can assert on status codes and
error bodies — including for the requests that are *meant* to fail.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import ssl
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from email.utils import formatdate
from typing import Any
from urllib.parse import urlencode

import httpx

from . import jose
from .config import CertPair, Config
from .errors import AuthorizationError, CtsError

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

#: Endpoints the CDR requires to be protected by mTLS (RFC 8705 aliases apply to these).
MTLS_ENDPOINTS = (
    "token_endpoint",
    "pushed_authorization_request_endpoint",
    "introspection_endpoint",
    "revocation_endpoint",
    "registration_endpoint",
    "cdr_arrangement_revocation_endpoint",
    "userinfo_endpoint",
)


def build_ssl_context(config: Config, cert: CertPair | None) -> ssl.SSLContext:
    if config.tls.verify:
        context = ssl.create_default_context(cafile=str(config.tls.ca_bundle) if config.tls.ca_bundle else None)
    else:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if cert is not None and cert.present:
        context.load_cert_chain(str(cert.cert), str(cert.key))
    return context


def pkce_pair() -> tuple[str, str]:
    verifier = jose.b64url(os.urandom(32))
    challenge = jose.b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


@dataclass
class AuthorizationRequest:
    """One authorisation attempt: the signed request object and the values it binds."""

    state: str
    nonce: str
    code_verifier: str
    request_object: str
    claims: dict = field(default_factory=dict)
    request_uri: str = ""


class FapiClient:
    """HTTP client acting as the CTS Simulated ADR towards one Data Holder brand."""

    def __init__(
        self,
        config: Config,
        key: jose.SigningKey,
        *,
        client_cert: CertPair | None = None,
        metadata: dict | None = None,
        client_id: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.config = config
        self.key = key
        self.client_cert = client_cert if client_cert is not None else config.tls.client
        self.transport = transport
        self.http = httpx.Client(
            verify=build_ssl_context(config, self.client_cert),
            timeout=config.timeouts.http,
            follow_redirects=False,
            headers={"User-Agent": "cdr-dh-cts"},
            transport=transport,
        )
        self._metadata = metadata
        self._dh_jwks: dict | None = None
        self.client_id: str | None = client_id or config.adr.client_id or None

    def with_cert(self, cert: CertPair | None) -> FapiClient:
        """A client sharing this one's DH metadata and client_id but presenting another certificate.

        ``CertPair()`` (empty) presents no certificate at all.
        """
        return FapiClient(
            self.config,
            self.key,
            client_cert=cert or CertPair(),
            metadata=self._metadata,
            client_id=self.client_id,
            transport=self.transport,
        )

    def close(self) -> None:
        self.http.close()

    # ------------------------------------------------------------- discovery

    def fetch_discovery(self) -> httpx.Response:
        if not self.config.dh.discovery_url:
            raise CtsError("dh.discovery_url is not configured")
        return self.http.get(self.config.dh.discovery_url, headers={"Accept": "application/json"})

    @property
    def metadata(self) -> dict:
        if self._metadata is None:
            response = self.fetch_discovery()
            if response.status_code != 200:
                raise CtsError(f"discovery returned HTTP {response.status_code}")
            try:
                self._metadata = response.json()
            except ValueError as exc:
                raise CtsError("discovery document is not JSON") from exc
        return self._metadata

    @property
    def issuer(self) -> str:
        return self.endpoint("issuer")

    def endpoint(self, name: str) -> str:
        """An endpoint URL from discovery, preferring the RFC 8705 mTLS alias for mTLS endpoints."""
        if name in MTLS_ENDPOINTS:
            alias = (self.metadata.get("mtls_endpoint_aliases") or {}).get(name)
            if alias:
                return alias
        value = self.metadata.get(name)
        if not value:
            raise CtsError(f"the DH discovery document has no {name}")
        return value

    def dh_jwks(self) -> dict:
        if self._dh_jwks is None:
            response = self.http.get(self.endpoint("jwks_uri"))
            if response.status_code != 200:
                raise CtsError(f"DH jwks_uri returned HTTP {response.status_code}")
            self._dh_jwks = response.json()
        return self._dh_jwks

    def require_client_id(self) -> str:
        if not self.client_id:
            raise CtsError("no client_id: run Create Client Registration (4) or set adr.client_id")
        return self.client_id

    # ------------------------------------------------------------- client authentication

    def assertion_audience(self, endpoint_url: str) -> str:
        return self.issuer if self.config.adr.assertion_audience == "issuer" else endpoint_url

    def client_assertion(
        self,
        audience: str,
        *,
        claims: Mapping[str, Any] | None = None,
        header: Mapping[str, Any] | None = None,
        alg: str | None = None,
        signature: bytes | None = None,
    ) -> str:
        """A ``private_key_jwt`` client assertion; overrides let scenarios build defective ones."""
        client_id = self.require_client_id()
        now = int(time.time())
        base = {
            "iss": client_id,
            "sub": client_id,
            "aud": audience,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + 300,
        }
        return jose.sign(jose.apply_overrides(base, claims), self.key, header=header, alg=alg, signature=signature)

    def client_auth(self, endpoint_url: str) -> dict:
        """The form fields that authenticate the client to ``endpoint_url``."""
        return {
            "client_id": self.require_client_id(),
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": self.client_assertion(self.assertion_audience(endpoint_url)),
        }

    def post_form(self, url: str, data: Mapping[str, Any], headers: Mapping[str, str] | None = None) -> httpx.Response:
        return self.http.post(
            url,
            content=urlencode({k: v for k, v in data.items() if v is not None}),
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json", **(headers or {})},
        )

    def _authenticated_post(self, endpoint_name: str, data: Mapping[str, Any], auth: Mapping[str, Any] | None) -> httpx.Response:
        url = self.endpoint(endpoint_name)
        form = dict(data)
        form.update(self.client_auth(url) if auth is None else auth)
        return self.post_form(url, form)

    # ------------------------------------------------------------- token endpoint

    def token(self, data: Mapping[str, Any], *, auth: Mapping[str, Any] | None = None) -> httpx.Response:
        """POST to the token endpoint. ``auth`` replaces the (valid) client authentication fields."""
        return self._authenticated_post("token_endpoint", data, auth)

    def client_credentials(self, scope: str = "cdr:registration") -> httpx.Response:
        return self.token({"grant_type": "client_credentials", "scope": scope})

    def exchange_code(self, code: str, code_verifier: str, *, auth: Mapping[str, Any] | None = None) -> httpx.Response:
        return self.token(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.config.redirect_uri,
                "code_verifier": code_verifier,
            },
            auth=auth,
        )

    def refresh(self, refresh_token: str) -> httpx.Response:
        return self.token({"grant_type": "refresh_token", "refresh_token": refresh_token})

    def introspect(self, token: str, hint: str = "refresh_token") -> httpx.Response:
        return self._authenticated_post("introspection_endpoint", {"token": token, "token_type_hint": hint}, None)

    def revoke(self, token: str, hint: str) -> httpx.Response:
        return self._authenticated_post("revocation_endpoint", {"token": token, "token_type_hint": hint}, None)

    def revoke_arrangement(self, arrangement_id: str) -> httpx.Response:
        """ADR-initiated arrangement revocation at the DH.

        CDS: "Data Holders MUST only support [the] 'CDR Arrangement Form Parameter'
        method" (cdr_arrangement_id). The cdr_arrangement_jwt method is for the DH
        calling the ADR's endpoint, not the other way round.
        """
        return self._authenticated_post(
            "cdr_arrangement_revocation_endpoint", {"cdr_arrangement_id": arrangement_id}, None
        )

    # ------------------------------------------------------------- dynamic client registration

    def _supported_alg(self, metadata_key: str) -> str:
        supported = self.metadata.get(metadata_key) or []
        if self.key.alg in supported or not supported:
            return self.key.alg
        for alg in jose.CDR_ALGS:
            if alg in supported:
                return alg
        return self.key.alg

    def registration_claims(self, ssa: str) -> dict:
        now = int(time.time())
        return {
            "iss": self.config.adr.software_product_id,
            "iat": now,
            "exp": now + 300,
            "jti": str(uuid.uuid4()),
            "aud": self.issuer,
            "redirect_uris": [self.config.redirect_uri],
            "token_endpoint_auth_signing_alg": self.key.alg,
            "token_endpoint_auth_method": "private_key_jwt",
            "grant_types": ["client_credentials", "authorization_code", "refresh_token"],
            "response_types": ["code"],
            "application_type": "web",
            "id_token_signed_response_alg": self._supported_alg("id_token_signing_alg_values_supported"),
            "request_object_signing_alg": self.key.alg,
            "authorization_signed_response_alg": self._supported_alg("authorization_signing_alg_values_supported"),
            "software_statement": ssa,
        }

    def registration_request(self, ssa: str, overrides: Mapping[str, Any] | None = None) -> str:
        return jose.sign(jose.apply_overrides(self.registration_claims(ssa), overrides), self.key)

    def register(self, ssa: str, *, overrides: Mapping[str, Any] | None = None) -> httpx.Response:
        return self.http.post(
            self.endpoint("registration_endpoint"),
            content=self.registration_request(ssa, overrides),
            headers={"Content-Type": "application/jwt", "Accept": "application/json"},
        )

    def _registration_url(self) -> str:
        return f"{self.endpoint('registration_endpoint').rstrip('/')}/{self.require_client_id()}"

    def get_registration(self, access_token: str) -> httpx.Response:
        return self.http.get(
            self._registration_url(), headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
        )

    def update_registration(self, access_token: str, ssa: str) -> httpx.Response:
        return self.http.put(
            self._registration_url(),
            content=self.registration_request(ssa),
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/jwt",
                "Accept": "application/json",
            },
        )

    # ------------------------------------------------------------- PAR / authorisation / JARM

    def new_authorization(
        self,
        *,
        cdr_arrangement_id: str | None = None,
        sharing_duration: int | None = None,
        scope: str | None = None,
    ) -> AuthorizationRequest:
        client_id = self.require_client_id()
        verifier, challenge = pkce_pair()
        state, nonce = jose.b64url(os.urandom(16)), jose.b64url(os.urandom(16))
        now = int(time.time())
        cdr_claims: dict[str, Any] = {
            "sharing_duration": self.config.adr.sharing_duration if sharing_duration is None else sharing_duration,
            "id_token": {"acr": {"essential": True, "values": [self.config.adr.acr]}},
        }
        if cdr_arrangement_id:
            cdr_claims["cdr_arrangement_id"] = cdr_arrangement_id
        claims = {
            "iss": client_id,
            "aud": self.issuer,
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "jti": str(uuid.uuid4()),
            "client_id": client_id,
            "response_type": "code",
            "response_mode": "jwt",
            "redirect_uri": self.config.redirect_uri,
            "scope": scope or self.config.adr.authorization_scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "claims": cdr_claims,
        }
        return AuthorizationRequest(state, nonce, verifier, jose.sign(claims, self.key), claims)

    def par(self, request: AuthorizationRequest) -> httpx.Response:
        return self._authenticated_post("pushed_authorization_request_endpoint", {"request": request.request_object}, None)

    def authorization_url(self, request_uri: str) -> str:
        query = urlencode({"client_id": self.require_client_id(), "request_uri": request_uri})
        return f"{self.endpoint('authorization_endpoint')}?{query}"

    def parse_jarm(self, response_jwt: str, request: AuthorizationRequest) -> dict:
        """Verify a JARM response against the DH's keys and the request; return its claims."""
        try:
            claims = jose.verify(response_jwt, self.dh_jwks())
            jose.validate_claims(claims, iss=self.issuer, aud=self.require_client_id())
        except jose.JoseError as exc:
            raise CtsError(f"JARM response failed validation: {exc}") from exc
        if "error" in claims:
            raise AuthorizationError(claims["error"], claims.get("error_description", ""))
        if claims.get("state") != request.state:
            raise CtsError("JARM state does not match the request")
        if not claims.get("code"):
            raise CtsError("JARM response carries no code")
        return claims

    def verify_id_token(self, id_token: str, request: AuthorizationRequest) -> dict:
        try:
            claims = jose.verify(id_token, self.dh_jwks())
            jose.validate_claims(
                claims, iss=self.issuer, aud=self.require_client_id(), nonce=request.nonce, require=("exp", "sub")
            )
        except jose.JoseError as exc:
            raise CtsError(f"ID token failed validation: {exc}") from exc
        return claims

    # ------------------------------------------------------------- resources

    def get_customer(self, access_token: str) -> httpx.Response:
        base = self.config.dh.resource_base_url
        if not base:
            raise CtsError("dh.resource_base_url is not configured")
        client_headers = base64.b64encode(b"cdr-dh-cts").decode("ascii")
        return self.http.get(
            f"{base.rstrip('/')}{self.config.dh.get_customer_path}",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
                "x-v": self.config.dh.get_customer_version,
                "x-fapi-interaction-id": str(uuid.uuid4()),
                "x-fapi-auth-date": formatdate(usegmt=True),
                "x-fapi-customer-ip-address": "203.0.113.10",
                "x-cds-client-headers": client_headers,
            },
        )


def response_json(response: httpx.Response) -> dict:
    """The JSON body as a dict, or ``{}`` when the body is empty or not a JSON object."""
    try:
        body = response.json()
    except (ValueError, json.JSONDecodeError):
        return {}
    return body if isinstance(body, dict) else {}


def oauth_error(response: httpx.Response) -> str:
    """The OAuth ``error`` code of a response body, or ``""``."""
    return str(response_json(response).get("error", ""))


def cds_error_codes(response: httpx.Response) -> list[str]:
    """The CDS ``errors[].code`` URNs of a response body."""
    errors = response_json(response).get("errors") or []
    return [str(e.get("code", "")) for e in errors if isinstance(e, dict)]

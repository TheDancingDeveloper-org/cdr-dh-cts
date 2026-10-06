"""An in-process fake Data Holder, served through ``httpx.MockTransport``.

Just enough of a conformant DH to run the consent, revocation and
client-assertion scenarios offline. ``lenient=True`` makes it accept any client
assertion, which the harness must catch.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
import uuid
from urllib.parse import parse_qs

import httpx

from cdr_cts import jose
from cdr_cts.fapi import CLIENT_ASSERTION_TYPE

ISSUER = "https://dh.test"
RESOURCE_BASE = "https://mtls.dh.test/cds-au/v1"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"


def _json(status: int, body: object, headers: dict | None = None) -> httpx.Response:
    return httpx.Response(status, content=json.dumps(body).encode(), headers={"content-type": "application/json", **(headers or {})})


def _error(status: int, error: str) -> httpx.Response:
    return _json(status, {"error": error, "error_description": error})


class FakeDataHolder:
    def __init__(
        self,
        adr_key: jose.SigningKey,
        client_id: str = "fake-client",
        *,
        lenient: bool = False,
        unreachable: tuple[str, ...] = (),
    ) -> None:
        self.key = jose.SigningKey.generate("PS256")
        self.adr_jwks = jose.jwks([adr_key])
        self.client_id = client_id
        self.lenient = lenient
        #: Paths whose connections are refused, as if the advertised host did not resolve.
        self.unreachable = unreachable
        self.pushed: dict[str, dict] = {}
        self.codes: dict[str, dict] = {}
        self.tokens: dict[str, dict] = {}
        self.arrangements: dict[str, bool] = {}

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def metadata(self) -> dict:
        return {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/jwks",
            "registration_endpoint": f"{ISSUER}/register",
            "pushed_authorization_request_endpoint": f"{ISSUER}/par",
            "introspection_endpoint": f"{ISSUER}/token/introspection",
            "revocation_endpoint": f"{ISSUER}/revocation",
            "cdr_arrangement_revocation_endpoint": f"{ISSUER}/arrangements/revoke",
            "userinfo_endpoint": f"{ISSUER}/userinfo",
            "scopes_supported": ["openid", "profile", "common:customer.basic:read", "cdr:registration"],
            "response_types_supported": ["code"],
            "response_modes_supported": ["jwt"],
            "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
            "acr_values_supported": ["urn:cds.au:cdr:2", "urn:cds.au:cdr:3"],
            "token_endpoint_auth_methods_supported": ["private_key_jwt"],
            "token_endpoint_auth_signing_alg_values_supported": ["PS256", "ES256"],
            "id_token_signing_alg_values_supported": ["PS256", "ES256"],
            "request_object_signing_alg_values_supported": ["PS256", "ES256"],
            "authorization_signing_alg_values_supported": ["PS256", "ES256"],
            "tls_client_certificate_bound_access_tokens": True,
        }

    # ------------------------------------------------------------------ dispatch

    def handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.path in self.unreachable:
            raise httpx.ConnectError("[Errno -2] Name or service not known", request=request)
        route = (request.method, request.url.path)
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()} if request.method == "POST" else {}
        if route == ("GET", "/.well-known/openid-configuration"):
            return _json(200, self.metadata())
        if route == ("GET", "/jwks"):
            return _json(200, jose.jwks([self.key]))
        if route == ("GET", "/authorize"):
            return self.authorize(request)
        if route == ("GET", "/cds-au/v1/common/customer"):
            return self.customer(request)
        if request.method == "POST":
            endpoints = {
                "/par": self.par,
                "/token": self.token,
                "/token/introspection": self.introspect,
                "/revocation": self.revoke,
                "/arrangements/revoke": self.revoke_arrangement,
            }
            if request.url.path in endpoints:
                failure = self.authenticate(form, str(request.url))
                return failure or endpoints[request.url.path](form)
        return _error(404, "not_found")

    def authenticate(self, form: dict, endpoint: str) -> httpx.Response | None:
        if self.lenient:
            return None
        assertion, assertion_type = form.get("client_assertion"), form.get("client_assertion_type")
        if assertion_type != CLIENT_ASSERTION_TYPE:
            return _error(400, "invalid_request") if assertion_type else _error(401, "invalid_client")
        if not assertion:
            return _error(401, "invalid_client")
        try:
            claims = jose.verify(assertion, self.adr_jwks)
            jose.validate_claims(claims, iss=self.client_id, require=("exp", "iss", "sub", "aud", "jti"))
            if claims["sub"] != self.client_id:
                raise jose.JoseError("sub")
            audiences = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
            if not {endpoint, ISSUER} & set(audiences):
                raise jose.JoseError("aud")
        except jose.JoseError:
            return _error(401, "invalid_client")
        return None

    # ------------------------------------------------------------------ authorisation

    def par(self, form: dict) -> httpx.Response:
        try:
            claims = jose.verify(form.get("request", ""), self.adr_jwks)
        except jose.JoseError:
            return _error(400, "invalid_request_object")
        if "cdr:registration" in claims.get("scope", "").split():
            # A consumer never consents to the DCR-management scope.
            return _error(400, "invalid_scope")
        request_uri = f"urn:ietf:params:oauth:request_uri:{secrets.token_urlsafe(16)}"
        self.pushed[request_uri] = claims
        return _json(201, {"request_uri": request_uri, "expires_in": 90})

    def authorize(self, request: httpx.Request) -> httpx.Response:
        claims = self.pushed.pop(request.url.params.get("request_uri", ""), None)
        if claims is None:
            return _error(400, "invalid_request_uri")
        code = secrets.token_urlsafe(24)
        self.codes[code] = claims
        now = int(time.time())
        jarm = jose.sign(
            {"iss": ISSUER, "aud": self.client_id, "exp": now + 120, "code": code, "state": claims["state"]}, self.key
        )
        return httpx.Response(302, headers={"location": f"{claims['redirect_uri']}?response={jarm}"})

    # ------------------------------------------------------------------ tokens

    def _issue(self, kind: str, arrangement: str | None) -> str:
        token = secrets.token_urlsafe(32)
        self.tokens[token] = {"kind": kind, "arrangement": arrangement, "active": True}
        return token

    def token(self, form: dict) -> httpx.Response:
        grant = form.get("grant_type")
        if grant == "authorization_code":
            claims = self.codes.pop(form.get("code", ""), None)
            if claims is None:
                return _error(400, "invalid_grant")
            challenge = jose.b64url(hashlib.sha256(form.get("code_verifier", "").encode()).digest())
            if challenge != claims["code_challenge"]:
                return _error(400, "invalid_grant")
            requested = claims["claims"].get("cdr_arrangement_id")
            if requested and self.arrangements.get(requested):
                arrangement = requested
                for token in self.tokens.values():
                    if token["arrangement"] == arrangement:
                        token["active"] = False
            else:
                arrangement = str(uuid.uuid4())
            self.arrangements[arrangement] = True
            now = int(time.time())
            id_token = jose.sign(
                {"iss": ISSUER, "aud": self.client_id, "sub": "customer-1", "nonce": claims["nonce"],
                 "iat": now, "exp": now + 300, "acr": "urn:cds.au:cdr:2"},
                self.key,
            )
            return _json(200, {
                "access_token": self._issue("access", arrangement),
                "refresh_token": self._issue("refresh", arrangement),
                "id_token": id_token,
                "cdr_arrangement_id": arrangement,
                "token_type": "Bearer",
                "expires_in": 300,
            })
        if grant == "refresh_token":
            token = self.tokens.get(form.get("refresh_token", ""))
            if not token or not token["active"] or token["kind"] != "refresh":
                return _error(400, "invalid_grant")
            return _json(200, {"access_token": self._issue("access", token["arrangement"]), "token_type": "Bearer"})
        if grant == "client_credentials":
            return _json(200, {"access_token": self._issue("access", None), "token_type": "Bearer", "expires_in": 300})
        return _error(400, "unsupported_grant_type")

    def introspect(self, form: dict) -> httpx.Response:
        token = self.tokens.get(form.get("token", ""))
        if not token or not token["active"]:
            return _json(200, {"active": False})
        return _json(200, {"active": True, "cdr_arrangement_id": token["arrangement"], "exp": int(time.time()) + 300})

    def revoke(self, form: dict) -> httpx.Response:
        token = self.tokens.get(form.get("token", ""))
        if token:
            token["active"] = False
        return httpx.Response(200)

    def revoke_arrangement(self, form: dict) -> httpx.Response:
        try:
            arrangement = jose.verify(form.get("cdr_arrangement_jwt", ""), self.adr_jwks)["cdr_arrangement_id"]
        except (jose.JoseError, KeyError):
            return _error(400, "invalid_request")
        if not self.arrangements.get(arrangement):
            return _json(422, {"errors": [{"code": "urn:au-cds:error:cds-all:Authorisation/InvalidArrangement"}]})
        self.arrangements[arrangement] = False
        for token in self.tokens.values():
            if token["arrangement"] == arrangement:
                token["active"] = False
        return httpx.Response(204)

    # ------------------------------------------------------------------ resources

    def customer(self, request: httpx.Request) -> httpx.Response:
        bearer = request.headers.get("authorization", "")[7:]
        token = self.tokens.get(bearer)
        if not token or not token["active"] or token["kind"] != "access":
            return _json(401, {"errors": [{"code": "urn:au-cds:error:cds-all:Authorisation/InvalidBearerToken"}]},
                         headers={"www-authenticate": 'Bearer error="invalid_token"'})
        return _json(200, {"data": {"customerUType": "person", "person": {"lastName": "Citizen"}},
                           "links": {"self": str(request.url)}, "meta": {}})

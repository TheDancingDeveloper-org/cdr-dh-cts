"""Multi-step flows several scenarios share: authorise, exchange, call Get Customer."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

import httpx

from .authorize import jarm_from_callback
from .errors import AuthorizationError, CtsError
from .fapi import AuthorizationRequest, FapiClient, oauth_error, response_json
from .scenario import ScenarioContext, describe

CLIENT_ERROR = range(400, 500)


@dataclass
class Consent:
    label: str
    request: AuthorizationRequest
    arrangement_id: str
    access_token: str
    refresh_token: str
    id_token_claims: dict


def authorise(ctx: ScenarioContext, label: str, *, cdr_arrangement_id: str | None = None) -> tuple[AuthorizationRequest, str]:
    """PAR, then authorisation via the configured adapter; returns the request and the code."""
    client = ctx.client
    request = client.new_authorization(cdr_arrangement_id=cdr_arrangement_id)
    response = client.par(request)
    ctx.expect_status(f"{label}: PAR accepted (HTTP 201)", response, {201})
    request.request_uri = response_json(response).get("request_uri", "")
    ctx.check(f"{label}: PAR response contains request_uri", bool(request.request_uri), describe(response))

    if ctx.adapter is None:
        ctx.skip("no authorization.adapter configured")
    try:
        callback = ctx.adapter(client, request, client.authorization_url(request.request_uri), ctx.config.authorization.options)
        claims = client.parse_jarm(jarm_from_callback(callback), request)
    except AuthorizationError as exc:
        ctx.fail(f"{label}: authorisation returns code and state", f"DH returned an authorisation error: {exc}")
    except CtsError as exc:
        ctx.fail(f"{label}: authorisation returns code and state", str(exc))
    ctx.check(f"{label}: authorisation returns a valid JARM with code and matching state", True)
    return request, claims["code"]


def exchange(ctx: ScenarioContext, label: str, request: AuthorizationRequest, code: str) -> Consent:
    """Exchange the code; verify the token response and ID token."""
    client = ctx.client
    response = client.exchange_code(code, request.code_verifier)
    ctx.expect_status(f"{label}: token request succeeds (HTTP 200)", response, {200})
    body = response_json(response)
    missing = [k for k in ("access_token", "id_token") if not body.get(k)]
    ctx.check(
        f"{label}: token response has access_token and id_token",
        not missing,
        f"missing: {', '.join(missing)}" if missing else "",
    )
    # A failure, but not a reason to stop: the remaining steps still produce evidence.
    # Scenarios that use the arrangement ID fail on their own when it is absent.
    ctx.check(
        f"{label}: token response has cdr_arrangement_id",
        bool(body.get("cdr_arrangement_id")),
        "missing: cdr_arrangement_id",
        fatal=False,
    )
    if (request.claims["claims"].get("sharing_duration") or 0) > 0:
        ctx.check(f"{label}: refresh_token issued for an ongoing consent", bool(body.get("refresh_token")))
    try:
        id_claims = client.verify_id_token(body["id_token"], request)
    except CtsError as exc:
        ctx.fail(f"{label}: ID token is valid", str(exc))
    ctx.check(f"{label}: ID token is valid (signature, iss, aud, nonce, exp, sub)", True)
    return Consent(
        label=label,
        request=request,
        arrangement_id=body.get("cdr_arrangement_id", ""),
        access_token=body["access_token"],
        refresh_token=body.get("refresh_token", ""),
        id_token_claims=id_claims,
    )


def establish_consent(ctx: ScenarioContext, label: str, *, cdr_arrangement_id: str | None = None) -> Consent:
    request, code = authorise(ctx, label, cdr_arrangement_id=cdr_arrangement_id)
    return exchange(ctx, label, request, code)


def get_customer_ok(ctx: ScenarioContext, label: str, access_token: str, client: FapiClient | None = None) -> httpx.Response:
    response = (client or ctx.client).get_customer(access_token)
    ctx.expect_status(f"{label}: Get Customer succeeds (HTTP 200)", response, {200})
    data = response_json(response).get("data") or {}
    ctx.check(f"{label}: Get Customer returns a customer payload", "customerUType" in data, describe(response))
    return response


def get_customer_rejected(
    ctx: ScenarioContext,
    label: str,
    access_token: str,
    *,
    client: FapiClient | None = None,
    expected: Iterable[int] = CLIENT_ERROR,
) -> httpx.Response:
    response = (client or ctx.client).get_customer(access_token)
    ctx.expect_status(f"{label}: Get Customer is rejected", response, expected, fatal=False)
    return response


def refresh_rejected(ctx: ScenarioContext, label: str, refresh_token: str) -> httpx.Response:
    response = ctx.client.refresh(refresh_token)
    ctx.expect_status(f"{label}: refresh-token grant is rejected", response, CLIENT_ERROR, fatal=False)
    if response.status_code in CLIENT_ERROR:
        ctx.info(f"{label}: refresh rejection", f"HTTP {response.status_code} {oauth_error(response)}")
    return response


def introspection(ctx: ScenarioContext, label: str, token: str, *, active: bool) -> None:
    response = ctx.client.introspect(token)
    ctx.expect_status(f"{label}: introspection succeeds (HTTP 200)", response, {200}, fatal=False)
    body = response_json(response)
    ctx.check(
        f"{label}: introspection reports active={str(active).lower()}",
        body.get("active") is active,
        f"active={body.get('active')!r}",
        fatal=False,
    )
    if active:
        ctx.check(
            f"{label}: introspection carries cdr_arrangement_id",
            bool(body.get("cdr_arrangement_id")),
            fatal=False,
        )

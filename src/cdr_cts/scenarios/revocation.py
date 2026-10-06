"""Revocation scenarios.

8. Data Recipient Initiated Arrangement Revocation (§3.11), 10. Data Recipient
Initiated Token Revocation (§3.13) and 11. Data Holder Initiated Arrangement
Revocation (§3.14) of the CTS DH Technical Guidance 5.3.0.
"""

from __future__ import annotations

from ..authorize import load_callable
from ..flows import establish_consent, get_customer_rejected, introspection, refresh_rejected
from ..jose import JoseError, decode, validate_claims, verify
from ..scenario import Requirement, Scenario, ScenarioContext, scenario

SUCCESS = range(200, 300)


@scenario
class DataRecipientInitiatedArrangementRevocation(Scenario):
    number = 8
    id = "dr-initiated-arrangement-revocation"
    title = "Data Recipient Initiated Arrangement Revocation"
    section = "3.11"
    requires = (Requirement.DATA_HOLDER, Requirement.CLIENT)
    depends_on = (7,)

    def run(self, ctx: ScenarioContext) -> None:
        consent = ctx.state["consent.second"]
        response = ctx.client.revoke_arrangement(consent.arrangement_id)
        ctx.expect_status("Arrangement revocation returns a success code", response, SUCCESS)
        if consent.refresh_token:
            introspection(ctx, "Revoked arrangement", consent.refresh_token, active=False)
            refresh_rejected(ctx, "Revoked arrangement", consent.refresh_token)
        else:
            ctx.info("Consent issued no refresh token; introspection and refresh checks not applicable")


@scenario
class DataRecipientInitiatedTokenRevocation(Scenario):
    number = 10
    id = "dr-initiated-token-revocation"
    title = "Data Recipient Initiated Token Revocation"
    section = "3.13"
    requires = (Requirement.DATA_HOLDER, Requirement.CLIENT, Requirement.RESOURCE)
    depends_on = (9,)

    def run(self, ctx: ScenarioContext) -> None:
        consent = ctx.state["consent.amended"]
        client = ctx.client
        response = client.revoke(consent.access_token, "access_token")
        ctx.expect_status("Access token revocation returns HTTP 200", response, {200}, fatal=False)
        get_customer_rejected(ctx, "Revoked access token", consent.access_token)
        if not consent.refresh_token:
            ctx.info("Amended consent issued no refresh token; refresh-token revocation not applicable")
            return
        response = client.revoke(consent.refresh_token, "refresh_token")
        ctx.expect_status("Refresh token revocation returns HTTP 200", response, {200}, fatal=False)
        refresh_rejected(ctx, "Revoked refresh token", consent.refresh_token)


@scenario
class DataHolderInitiatedArrangementRevocation(Scenario):
    number = 11
    id = "dh-initiated-arrangement-revocation"
    title = "Data Holder Initiated Arrangement Revocation"
    section = "3.14"
    requires = (Requirement.DATA_HOLDER, Requirement.CLIENT, Requirement.AUTHORIZATION, Requirement.ECOSYSTEM)

    def run(self, ctx: ScenarioContext) -> None:
        consent = establish_consent(ctx, "Consent for DH revocation")
        since = ctx.ecosystem.now()
        hook = ctx.config.hooks.dh_revoke_arrangement
        if hook:
            try:
                load_callable(hook)(consent.arrangement_id, ctx.config.hooks.options)
            except Exception as exc:  # noqa: BLE001 — the hook is user code
                ctx.fail("DH revocation hook ran", f"{type(exc).__name__}: {exc}")
            ctx.info("DH revocation triggered by hook", hook)
        else:
            print(f"\n  >> Revoke arrangement {consent.arrangement_id} at the Data Holder now "
                  f"(waiting up to {ctx.config.timeouts.dh_action:.0f}s)\n")

        found = ctx.ecosystem.wait_for(
            lambda: ctx.ecosystem.requests(since=since, path_contains="/dr/arrangements/revoke"),
            ctx.config.timeouts.dh_action,
        )
        ctx.check("DH sent an arrangement revocation to the simulated ADR", bool(found),
                  f"no request within {ctx.config.timeouts.dh_action:.0f}s")
        request = found[-1]

        arrangement_jwt = (request.get("form") or {}).get("cdr_arrangement_jwt", "")
        ctx.check("Request carries cdr_arrangement_jwt", bool(arrangement_jwt), f"form keys: {sorted(request.get('form') or {})}")
        try:
            claims = verify(arrangement_jwt, ctx.client.dh_jwks())
        except JoseError as exc:
            ctx.fail("cdr_arrangement_jwt is signed by the DH", str(exc))
        ctx.check("cdr_arrangement_jwt is signed by the DH", True)
        ctx.check(
            "cdr_arrangement_jwt names the arrangement from the initial consent",
            claims.get("cdr_arrangement_id") == consent.arrangement_id,
            f"cdr_arrangement_id={claims.get('cdr_arrangement_id')!r}",
        )

        authorization = (request.get("headers") or {}).get("authorization", "")
        bearer = authorization[7:] if authorization.lower().startswith("bearer ") else ""
        if not bearer:
            ctx.check("Request is authenticated with a DH-signed bearer JWT", False, "no bearer token", fatal=False)
            return
        try:
            token_claims = verify(bearer, ctx.client.dh_jwks())
            validate_claims(token_claims, aud=ctx.config.adr_revocation_uri, require=("exp", "iss", "jti"))
            ok, detail = True, f"iss={token_claims.get('iss')!r}"
        except JoseError as exc:
            ok, detail = False, f"{exc} (header: {decode(bearer).header if bearer.count('.') == 2 else 'not a JWT'})"
        ctx.check("Request is authenticated with a DH-signed bearer JWT addressed to the ADR", ok, detail, fatal=False)

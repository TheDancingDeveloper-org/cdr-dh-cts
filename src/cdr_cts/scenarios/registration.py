"""Dynamic Client Registration scenarios.

3. Ensure SSA Validation (§3.6), 4. Create Client Registration (§3.7) and
13. Retrieve and Update Client Registration (§3.16) of the CTS DH Technical
Guidance 5.3.0.
"""

from __future__ import annotations

import uuid

from ..fapi import response_json
from ..jose import SigningKey
from ..runner import participant_for
from ..scenario import Requirement, Scenario, ScenarioContext, describe, scenario
from ..ssa import mint_ssa

REGISTRATION_ERRORS = {"invalid_software_statement", "unapproved_software_statement"}


def _jwks_fetches(ctx: ScenarioContext, since: float) -> tuple[int, int]:
    seen = ctx.ecosystem.requests(since=since)
    register = sum(1 for r in seen if r["path"].endswith("/register/cdr-register/v1/jwks"))
    adr = sum(1 for r in seen if r["path"].endswith("/dr/jwks"))
    return register, adr


@scenario
class EnsureSsaValidation(Scenario):
    number = 3
    id = "ssa-validation"
    title = "Ensure SSA Validation"
    section = "3.6"
    requires = (Requirement.DATA_HOLDER, Requirement.ECOSYSTEM)

    def run(self, ctx: ScenarioContext) -> None:
        since = ctx.ecosystem.now()
        rogue = SigningKey.generate("PS256", kid=f"not-in-register-jwks-{uuid.uuid4()}")
        ssa = mint_ssa(participant_for(ctx.config), rogue)
        response = ctx.client.register(ssa)
        ctx.expect_oauth_error(
            "Registration with an SSA signed by a kid absent from the Register JWKS is rejected",
            response,
            [({400}, REGISTRATION_ERRORS)],
        )
        body = response_json(response)
        ctx.check(
            "Error body follows the Registration Error schema (error, optional error_description)",
            isinstance(body.get("error"), str) and isinstance(body.get("error_description", ""), str),
            describe(response),
            fatal=False,
        )
        register_fetches, _ = _jwks_fetches(ctx, since)
        ctx.info("DH fetched the Register SSA JWKS", f"{register_fetches} fetch(es) (may be cached)")


@scenario
class CreateClientRegistration(Scenario):
    number = 4
    id = "create-client-registration"
    title = "Create Client Registration"
    section = "3.7"
    requires = (Requirement.DATA_HOLDER, Requirement.ECOSYSTEM)

    def run(self, ctx: ScenarioContext) -> None:
        if ctx.config.adr.client_id:
            ctx.skip("adr.client_id is set, so the pre-registered client is used; clear it to test DCR create")
        client = ctx.client
        since = ctx.ecosystem.now()
        response = client.register(ctx.ecosystem.mint_ssa())
        ctx.expect_status("DCR request is accepted (HTTP 201)", response, {201})
        body = response_json(response)
        client_id = body.get("client_id")
        ctx.check("Registration response contains client_id", bool(client_id), describe(response))

        adr = ctx.config.adr
        ctx.check("software_id is the simulated software product", body.get("software_id") == adr.software_product_id,
                  f"software_id={body.get('software_id')!r}", fatal=False)
        ctx.check("redirect_uris are registered", ctx.config.redirect_uri in (body.get("redirect_uris") or []),
                  f"redirect_uris={body.get('redirect_uris')}", fatal=False)
        ctx.check("token_endpoint_auth_method is private_key_jwt",
                  body.get("token_endpoint_auth_method") == "private_key_jwt", fatal=False)
        ctx.check("grant_types include authorization_code, client_credentials and refresh_token",
                  {"authorization_code", "client_credentials", "refresh_token"} <= set(body.get("grant_types") or []),
                  f"grant_types={body.get('grant_types')}", fatal=False)

        register_fetches, adr_fetches = _jwks_fetches(ctx, since)
        ctx.info("DH fetched the Register SSA JWKS", f"{register_fetches} fetch(es) (may be cached)")
        ctx.info("DH fetched the simulated ADR JWKS from the SSA jwks_uri", f"{adr_fetches} fetch(es)")

        client.client_id = client_id
        ctx.state["client_id"] = client_id
        ctx.state["registration"] = body


#: Client metadata the GET must return as it was sent in the PUT.
COMPARED_METADATA = ("redirect_uris", "grant_types", "response_types", "token_endpoint_auth_method",
                     "id_token_signed_response_alg", "request_object_signing_alg", "software_id")


@scenario
class RetrieveAndUpdateClientRegistration(Scenario):
    number = 13
    id = "retrieve-update-client-registration"
    title = "Retrieve and Update Client Registration"
    section = "3.16"
    requires = (Requirement.DATA_HOLDER, Requirement.ECOSYSTEM, Requirement.CLIENT)

    def run(self, ctx: ScenarioContext) -> None:
        client = ctx.client
        token_response = client.client_credentials("cdr:registration")
        ctx.expect_status("client_credentials token for cdr:registration is issued (HTTP 200)", token_response, {200})
        access_token = response_json(token_response).get("access_token")
        ctx.check("Token response contains access_token", bool(access_token), describe(token_response))

        ssa = ctx.ecosystem.mint_ssa({"client_description": f"Updated by cdr-dh-cts {uuid.uuid4()}"})
        put = client.update_registration(access_token, ssa)
        ctx.expect_status("PUT registration is accepted (HTTP 200)", put, {200})

        get = client.get_registration(access_token)
        ctx.expect_status("GET registration succeeds (HTTP 200)", get, {200})
        sent = {**client.registration_claims(ssa), "software_id": ctx.config.adr.software_product_id}
        returned = response_json(get)
        differing = [
            name for name in COMPARED_METADATA
            if name in returned and _normalise(returned[name]) != _normalise(sent.get(name))
        ]
        ctx.check("GET registration reflects the PUT", not differing,
                  "differs: " + ", ".join(f"{n} sent={sent.get(n)!r} got={returned.get(n)!r}" for n in differing))


def _normalise(value: object) -> object:
    return sorted(value) if isinstance(value, list) else value

"""6. Holder Of Key Resource Requests (CTS DH Technical Guidance 5.3.0 §3.9)."""

from __future__ import annotations

from ..fapi import oauth_error
from ..scenario import Requirement, Scenario, ScenarioContext, scenario


@scenario
class HolderOfKeyResourceRequests(Scenario):
    number = 6
    id = "holder-of-key"
    title = "Holder Of Key Resource Requests"
    section = "3.9"
    requires = (Requirement.DATA_HOLDER, Requirement.RESOURCE, Requirement.MTLS_EDGE, Requirement.ALTERNATE_CERT)
    depends_on = (5,)

    def run(self, ctx: ScenarioContext) -> None:
        consent = ctx.state["consent.first"]
        control = ctx.client.get_customer(consent.access_token)
        ctx.info("Control: Get Customer with the bound certificate", f"HTTP {control.status_code}")

        other = ctx.client_with(ctx.config.tls.alternate_client)
        response = other.get_customer(consent.access_token)
        ctx.expect_status(
            "Get Customer with a certificate not bound to the access token is rejected (HTTP 401)",
            response,
            {401},
            fatal=False,
        )
        challenge = response.headers.get("www-authenticate", "")
        ctx.check(
            "Rejection carries error invalid_token",
            "invalid_token" in challenge or oauth_error(response) == "invalid_token",
            f"WWW-Authenticate={challenge!r} error={oauth_error(response)!r}",
            fatal=False,
        )

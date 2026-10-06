"""14. Removed Software Product (CTS DH Technical Guidance 5.3.0 §3.17)."""

from __future__ import annotations

from ..fapi import cds_error_codes
from ..flows import establish_consent
from ..scenario import Requirement, Scenario, ScenarioContext, scenario

#: §3.17.5.1: the (status, URN) pairs that pass.
PASSING_ERRORS = {
    403: {
        "urn:au-cds:error:cds-all:Authorisation/AdrStatusNotActive",
        "urn:au-cds:error:cds-all:Authorisation/RevokedConsent",
        "urn:au-cds:error:cds-all:Authorisation/InvalidConsent",
    },
    422: {"urn:au-cds:error:cds-all:Authorisation/InvalidArrangement"},
}

POLL_PATHS = ("/data-recipients/brands/software-products/status", "/data-recipients")


@scenario
class RemovedSoftwareProduct(Scenario):
    number = 14
    id = "removed-software-product"
    title = "Removed Software Product"
    section = "3.17"
    requires = (
        Requirement.DATA_HOLDER,
        Requirement.CLIENT,
        Requirement.AUTHORIZATION,
        Requirement.RESOURCE,
        Requirement.ECOSYSTEM,
    )

    def run(self, ctx: ScenarioContext) -> None:
        consent = establish_consent(ctx, "Consent before removal")
        ecosystem = ctx.ecosystem
        changed_at = ecosystem.now()
        ecosystem.set_software_product_status("REMOVED")
        ctx.info("Simulated Register: software product status changed ACTIVE -> REMOVED")
        try:
            timeout = ctx.config.timeouts.register_poll
            polls = ecosystem.wait_for(
                lambda: [
                    r for r in ecosystem.requests(since=changed_at, path_contains="/register/cdr-register/v1/")
                    if r["path"].endswith(POLL_PATHS)
                ],
                timeout,
                poll=5.0,
            )
            ctx.check(
                f"DH polled the Register within {timeout:.0f}s of the status change",
                bool(polls),
                f"first poll after {polls[0]['time'] - changed_at:.0f}s ({polls[0]['path']})" if polls else "no poll seen",
                fatal=False,
            )

            response = ctx.client.get_customer(consent.access_token)
            ctx.check(
                "Get Customer discloses no CDR data for the removed software product",
                400 <= response.status_code < 500,
                f"HTTP {response.status_code} {cds_error_codes(response)}",
                fatal=False,
            )

            response = ctx.client.revoke_arrangement(consent.arrangement_id)
            codes = set(cds_error_codes(response))
            ok = response.status_code in PASSING_ERRORS and bool(codes & PASSING_ERRORS[response.status_code])
            ctx.check(
                "Arrangement revocation is refused with HTTP 403/422 and a §3.17.5.1 error code",
                ok,
                f"HTTP {response.status_code} {sorted(codes)}",
                fatal=False,
            )
        finally:
            ecosystem.set_software_product_status("ACTIVE")
            ctx.info("Simulated Register: software product status restored to ACTIVE")

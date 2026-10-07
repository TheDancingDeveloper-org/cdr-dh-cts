"""Consent scenarios.

5. First Consent (§3.8), 7. Second Consent (§3.10) and 9. Amending Existing
Consent (§3.12) of the CTS DH Technical Guidance 5.3.0.
"""

from __future__ import annotations

from ..flows import establish_consent, get_customer_ok, introspection, refresh_rejected
from ..scenario import Requirement, Scenario, ScenarioContext, scenario

CONSENT_REQUIREMENTS = (Requirement.DATA_HOLDER, Requirement.CLIENT, Requirement.AUTHORIZATION, Requirement.RESOURCE)


@scenario
class FirstConsent(Scenario):
    number = 5
    id = "first-consent"
    title = "First Consent"
    section = "3.8"
    requires = CONSENT_REQUIREMENTS

    def run(self, ctx: ScenarioContext) -> None:
        consent = establish_consent(ctx, "First consent")
        if consent.refresh_token:
            introspection(ctx, "First consent", consent.refresh_token, active=True)
        get_customer_ok(ctx, "First consent", consent.access_token)
        ctx.state["consent.first"] = consent


@scenario
class SecondConsent(Scenario):
    number = 7
    id = "second-consent"
    title = "Second Consent"
    section = "3.10"
    requires = CONSENT_REQUIREMENTS
    depends_on = (5,)

    def run(self, ctx: ScenarioContext) -> None:
        first = ctx.state["consent.first"]
        second = establish_consent(ctx, "Second consent")
        ctx.check(
            "Second consent has a new cdr_arrangement_id",
            second.arrangement_id != first.arrangement_id,
            f"first={first.arrangement_id} second={second.arrangement_id}",
        )
        get_customer_ok(ctx, "Second consent", second.access_token)
        ctx.state["consent.second"] = second


@scenario
class AmendingExistingConsent(Scenario):
    number = 9
    id = "amending-existing-consent"
    title = "Amending Existing Consent"
    section = "3.12"
    requires = CONSENT_REQUIREMENTS
    depends_on = (5,)

    def run(self, ctx: ScenarioContext) -> None:
        first = ctx.state["consent.first"]
        amended = establish_consent(ctx, "Amended consent", cdr_arrangement_id=first.arrangement_id)
        # CDS (CDR Arrangement ID): "MUST be static across consents within the one sharing
        # arrangement (e.g. across consent renewal and re-authorisation)".
        ctx.check(
            "Amended consent keeps the cdr_arrangement_id",
            bool(amended.arrangement_id) and amended.arrangement_id == first.arrangement_id,
            f"first={first.arrangement_id!r} amended={amended.arrangement_id!r}",
            fatal=False,
        )
        get_customer_ok(ctx, "Amended consent", amended.access_token)
        if first.refresh_token:
            refresh_rejected(ctx, "First consent's refresh token after amendment", first.refresh_token)
        else:
            ctx.info("First consent issued no refresh token; nothing to replay")
        ctx.state["consent.amended"] = amended

"""12. Ensure Client Assertion Data in Requests (CTS DH Technical Guidance 5.3.0 §3.15).

Fifteen token requests, each with one defect in its client authentication. The
DH must answer every one with ``400/401 invalid_client`` or ``400
invalid_request``. Client authentication is evaluated before the grant, so a
DH that wrongly accepts a defective assertion shows up as a token response or
an ``invalid_grant`` — both fail the step.
"""

from __future__ import annotations

import os
import time

from ..fapi import CLIENT_ASSERTION_TYPE, response_json
from ..flows import authorise
from ..jose import REMOVE
from ..scenario import Requirement, Scenario, ScenarioContext, scenario

ALLOWED = [({400, 401}, {"invalid_client"}), ({400}, {"invalid_request"})]


@scenario
class EnsureClientAssertionData(Scenario):
    number = 12
    id = "client-assertion-data"
    title = "Ensure Client Assertion Data in Requests"
    section = "3.15"
    requires = (Requirement.DATA_HOLDER, Requirement.CLIENT, Requirement.AUTHORIZATION)

    def run(self, ctx: ScenarioContext) -> None:
        client = ctx.client
        request, code = authorise(ctx, "Client assertion")
        client_id = client.require_client_id()
        audience = client.assertion_audience(client.endpoint("token_endpoint"))
        now = int(time.time())

        def form(assertion: str | None = None, assertion_type: str | None = CLIENT_ASSERTION_TYPE, **mutation) -> dict:
            fields = {"client_id": client_id}
            if assertion_type is not None:
                fields["client_assertion_type"] = assertion_type
            if assertion is None and "omit" not in mutation:
                assertion = client.client_assertion(audience, **mutation)
            if assertion is not None:
                fields["client_assertion"] = assertion
            return fields

        signature_size = 64 if ctx.adr_key.alg == "ES256" else 256
        cases = [
            ("without a client assertion", form(omit=True)),
            ("with a wrong 'aud'", form(claims={"aud": "https://wrong-audience.invalid/token"})),
            ("missing 'aud'", form(claims={"aud": REMOVE})),
            ("with a wrong 'sub'", form(claims={"sub": "wrong-client-id"})),
            ("missing 'sub'", form(claims={"sub": REMOVE})),
            ("with an expired client assertion", form(claims={"iat": now - 900, "exp": now - 600})),
            ("missing 'iss'", form(claims={"iss": REMOVE})),
            ("with a wrong 'iss'", form(claims={"iss": "wrong-client-id"})),
            ("missing 'alg'", form(header={"alg": REMOVE})),
            ("with an empty 'alg'", form(header={"alg": ""})),
            ("with 'alg' none", form(header={"alg": "none"})),
            ("with 'alg' RS256", form(header={"alg": "RS256"})),
            ("with a wrong signature", form(signature=os.urandom(signature_size))),
            ("missing 'client_assertion_type'", form(assertion_type=None)),
            ("with a wrong 'client_assertion_type'", form(assertion_type="urn:ietf:params:oauth:client-assertion-type:saml2-bearer")),
        ]
        for label, auth in cases:
            response = client.exchange_code(code, request.code_verifier, auth=auth)
            ctx.expect_oauth_error(f"Token request {label} is rejected", response, ALLOWED)

        # Positive control; scenario 14 builds on a consent from this flow in the CTS.
        response = client.exchange_code(code, request.code_verifier)
        body = response_json(response)
        if response.status_code == 200 and body.get("access_token"):
            ctx.info("Control: token request with a valid client assertion succeeds")
            ctx.state["consent.client_assertion"] = body
        else:
            ctx.info("Control: valid token request after the negative cases",
                     f"HTTP {response.status_code} (a DH may invalidate the code after failed attempts)")

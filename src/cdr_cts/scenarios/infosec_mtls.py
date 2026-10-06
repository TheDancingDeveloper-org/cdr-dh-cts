"""2. Ensure Infosec Endpoints Using MTLS (CTS DH Technical Guidance 5.3.0 §3.5)."""

from __future__ import annotations

import httpx

from ..config import CertPair
from ..scenario import Requirement, Scenario, ScenarioContext, Status, scenario


@scenario
class InfosecEndpointsUsingMtls(Scenario):
    number = 2
    id = "infosec-endpoints-mtls"
    title = "Ensure Infosec Endpoints Using MTLS"
    section = "3.5"
    requires = (Requirement.DATA_HOLDER, Requirement.ECOSYSTEM, Requirement.MTLS_EDGE)

    def run(self, ctx: ScenarioContext) -> None:
        tls = ctx.config.tls
        cases = [
            ("without a CDR client certificate", CertPair(), None),
            ("with an expired CDR client certificate", tls.expired_client, "tls.expired_client"),
            ("with a non-CDR (self-signed) client certificate", tls.self_signed_client, "tls.self_signed_client"),
            ("with a revoked CDR client certificate", tls.revoked_client, "tls.revoked_client"),
        ]
        _ = ctx.client.metadata  # resolve endpoints once, over the valid certificate
        unconfigured = []
        for label, cert, setting in cases:
            title = f"Registration request {label} is refused"
            if setting and not cert.present:
                unconfigured.append(setting)
                ctx.record(title, Status.SKIP, f"set {setting}.cert/key")
                continue
            client = ctx.client_with(cert)
            ssa = ctx.ecosystem.mint_ssa()
            try:
                response = client.register(ssa)
            except httpx.TransportError as exc:
                ctx.check(title, True, f"no response: connection refused during TLS ({type(exc).__name__})")
                continue
            ctx.check(title, 400 <= response.status_code <= 599, f"HTTP {response.status_code}", fatal=False)
        if unconfigured and not any(s.status is Status.FAIL for s in ctx.steps):
            ctx.skip(f"{len(unconfigured)} of 4 certificate cases not configured: {', '.join(unconfigured)}")

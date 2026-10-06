"""1. Discovery Document (CTS DH Technical Guidance 5.3.0 §3.4, with the §3.3 Register poll)."""

from __future__ import annotations

from ..fapi import response_json
from ..jose import CDR_ALGS
from ..scenario import Requirement, Scenario, ScenarioContext, describe, scenario

REQUIRED_FIELDS = (
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
    "registration_endpoint",
    "pushed_authorization_request_endpoint",
    "introspection_endpoint",
    "revocation_endpoint",
    "cdr_arrangement_revocation_endpoint",
    "userinfo_endpoint",
    "scopes_supported",
    "response_types_supported",
    "grant_types_supported",
    "token_endpoint_auth_methods_supported",
)

ALG_FIELDS = (
    "id_token_signing_alg_values_supported",
    "request_object_signing_alg_values_supported",
    "authorization_signing_alg_values_supported",
    "token_endpoint_auth_signing_alg_values_supported",
)

REGISTER_STATUS_PATHS = ("/data-recipients/status", "/software-products/status", "/data-recipients")


@scenario
class DiscoveryDocument(Scenario):
    number = 1
    id = "discovery-document"
    title = "Discovery Document"
    section = "3.4"
    requires = (Requirement.DATA_HOLDER,)

    def run(self, ctx: ScenarioContext) -> None:
        client = ctx.client
        response = client.fetch_discovery()
        ctx.expect_status("Discovery endpoint returns HTTP 200", response, {200})
        meta = response_json(response)
        ctx.check("Discovery document is a JSON object", bool(meta), describe(response))

        missing = [name for name in REQUIRED_FIELDS if not meta.get(name)]
        ctx.check("Discovery document advertises the CDR metadata", not missing, f"missing: {', '.join(missing)}")

        expected_url = meta["issuer"].rstrip("/") + "/.well-known/openid-configuration"
        ctx.check(
            "issuer matches the discovery URL",
            ctx.config.dh.discovery_url.rstrip("/") == expected_url,
            f"issuer {meta['issuer']!r}, discovery URL {ctx.config.dh.discovery_url!r}",
            fatal=False,
        )

        response_types = [set(rt.split()) for rt in meta.get("response_types_supported", [])]
        ctx.check("response_types_supported includes 'code'", {"code"} in response_types, fatal=False)
        ctx.check(
            "OIDC Hybrid flow is not offered (retired in CDS 1.33.0 / TP 5.2.0)",
            not any({"code", "id_token"} <= rt for rt in response_types),
            f"response_types_supported={meta.get('response_types_supported')}",
            fatal=False,
        )
        ctx.check(
            "response_modes_supported includes 'jwt' (JARM)",
            "jwt" in (meta.get("response_modes_supported") or []),
            f"response_modes_supported={meta.get('response_modes_supported')}",
            fatal=False,
        )
        ctx.check(
            "token_endpoint_auth_methods_supported includes private_key_jwt",
            "private_key_jwt" in meta.get("token_endpoint_auth_methods_supported", []),
            fatal=False,
        )
        ctx.check(
            "tls_client_certificate_bound_access_tokens is true",
            meta.get("tls_client_certificate_bound_access_tokens") is True,
            fatal=False,
        )
        ctx.check(
            "acr_values_supported includes urn:cds.au:cdr:2",
            "urn:cds.au:cdr:2" in (meta.get("acr_values_supported") or []),
            f"acr_values_supported={meta.get('acr_values_supported')}",
            fatal=False,
        )
        for name in ALG_FIELDS:
            values = meta.get(name)
            if values is None:
                ctx.info(f"{name} not advertised")
                continue
            ctx.check(f"{name} offers only PS256/ES256", bool(values) and set(values) <= set(CDR_ALGS),
                      f"{name}={values}", fatal=False)

        jwks = client.http.get(meta["jwks_uri"])
        ctx.check(
            "jwks_uri serves a key set",
            jwks.status_code == 200 and bool(response_json(jwks).get("keys")),
            describe(jwks),
            fatal=False,
        )

        if ctx.satisfies(Requirement.ECOSYSTEM):
            polls = [
                r for r in ctx.ecosystem.requests(path_contains="/register/cdr-register/v1/")
                if r["path"].endswith(REGISTER_STATUS_PATHS)
            ]
            ctx.info(
                "Register status endpoints polled by the DH (§3.3)",
                f"{len(polls)} request(s) seen" if polls else
                "none seen yet — the DH must call a Register status endpoint before the CTS continues",
            )

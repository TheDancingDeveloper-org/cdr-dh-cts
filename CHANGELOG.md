# Changelog

## 0.1.0 — unreleased

First version, targeting DH Test Plan 5.3.0 / CDS 1.36.0 (CTS DH Technical
Guidance 5.3.0, 22 July 2026).

- All 14 DH scenarios implemented, with prerequisites and dependencies; a
  scenario that cannot run reports `SKIP` with the missing setting.
- Runner, registry checked against `scenarios/tp-5.3.0.yaml`, JSON and console
  reports with bearer material redacted.
- JOSE layer: PS256 / ES256 signing and verification, RS256 and `none` for the
  negative cases, RFC 7638 key IDs, SSA minting.
- FAPI client (simulated ADR): discovery, PAR, request objects with PKCE, JARM,
  `private_key_jwt` with per-case defects, token / refresh / introspection /
  revocation, arrangement revocation, DCR create / get / update, Get Customer,
  mTLS and RFC 8705 endpoint aliases.
- Mock ecosystem (FastAPI) on the official CTS path layout: simulated Register
  (JWKS, SSA issuance, Get Data Recipients, statuses, status changes) and the
  simulated ADR's JWKS, redirect URI and arrangement-revocation endpoints, with a
  request log the scenarios assert on.
- Pluggable authorisation adapters (`direct_redirect`, `ecosystem_callback`) and
  a hook for DH-initiated revocation.
- Container image and Compose file; CI for lint, tests and the image.
- Offline tests run scenarios 1, 5, 7, 8, 9, 10 and 12 against an in-process
  fake DH, and check that a DH accepting malformed client assertions fails 12.

## Next

1. Run against a real DH (first target: a commercial CDR identity stack) and fix what
   that finds in scenarios 2–4, 6, 11, 13 and 14.
2. Extend the fake DH to DCR and the Register poll so 3, 4, 13 and 14 are
   verified offline too.
3. A browser-automation authorisation adapter for DHs with interactive login.

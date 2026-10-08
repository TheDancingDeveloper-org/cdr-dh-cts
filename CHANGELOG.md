# Changelog

## 0.1.0 — 2026-10-08

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

Fixed after the first end-to-end run against a real DH, each against the clause
the earlier behaviour contradicted:

- An unreachable DH endpoint is a `FAIL` of the DH, not a harness `ERROR`.
- Authorisation requests ask for the configured `adr.authorization_scope`, not
  `cdr:registration` (a DCR scope, not a consent scope).
- A token response without `cdr_arrangement_id` is a non-fatal failed check, so
  the scenario keeps collecting evidence.
- Arrangement revocation at the DH sends the `cdr_arrangement_id` form
  parameter (CDS: Data Holder arrangement revocation endpoint), and amendment
  checks that the arrangement ID stays the same.

## Next

1. Extend the fake DH to DCR and the Register poll so 3, 4, 13 and 14 are
   verified offline too.
2. A browser-automation authorisation adapter for DHs with interactive login.

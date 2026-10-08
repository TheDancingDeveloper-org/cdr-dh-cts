# cdr-dh-cts

A standalone, containerised **Data Holder Conformance Test Suite (CTS) harness**
for the Australian Consumer Data Right (CDR).

It plays the role the official ACCC CTS plays during onboarding — a **simulated
Accredited Data Recipient (ADR)** and a **simulated CDR Register** — and drives a
**Data Holder (DH) under test** through the conformance scenarios, then reports a
pass/fail result per scenario.

> This is an independent, open-source re-implementation of the *publicly
> documented* DH CTS scenarios. It is **not** affiliated with or endorsed by the
> ACCC/Treasury, and passing it is **not** a substitute for the official CTS run
> required for ecosystem activation. Use it for development, pre-flight and
> regression testing before you book the real thing.

- **Target test plan:** DH Test Plan **5.3.0**
- **Consumer Data Standards:** **1.36.0**
- **Security profile:** FAPI 1.0 Advanced (Authorization Code Flow + JARM;
  OIDC Hybrid flow retired), `private_key_jwt`, PAR, JARM, Holder-of-Key.
- Source of truth: *CTS Data Holder Technical Guidance 5.3.0 (22 July 2026)* and
  the [Consumer Data Standards](https://consumerdatastandardsaustralia.github.io/standards/).

## What it contains

| Path | What it is |
|---|---|
| `src/cdr_cts/` | The harness: scenario runner, the 14 DH scenarios, the FAPI client (simulated ADR), JOSE, config and reporting. |
| `src/cdr_mocks/` | The mock ecosystem (FastAPI): the simulated Register (SSA issuance, JWKS, Get Data Recipients, Get Data Recipient Statuses, Get Software Product Statuses) **and** the simulated ADR's public endpoints the DH calls back (JWKS, redirect URI, arrangement revocation), plus an admin API for the harness. |
| `scenarios/tp-5.3.0.yaml` | Machine-readable manifest of the 14 scenarios and their endpoints, keyed to the test-plan IDs; a test checks the code against it. |
| `config/config.example.yaml` | Template for the DH under test: endpoints, certificates, client and adapters. |
| `docker/`, `docker-compose.yml` | One image; a long-running mock ecosystem and a one-shot harness runner. |
| `tests/` | Offline tests, including the real scenarios run against an in-process fake Data Holder. |

The mock serves the same paths as the official CTS (`/cts/{conformanceId}/register/cdr-register/v1/...`,
`/cts/{conformanceId}/dr/...`), so a DH configured for the real CTS only needs a different host.

## The 14 Data Holder scenarios (TP 5.3.0)

All 14 are implemented. What each needs beyond a reachable DH:

| # | Scenario | Needs | Verified offline |
|---|---|---|---|
| 1 | Discovery Document | — | yes |
| 2 | Ensure Infosec Endpoints Using MTLS | mock ecosystem, mTLS edge, negative certificates | — |
| 3 | Ensure SSA Validation | mock ecosystem | — |
| 4 | Create Client Registration | mock ecosystem | — |
| 5 | First Consent | registered client, authorisation adapter | yes |
| 6 | Holder Of Key Resource Requests | mTLS edge, a second CDR certificate | — |
| 7 | Second Consent | as 5 | yes |
| 8 | Data Recipient Initiated Arrangement Revocation | as 5 | yes |
| 9 | Amending Existing Consent | as 5 | yes |
| 10 | Data Recipient Initiated Token Revocation | as 5 | yes |
| 11 | Data Holder Initiated Arrangement Revocation | as 5, mock ecosystem, a DH-side trigger | — |
| 12 | Ensure Client Assertion Data in Requests | as 5 | yes (and a lenient DH fails it) |
| 13 | Retrieve and Update Client Registration | mock ecosystem, registered client | — |
| 14 | Removed Software Product | as 5, mock ecosystem | — |

"Verified offline" means the scenario passes against the in-process fake DH in
`tests/`. The others need TLS, DCR trust or DH-side actions the fake does not
model, and are verified against a real DH. A scenario whose prerequisite is not
configured returns `SKIP` with the exact setting to add — never a silent `PASS`.

### Authorisation adapters

The CTS signs in as a test consumer. How that happens is DH-specific, so it is
pluggable (`authorization.adapter`): `direct_redirect` follows redirects for DHs
whose test login completes without interaction; `ecosystem_callback` prints the
URL for an operator and waits for the redirect at the mock. Write your own as a
`module:function` for anything else.

## Quick start

```sh
# 1. Configuration
cp config/config.example.yaml config/config.yaml   # edit DH endpoints + certs

# 2. Containerised: mock ecosystem (long-running) + harness (one-shot)
docker compose up -d --build mock-ecosystem
docker compose run --rm harness run --config /work/config/config.yaml

# or locally, without Docker
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev,mock]"
cdr-cts keys init keys                              # register.pem + adr.pem
cdr-cts mock --keys-dir keys &                      # mock ecosystem on :8080
cdr-cts list                                        # list scenarios
cdr-cts run --config config/config.yaml --only 1,4,5,12   # dependencies are added
```

Reports are written to `out/` as JSON (bearer material redacted) and summarised to
the console, keyed to the TP 5.3.0 scenario IDs. The exit code is non-zero when any
scenario fails or errors.

The DH must be able to reach the mock at `ecosystem.public_base_url` — most DHs
also require HTTPS there (`cdr-cts mock --tls-cert ... --tls-key ...`, or a TLS
proxy). To test a DH running in another Compose project, attach the mock to that
project's network.

## Using it from another project

Pin a release and let Docker build the image straight from the repository; no
checkout is needed:

```yaml
services:
  cts-harness:
    build:
      context: https://github.com/TheDancingDeveloper-org/cdr-dh-cts.git#v0.1.0
      dockerfile: docker/Dockerfile
    image: cdr-dh-cts:0.1.0
```

Exit codes: `0` every scenario passed, `1` at least one failed or errored, `2`
a usage or configuration error.

## Status

Version 0.1.0: all 14 scenarios implemented. Seven are verified offline against
the fake DH. All 14 have been run end to end against a commercial CDR identity
stack, and the harness defects that run exposed are fixed (`CHANGELOG.md`).
Failures that run reported against the Data Holder are left as findings: the
harness is never relaxed to make a particular product pass.

Contributions are welcome; see [`CONTRIBUTING.md`](CONTRIBUTING.md) and, for AI
coding agents, [`AGENTS.md`](AGENTS.md).

## Licence

MIT — see [`LICENSE`](LICENSE). Development/test use only; use synthetic
identities and data, never production credentials or consumer data.

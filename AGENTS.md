# Agent guide

Orientation for AI coding agents (and humans) changing this repository. Read
`README.md` first, then `CONTRIBUTING.md`.

## What this is

An independent harness for the CDR Data Holder Conformance Test Suite, test
plan 5.3.0 (CDS 1.36.0). It plays the simulated ADR and the simulated CDR
Register, drives a Data Holder through the 14 scenarios, and reports PASS,
FAIL, SKIP or ERROR per scenario.

## Rules that matter most

1. **The specification decides, never the Data Holder under test.** When a run
   against a product fails, decide from the CTS guidance and the CDS which side
   is wrong. Fix the harness only when it contradicts a cited clause, and say
   which clause in the commit message and `CHANGELOG.md`. Never relax a check,
   add a product-specific branch, or turn a FAIL into a SKIP to make a product
   pass.
2. **Stay vendor-neutral.** No product names, customer or participant names,
   hostnames, or configuration specific to one deployment. DH-specific
   behaviour belongs in the user's config or in an authorisation adapter.
3. **No real material.** No credentials, real certificates, private keys or
   consumer data. Tests generate keys at runtime; `.gitignore` covers `secrets/`,
   `out/`, `config/config.yaml`, `*.pem` and `*.key`.
4. **Fail loudly.** A scenario that cannot run returns SKIP naming the missing
   setting. A DH endpoint that cannot be reached is a FAIL of the DH; ERROR is
   reserved for harness defects.

## Where things go

| Change | Location |
|---|---|
| A scenario | `src/cdr_cts/scenarios/<area>.py`, its entry in `scenarios/tp-5.3.0.yaml` |
| ADR protocol (PAR, JARM, tokens, DCR, mTLS) | `src/cdr_cts/fapi.py`, `flows.py`, `authorize.py` |
| JOSE, SSA | `src/cdr_cts/jose.py`, `ssa.py` |
| Simulated Register and ADR endpoints | `src/cdr_mocks/` (official CTS path layout) |
| Offline tests, fake DH | `tests/` (`fake_dh.py`) |
| A new test plan version | a new `scenarios/tp-<version>.yaml`; record the change in `CHANGELOG.md` |

## Checks before committing

```sh
pip install -e ".[dev,mock]"
pytest
ruff check .
docker compose config --quiet
docker build -f docker/Dockerfile .
git diff --check
```

CI (`.github/workflows/ci.yml`) runs the same checks.

## Releases

Consumers pin a tag and build the image from the git URL
(`...cdr-dh-cts.git#vX.Y.Z`), so a tag is a contract:

- Never move or delete a pushed tag.
- Bump `pyproject.toml` and `src/cdr_cts/__init__.py` together.
- Date the `CHANGELOG.md` entry, then tag `vX.Y.Z`.
- Keep the exit codes (0 all passed, 1 a scenario failed or errored, 2 usage or
  configuration) and the report's JSON shape stable within a minor version.

# Contributing

## Ground rules

- **Spec first.** Every scenario cites the section of the *CTS Data Holder
  Technical Guidance* and the Consumer Data Standards it implements. When the
  guidance changes, bump `scenarios/tp-<version>.yaml` and record the change in
  `CHANGELOG.md`.
- **No real material.** Never commit production credentials, real certificates
  or private keys, consumer data, or anything identifying a participant. Tests
  use keys generated at runtime.
- **Fail loudly.** A scenario that cannot run returns `SKIP` with the exact
  missing prerequisite; it never returns `PASS` by default.

## Development

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,mock]"
pytest
ruff check .
docker compose config --quiet
```

## Adding or finishing a scenario

1. Find its entry in `scenarios/tp-5.3.0.yaml` (number, title, endpoints,
   requirements).
2. Implement `run()` in the matching module under `src/cdr_cts/scenarios/`,
   recording each high-level test step with `ctx.step(...)`.
3. Add an offline test for any new protocol helper.
4. Update the status table in `README.md`.

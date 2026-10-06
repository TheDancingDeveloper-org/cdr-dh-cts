# Security

This harness deliberately sends malformed and hostile requests (bad client
assertions, invalid certificates, revoked software products) to the Data Holder
it is pointed at.

- Run it **only** against non-production environments you are authorised to
  test.
- Use synthetic identities and data only.
- Keep client certificates, private keys and secrets outside the repository
  (`config/config.yaml`, `secrets/` and `*.pem` are ignored) and supply them at
  runtime via mounted files or environment variables.
- Reports in `out/` can contain tokens and request/response bodies; treat them
  as sensitive and do not publish them.

To report a vulnerability in the harness itself, open a private security
advisory on the repository rather than a public issue.

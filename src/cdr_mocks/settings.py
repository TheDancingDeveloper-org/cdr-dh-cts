"""Mock ecosystem settings, read from the environment."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from cdr_cts.jose import SigningKey

DEFAULT_CONFORMANCE_ID = "00000000-0000-4000-8000-000000000000"


@dataclass
class Settings:
    keys_dir: Path = Path("keys")
    #: Conformance ID accepted in ``/cts/{id}/...`` paths; ``*`` accepts any.
    conformance_id: str = DEFAULT_CONFORMANCE_ID
    #: Base URL the DH uses to reach this mock (for SSA URLs before the harness registers a participant).
    public_base_url: str = "http://localhost:8080"
    #: Generate missing key files on start-up instead of failing.
    generate_keys: bool = True
    #: Most recent requests kept in the log.
    request_log_size: int = 2000

    @classmethod
    def from_env(cls) -> Settings:
        env = os.environ.get
        return cls(
            keys_dir=Path(env("CDR_MOCK_KEYS_DIR", "keys")),
            conformance_id=env("CDR_MOCK_CONFORMANCE_ID", DEFAULT_CONFORMANCE_ID),
            public_base_url=env("CDR_MOCK_PUBLIC_BASE_URL", "http://localhost:8080").rstrip("/"),
            generate_keys=env("CDR_MOCK_GENERATE_KEYS", "true").lower() in ("1", "true", "yes"),
            request_log_size=int(env("CDR_MOCK_REQUEST_LOG_SIZE", "2000")),
        )


def load_or_create_key(path: Path, generate: bool, alg: str = "PS256") -> SigningKey:
    if path.exists():
        return SigningKey.from_pem_file(path)
    if not generate:
        raise FileNotFoundError(f"key file {path} not found (set CDR_MOCK_GENERATE_KEYS=true or run 'cdr-cts keys init')")
    key = SigningKey.generate(alg)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.to_pem())
    return key

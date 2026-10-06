from __future__ import annotations

from pathlib import Path

import pytest

from cdr_cts.config import Config, ConfigError

REPO = Path(__file__).resolve().parents[1]


def test_example_config_loads():
    config = Config.load(REPO / "config" / "config.example.yaml")
    assert config.plan == "5.3.0"
    assert config.adr.keys_dir == (REPO / "keys").resolve()
    assert config.tls.client.cert == (REPO / "secrets" / "adr-client.pem").resolve()
    assert config.tls.alternate_client.cert is None  # "" means not configured
    assert not config.tls.alternate_client.present


def test_unknown_keys_are_rejected(tmp_path):
    with pytest.raises(ConfigError, match="unknown key.*discovery_ur"):
        Config.from_dict({"dh": {"discovery_ur": "typo"}}, base_dir=tmp_path)


def test_environment_variables_are_expanded(tmp_path, monkeypatch):
    monkeypatch.setenv("CTS_TEST_CLIENT", "client-123")
    config = Config.from_dict({"adr": {"client_id": "${CTS_TEST_CLIENT}"}}, base_dir=tmp_path)
    assert config.adr.client_id == "client-123"


def test_default_paths_resolve_against_the_config_directory(tmp_path):
    config = Config.from_dict({}, base_dir=tmp_path)
    assert config.out_dir == (tmp_path / "out").resolve()
    assert config.adr.keys_dir == (tmp_path / "keys").resolve()


def test_simulated_ecosystem_urls_follow_the_cts_layout(tmp_path):
    config = Config.from_dict(
        {"conformance_id": "abc", "ecosystem": {"public_base_url": "https://eco.test/"}}, base_dir=tmp_path
    )
    assert config.register_base_url == "https://eco.test/cts/abc/register"
    assert config.adr_jwks_uri == "https://eco.test/cts/abc/dr/jwks"
    assert config.redirect_uri == "https://eco.test/cts/abc/dr/signin"
    assert config.adr_revocation_uri == "https://eco.test/cts/abc/dr/arrangements/revoke"


def test_bad_types_are_reported(tmp_path):
    with pytest.raises(ConfigError, match="mtls_edge must be a boolean"):
        Config.from_dict({"mtls_edge": "sometimes"}, base_dir=tmp_path)
    with pytest.raises(ConfigError, match="timeouts.http must be a number"):
        Config.from_dict({"timeouts": {"http": "soon"}}, base_dir=tmp_path)

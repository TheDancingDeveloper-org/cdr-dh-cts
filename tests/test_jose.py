from __future__ import annotations

import time

import pytest

from cdr_cts import jose


@pytest.mark.parametrize("alg", ["PS256", "ES256", "RS256"])
def test_sign_verify_round_trip(alg):
    key = jose.SigningKey.generate(alg)
    token = jose.sign({"sub": "x"}, key)
    assert jose.verify(token, jose.jwks([key]), algorithms=[alg]) == {"sub": "x"}


def test_kid_is_rfc7638_thumbprint_and_stable_across_pem():
    key = jose.SigningKey.generate("PS256")
    assert key.kid == jose.thumbprint(key.public_jwk())
    assert jose.SigningKey.from_pem(key.to_pem()).kid == key.kid


def test_tampered_payload_is_rejected():
    key = jose.SigningKey.generate("PS256")
    header, _, signature = jose.sign({"sub": "x"}, key).split(".")
    payload = jose.b64url(b'{"sub":"y"}')
    forged = f"{header}.{payload}.{signature}"
    with pytest.raises(jose.JoseError, match="signature"):
        jose.verify(forged, jose.jwks([key]))


def test_unknown_kid_is_rejected():
    signer, other = jose.SigningKey.generate("PS256"), jose.SigningKey.generate("PS256")
    with pytest.raises(jose.JoseError, match="no signing key"):
        jose.verify(jose.sign({}, signer), jose.jwks([other]))


@pytest.mark.parametrize("alg", ["none", "RS256", "", None])
def test_disallowed_algorithms_are_rejected_by_default(alg):
    key = jose.SigningKey.generate("PS256")
    header = {"alg": jose.REMOVE} if alg is None else {"alg": alg}
    with pytest.raises(jose.JoseError, match="not permitted"):
        jose.verify(jose.sign({}, key, header=header), jose.jwks([key]))


def test_missing_and_empty_alg_still_carry_a_valid_signature():
    key = jose.SigningKey.generate("PS256")
    for header in ({"alg": jose.REMOVE}, {"alg": ""}):
        decoded = jose.decode(jose.sign({"a": 1}, key, header=header))
        assert decoded.header.get("alg") in (None, "")
        assert decoded.signature  # signed with the key's own algorithm


def test_alg_none_has_an_empty_signature():
    token = jose.sign({}, jose.SigningKey.generate("PS256"), header={"alg": "none"})
    assert token.endswith(".")


def test_rs256_header_with_ec_key_uses_an_ephemeral_rsa_signer():
    token = jose.sign({}, jose.SigningKey.generate("ES256"), header={"alg": "RS256"})
    assert len(jose.decode(token).signature) == 256


def test_apply_overrides_removes_and_sets():
    assert jose.apply_overrides({"a": 1, "b": 2}, {"a": jose.REMOVE, "c": 3}) == {"b": 2, "c": 3}


def test_validate_claims():
    now = time.time()
    jose.validate_claims({"iss": "i", "aud": ["x", "a"], "exp": now + 60}, iss="i", aud="a")
    with pytest.raises(jose.JoseError, match="expired"):
        jose.validate_claims({"exp": now - 600})
    with pytest.raises(jose.JoseError, match="aud"):
        jose.validate_claims({"aud": "b", "exp": now + 60}, aud="a")
    with pytest.raises(jose.JoseError, match="nonce"):
        jose.validate_claims({"nonce": "n1", "exp": now + 60}, nonce="n2")

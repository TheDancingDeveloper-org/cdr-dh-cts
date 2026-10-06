"""Minimal JOSE helpers for the CDR security profile.

Compact JWS only (the profile this harness needs): PS256 and ES256 for normal
traffic, RS256 and ``none`` so the negative client-assertion cases can be built.
Kept dependency-light and explicit on purpose — the harness has to be able to
produce *malformed* tokens, which general-purpose JWT libraries refuse to do.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

#: Algorithms the CDR permits for signing.
CDR_ALGS = ("PS256", "ES256")
#: Algorithms this module can produce (RS256 only to build negative cases).
SUPPORTED_ALGS = ("PS256", "ES256", "RS256")


class JoseError(ValueError):
    """A token could not be decoded, verified or validated."""


class _Remove:
    def __repr__(self) -> str:
        return "REMOVE"


#: Override value meaning "delete this member" (header or claims).
REMOVE: Any = _Remove()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:
        raise JoseError(f"invalid base64url: {exc}") from exc


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _int_b64(value: int, length: int | None = None) -> str:
    length = length or max(1, (value.bit_length() + 7) // 8)
    return b64url(value.to_bytes(length, "big"))


def _b64_int(text: str) -> int:
    return int.from_bytes(b64url_decode(text), "big")


def apply_overrides(base: Mapping[str, Any], overrides: Mapping[str, Any] | None) -> dict:
    """Return a copy of ``base`` with ``overrides`` applied; ``REMOVE`` deletes a member."""
    result = dict(base)
    for name, value in (overrides or {}).items():
        if value is REMOVE:
            result.pop(name, None)
        else:
            result[name] = value
    return result


# --------------------------------------------------------------------------- keys


def public_jwk(public_key: Any) -> dict:
    """The public JWK members (no ``kid``/``alg``/``use``) for an RSA or P-256 key."""
    if isinstance(public_key, rsa.RSAPublicKey):
        numbers = public_key.public_numbers()
        return {"kty": "RSA", "n": _int_b64(numbers.n), "e": _int_b64(numbers.e)}
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if not isinstance(public_key.curve, ec.SECP256R1):
            raise JoseError("only P-256 EC keys are supported")
        numbers = public_key.public_numbers()
        return {"kty": "EC", "crv": "P-256", "x": _int_b64(numbers.x, 32), "y": _int_b64(numbers.y, 32)}
    raise JoseError(f"unsupported key type {type(public_key).__name__}")


def thumbprint(jwk: Mapping[str, Any]) -> str:
    """RFC 7638 JWK thumbprint (SHA-256), used as a deterministic ``kid``."""
    if jwk["kty"] == "RSA":
        members = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif jwk["kty"] == "EC":
        members = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    else:
        raise JoseError(f"unsupported kty {jwk['kty']!r}")
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return b64url(hashlib.sha256(canonical).digest())


def public_key_from_jwk(jwk: Mapping[str, Any]) -> Any:
    kty = jwk.get("kty")
    if kty == "RSA":
        return rsa.RSAPublicNumbers(_b64_int(jwk["e"]), _b64_int(jwk["n"])).public_key()
    if kty == "EC":
        if jwk.get("crv") != "P-256":
            raise JoseError(f"unsupported curve {jwk.get('crv')!r}")
        return ec.EllipticCurvePublicNumbers(
            _b64_int(jwk["x"]), _b64_int(jwk["y"]), ec.SECP256R1()
        ).public_key()
    raise JoseError(f"unsupported kty {kty!r}")


def _key_supports(private_key: Any, alg: str) -> bool:
    if alg in ("PS256", "RS256"):
        return isinstance(private_key, rsa.RSAPrivateKey)
    if alg == "ES256":
        return isinstance(private_key, ec.EllipticCurvePrivateKey)
    return False


@dataclass(frozen=True)
class SigningKey:
    """A private signing key with the ``alg`` and ``kid`` it is published under."""

    private_key: Any
    alg: str
    kid: str

    @classmethod
    def generate(cls, alg: str = "PS256", kid: str | None = None) -> SigningKey:
        if alg == "ES256":
            private_key: Any = ec.generate_private_key(ec.SECP256R1())
        elif alg in ("PS256", "RS256"):
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:
            raise JoseError(f"cannot generate a key for alg {alg!r}")
        return cls.from_private_key(private_key, alg, kid)

    @classmethod
    def from_private_key(cls, private_key: Any, alg: str | None = None, kid: str | None = None) -> SigningKey:
        alg = alg or ("ES256" if isinstance(private_key, ec.EllipticCurvePrivateKey) else "PS256")
        if not _key_supports(private_key, alg):
            raise JoseError(f"key type {type(private_key).__name__} cannot sign {alg}")
        kid = kid or thumbprint(public_jwk(private_key.public_key()))
        return cls(private_key, alg, kid)

    @classmethod
    def from_pem(cls, data: bytes, alg: str | None = None, kid: str | None = None) -> SigningKey:
        return cls.from_private_key(serialization.load_pem_private_key(data, password=None), alg, kid)

    @classmethod
    def from_pem_file(cls, path: str | Path, alg: str | None = None, kid: str | None = None) -> SigningKey:
        return cls.from_pem(Path(path).read_bytes(), alg, kid)

    def to_pem(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def public_jwk(self) -> dict:
        jwk = public_jwk(self.private_key.public_key())
        jwk.update({"kid": self.kid, "alg": self.alg, "use": "sig"})
        return jwk


def jwks(keys: Iterable[SigningKey]) -> dict:
    return {"keys": [key.public_jwk() for key in keys]}


# --------------------------------------------------------------------------- sign


def _sign_bytes(signing_input: bytes, private_key: Any, alg: str) -> bytes:
    if alg == "PS256":
        return private_key.sign(
            signing_input,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
    if alg == "RS256":
        return private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    if alg == "ES256":
        r, s = utils.decode_dss_signature(private_key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    raise JoseError(f"cannot sign with alg {alg!r}")


def sign(
    claims: Mapping[str, Any],
    key: SigningKey,
    *,
    header: Mapping[str, Any] | None = None,
    alg: str | None = None,
    signature: bytes | None = None,
) -> str:
    """Sign ``claims`` as a compact JWS.

    ``header`` overrides the default ``{"alg", "kid", "typ"}`` header (``REMOVE``
    deletes a member). The signing algorithm is ``alg`` if given, otherwise the
    header's ``alg`` when it is a real algorithm, otherwise the key's own — so a
    missing or empty ``alg`` header still produces a correctly signed token whose
    only defect is the header. ``alg: none`` produces an empty signature.
    ``signature`` replaces the signature bytes outright (tamper cases).
    """
    protected = apply_overrides({"alg": key.alg, "kid": key.kid, "typ": "JWT"}, header)
    signing_input = f"{b64url(_json_bytes(protected))}.{b64url(_json_bytes(dict(claims)))}".encode("ascii")
    if signature is None:
        header_alg = protected.get("alg")
        if header_alg == "none":
            signature = b""
        else:
            use = alg or (header_alg if header_alg in SUPPORTED_ALGS else key.alg)
            signer = key.private_key if _key_supports(key.private_key, use) else SigningKey.generate(use).private_key
            signature = _sign_bytes(signing_input, signer, use)
    return f"{signing_input.decode('ascii')}.{b64url(signature)}"


# --------------------------------------------------------------------------- verify


@dataclass(frozen=True)
class Decoded:
    header: dict
    claims: dict
    signing_input: bytes
    signature: bytes


def decode(token: str) -> Decoded:
    """Split and decode a compact JWS without verifying it."""
    if not isinstance(token, str):
        raise JoseError("token is not a string")
    parts = token.split(".")
    if len(parts) != 3:
        raise JoseError(f"expected a compact JWS with 3 parts, got {len(parts)}")
    try:
        header = json.loads(b64url_decode(parts[0]))
        claims = json.loads(b64url_decode(parts[1]))
    except json.JSONDecodeError as exc:
        raise JoseError(f"invalid JSON in token: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise JoseError("token header and payload must be JSON objects")
    return Decoded(header, claims, f"{parts[0]}.{parts[1]}".encode("ascii"), b64url_decode(parts[2]))


def _verify_signature(decoded: Decoded, jwk: Mapping[str, Any], alg: str) -> bool:
    public_key = public_key_from_jwk(jwk)
    try:
        if alg == "PS256":
            public_key.verify(
                decoded.signature,
                decoded.signing_input,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )
        elif alg == "RS256":
            public_key.verify(decoded.signature, decoded.signing_input, padding.PKCS1v15(), hashes.SHA256())
        elif alg == "ES256":
            if len(decoded.signature) != 64:
                return False
            der = utils.encode_dss_signature(
                int.from_bytes(decoded.signature[:32], "big"), int.from_bytes(decoded.signature[32:], "big")
            )
            public_key.verify(der, decoded.signing_input, ec.ECDSA(hashes.SHA256()))
        else:
            return False
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def verify(token: str, keyset: Mapping[str, Any], *, algorithms: Iterable[str] = CDR_ALGS) -> dict:
    """Verify a compact JWS against a JWKS and return its claims."""
    decoded = decode(token)
    alg = decoded.header.get("alg")
    if alg not in tuple(algorithms):
        raise JoseError(f"alg {alg!r} is not permitted")
    kid = decoded.header.get("kid")
    candidates = [
        jwk
        for jwk in keyset.get("keys", [])
        if (kid is None or jwk.get("kid") == kid) and jwk.get("use", "sig") == "sig"
    ]
    if not candidates:
        raise JoseError(f"no signing key with kid {kid!r} in the key set")
    for jwk in candidates:
        try:
            if _verify_signature(decoded, jwk, alg):
                return decoded.claims
        except JoseError:
            continue
    raise JoseError("signature verification failed")


def validate_claims(
    claims: Mapping[str, Any],
    *,
    iss: str | None = None,
    aud: str | None = None,
    nonce: str | None = None,
    require: Iterable[str] = ("exp",),
    leeway: int = 60,
    now: float | None = None,
) -> None:
    """Check the registered claims; raise ``JoseError`` naming the first failure."""
    now = time.time() if now is None else now
    for name in require:
        if name not in claims:
            raise JoseError(f"missing required claim {name!r}")
    if iss is not None and claims.get("iss") != iss:
        raise JoseError(f"iss {claims.get('iss')!r} != expected {iss!r}")
    if aud is not None:
        audience = claims.get("aud")
        audiences = audience if isinstance(audience, list) else [audience]
        if aud not in audiences:
            raise JoseError(f"aud {audience!r} does not contain {aud!r}")
    if nonce is not None and claims.get("nonce") != nonce:
        raise JoseError("nonce does not match the request")
    if "exp" in claims and float(claims["exp"]) < now - leeway:
        raise JoseError("token has expired")
    if "nbf" in claims and float(claims["nbf"]) > now + leeway:
        raise JoseError("token is not yet valid (nbf)")

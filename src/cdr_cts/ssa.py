"""Software Statement Assertions, as the CDR Register issues them.

The mock Register signs SSAs with these claims; the harness uses the same
builder to produce deliberately invalid ones (scenario 3).
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

from . import jose

REGISTER_ISSUER = "cdr-register"


@dataclass
class Participant:
    """The simulated ADR's Register entry: legal entity -> brand -> software product."""

    legal_entity_id: str
    legal_entity_name: str
    brand_id: str
    brand_name: str
    software_product_id: str
    software_product_name: str
    scope: str
    #: ``{base}/cts/{conformance id}/dr`` — where the simulated ADR's endpoints live.
    adr_base_url: str
    accreditation_number: str = "ADR-CTS-0001"
    legal_entity_status: str = "ACTIVE"
    brand_status: str = "ACTIVE"
    software_product_status: str = "ACTIVE"

    @property
    def jwks_uri(self) -> str:
        return f"{self.adr_base_url}/jwks"

    @property
    def redirect_uri(self) -> str:
        return f"{self.adr_base_url}/signin"

    @property
    def revocation_uri(self) -> str:
        return f"{self.adr_base_url}/arrangements/revoke"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Participant:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


def ssa_claims(participant: Participant, *, lifetime: int = 600, now: int | None = None) -> dict:
    now = int(time.time()) if now is None else now
    base = participant.adr_base_url
    return {
        "iss": REGISTER_ISSUER,
        "iat": now,
        "exp": now + lifetime,
        "jti": str(uuid.uuid4()),
        "legal_entity_id": participant.legal_entity_id,
        "legal_entity_name": participant.legal_entity_name,
        "org_id": participant.brand_id,
        "org_name": participant.brand_name,
        "client_name": participant.software_product_name,
        "client_description": "Simulated ADR software product used by the cdr-dh-cts harness",
        "client_uri": base,
        "redirect_uris": [participant.redirect_uri],
        "logo_uri": f"{base}/logo.png",
        "tos_uri": f"{base}/tos",
        "policy_uri": f"{base}/policy",
        "jwks_uri": participant.jwks_uri,
        "revocation_uri": participant.revocation_uri,
        "recipient_base_uri": base,
        "software_id": participant.software_product_id,
        "software_roles": "data-recipient-software-product",
        "scope": participant.scope,
    }


def mint_ssa(
    participant: Participant,
    register_key: jose.SigningKey,
    *,
    overrides: Mapping[str, Any] | None = None,
    lifetime: int = 600,
) -> str:
    return jose.sign(jose.apply_overrides(ssa_claims(participant, lifetime=lifetime), overrides), register_key)

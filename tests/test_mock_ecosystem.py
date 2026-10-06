from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from cdr_cts import jose
from cdr_cts.ssa import REGISTER_ISSUER
from cdr_mocks.app import create_app
from cdr_mocks.settings import Settings

CID = "11111111-2222-4333-8444-555555555555"
REGISTER = f"/cts/{CID}/register/cdr-register/v1"


@pytest.fixture()
def client(tmp_path):
    settings = Settings(keys_dir=tmp_path, conformance_id=CID, public_base_url="https://eco.test")
    return TestClient(create_app(settings))


def test_keys_are_generated_and_published(client, tmp_path):
    assert (tmp_path / "register.pem").exists() and (tmp_path / "adr.pem").exists()
    register = client.get(f"{REGISTER}/jwks").json()
    adr = client.get(f"/cts/{CID}/dr/jwks").json()
    assert register["keys"][0]["kid"] != adr["keys"][0]["kid"]


def test_ssa_is_signed_by_the_register_and_honours_overrides(client):
    ssa = client.post("/admin/ssa", json={"overrides": {"client_description": "changed", "tos_uri": None}}).json()["ssa"]
    claims = jose.verify(ssa, client.get(f"{REGISTER}/jwks").json())
    assert claims["iss"] == REGISTER_ISSUER
    assert claims["client_description"] == "changed"
    assert "tos_uri" not in claims
    assert claims["jwks_uri"] == f"https://eco.test/cts/{CID}/dr/jwks"


def test_participant_and_status_changes_show_in_register_apis(client):
    client.put("/admin/participant", json={"software_product_id": "sp-1", "legal_entity_id": "le-1"})
    client.put("/admin/status/software-product", json={"status": "REMOVED"})
    statuses = client.get(f"{REGISTER}/banking/data-recipients/brands/software-products/status", headers={"x-v": "2"})
    assert statuses.headers["x-v"] == "2"
    assert statuses.json()["data"] == [{"softwareProductId": "sp-1", "status": "REMOVED"}]
    recipients = client.get(f"{REGISTER}/banking/data-recipients").json()["data"]
    assert recipients[0]["legalEntityId"] == "le-1"
    assert recipients[0]["dataRecipientBrands"][0]["softwareProducts"][0]["status"] == "REMOVED"
    assert client.put("/admin/status/software-product", json={"status": "GONE"}).status_code == 400


def test_dh_requests_are_logged_and_filterable(client):
    since = client.get("/admin/health").json()["time"]
    client.get(f"{REGISTER}/banking/data-recipients/status")
    client.post(
        f"/cts/{CID}/dr/arrangements/revoke",
        content="cdr_arrangement_jwt=abc",
        headers={"content-type": "application/x-www-form-urlencoded", "authorization": "Bearer t"},
    )
    logged = client.get("/admin/requests", params={"since": since, "path_contains": "/dr/arrangements/revoke"}).json()
    entry = logged["requests"][-1]
    assert entry["form"] == {"cdr_arrangement_jwt": "abc"}
    assert entry["headers"]["authorization"] == "Bearer t"
    assert len(client.get("/admin/requests", params={"since": since}).json()["requests"]) == 2


def test_signin_callbacks_are_matched_by_state(client):
    key = jose.SigningKey.generate("PS256")
    jarm = jose.sign({"state": "s-1", "code": "c"}, key)
    assert client.get(f"/cts/{CID}/dr/signin", params={"response": jarm}).status_code == 200
    assert client.get("/admin/callbacks", params={"state": "s-1"}).json()["callbacks"][0]["params"]["response"] == jarm
    assert client.get("/admin/callbacks", params={"state": "other"}).json()["callbacks"] == []


def test_unknown_conformance_id_is_404(client):
    assert client.get("/cts/not-this-one/dr/jwks").status_code == 404

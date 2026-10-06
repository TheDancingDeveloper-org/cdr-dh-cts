"""FastAPI app for the mock ecosystem.

Public routes mirror the official CTS layout (§4 of the CTS DH Technical
Guidance 5.3.0) so a DH configured for the real CTS only needs a different host:

    /cts/{conformanceId}/register/cdr-register/v1/jwks
    /cts/{conformanceId}/register/cdr-register/v1/{industry}/data-recipients
    /cts/{conformanceId}/register/cdr-register/v1/{industry}/data-recipients/status
    /cts/{conformanceId}/register/cdr-register/v1/{industry}/data-recipients/brands/software-products/status
    /cts/{conformanceId}/dr/jwks
    /cts/{conformanceId}/dr/signin
    /cts/{conformanceId}/dr/arrangements/revoke

``/admin/*`` is for the harness: participant setup, SSA minting, status changes,
and the log of every request the DH made.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

from cdr_cts.jose import REMOVE, jwks
from cdr_cts.ssa import Participant, mint_ssa

from .settings import Settings, load_or_create_key

SOFTWARE_PRODUCT_STATUSES = {"ACTIVE", "INACTIVE", "REMOVED"}
DATA_RECIPIENT_STATUSES = {"ACTIVE", "SUSPENDED", "REVOKED", "SURRENDERED"}
LOGGED_HEADERS = ("authorization", "content-type", "x-v", "x-min-v", "user-agent", "x-fapi-interaction-id")


class State:
    def __init__(self, settings: Settings) -> None:
        self.lock = threading.Lock()
        self.participant = Participant(
            legal_entity_id="8a2e7c4d-0000-4000-8000-00000000a001",
            legal_entity_name="CTS Harness Data Recipient",
            brand_id="8a2e7c4d-0000-4000-8000-00000000b001",
            brand_name="CTS Harness Brand",
            software_product_id="8a2e7c4d-0000-4000-8000-00000000c001",
            software_product_name="CTS Harness Software Product",
            scope="openid profile common:customer.basic:read cdr:registration",
            adr_base_url=f"{settings.public_base_url}/cts/{settings.conformance_id.replace('*', 'any')}/dr",
        )
        self.requests: deque[dict] = deque(maxlen=settings.request_log_size)
        self.callbacks: deque[dict] = deque(maxlen=500)
        self.updated_at = _now_iso()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    register_key = load_or_create_key(settings.keys_dir / "register.pem", settings.generate_keys)
    adr_key = load_or_create_key(settings.keys_dir / "adr.pem", settings.generate_keys)
    state = State(settings)
    app = FastAPI(title="cdr-dh-cts mock ecosystem", docs_url="/admin/docs", openapi_url="/admin/openapi.json")
    app.state.mock = state

    def check_conformance_id(conformance_id: str) -> None:
        if settings.conformance_id != "*" and conformance_id != settings.conformance_id:
            raise HTTPException(404, f"unknown conformance id {conformance_id}")

    async def record(request: Request, conformance_id: str) -> dict:
        check_conformance_id(conformance_id)
        body = await request.body()
        entry: dict[str, Any] = {
            "time": time.time(),
            "method": request.method,
            "path": request.url.path,
            "query": dict(request.query_params),
            "headers": {k: v for k, v in request.headers.items() if k in LOGGED_HEADERS},
            "client": request.client.host if request.client else None,
        }
        if "application/x-www-form-urlencoded" in request.headers.get("content-type", ""):
            entry["form"] = {k: v[0] for k, v in parse_qs(body.decode("utf-8", "replace")).items()}
        elif body:
            entry["body"] = body.decode("utf-8", "replace")[:4000]
        with state.lock:
            state.requests.append(entry)
        return entry

    def register_response(data: Any, request: Request) -> JSONResponse:
        return JSONResponse(
            {"data": data, "links": {"self": str(request.url)}, "meta": {}},
            headers={"x-v": request.headers.get("x-v", "1")},
        )

    # ------------------------------------------------------------------ Register

    @app.get("/cts/{conformance_id}/register/cdr-register/v1/jwks")
    async def register_jwks(conformance_id: str, request: Request) -> dict:
        await record(request, conformance_id)
        return jwks([register_key])

    @app.get("/cts/{conformance_id}/register/cdr-register/v1/{industry}/data-recipients")
    async def data_recipients(conformance_id: str, industry: str, request: Request) -> JSONResponse:
        await record(request, conformance_id)
        p = state.participant
        return register_response(
            [
                {
                    "legalEntityId": p.legal_entity_id,
                    "legalEntityName": p.legal_entity_name,
                    "accreditationNumber": p.accreditation_number,
                    "accreditationLevel": "UNRESTRICTED",
                    "logoUri": f"{p.adr_base_url}/logo.png",
                    "status": p.legal_entity_status,
                    "dataRecipientBrands": [
                        {
                            "dataRecipientBrandId": p.brand_id,
                            "brandName": p.brand_name,
                            "logoUri": f"{p.adr_base_url}/logo.png",
                            "status": p.brand_status,
                            "softwareProducts": [
                                {
                                    "softwareProductId": p.software_product_id,
                                    "softwareProductName": p.software_product_name,
                                    "softwareProductDescription": "Simulated ADR software product",
                                    "logoUri": f"{p.adr_base_url}/logo.png",
                                    "status": p.software_product_status,
                                }
                            ],
                        }
                    ],
                    "lastUpdated": state.updated_at,
                }
            ],
            request,
        )

    @app.get("/cts/{conformance_id}/register/cdr-register/v1/{industry}/data-recipients/status")
    async def data_recipient_statuses(conformance_id: str, industry: str, request: Request) -> JSONResponse:
        await record(request, conformance_id)
        p = state.participant
        return register_response([{"legalEntityId": p.legal_entity_id, "status": p.legal_entity_status}], request)

    @app.get("/cts/{conformance_id}/register/cdr-register/v1/{industry}/data-recipients/brands/software-products/status")
    async def software_product_statuses(conformance_id: str, industry: str, request: Request) -> JSONResponse:
        await record(request, conformance_id)
        p = state.participant
        return register_response([{"softwareProductId": p.software_product_id, "status": p.software_product_status}], request)

    # ------------------------------------------------------------------ simulated ADR

    @app.get("/cts/{conformance_id}/dr/jwks")
    async def adr_jwks(conformance_id: str, request: Request) -> dict:
        await record(request, conformance_id)
        return jwks([adr_key])

    @app.api_route("/cts/{conformance_id}/dr/signin", methods=["GET", "POST"])
    async def signin(conformance_id: str, request: Request) -> HTMLResponse:
        entry = await record(request, conformance_id)
        params = dict(entry["query"])
        params.update(entry.get("form") or {})
        with state.lock:
            state.callbacks.append({"time": entry["time"], "params": params})
        outcome = "an error" if "error" in params else "a response"
        return HTMLResponse(f"<html><body><h1>Simulated ADR</h1><p>Received {outcome}; you can close this window.</p></body></html>")

    @app.post("/cts/{conformance_id}/dr/arrangements/revoke")
    async def arrangement_revoke(conformance_id: str, request: Request) -> Response:
        await record(request, conformance_id)
        return Response(status_code=204)

    # ------------------------------------------------------------------ admin

    @app.get("/admin/health")
    async def health() -> dict:
        return {"status": "ok", "time": time.time(), "conformance_id": settings.conformance_id}

    @app.get("/admin/participant")
    async def get_participant() -> dict:
        return state.participant.to_dict()

    @app.put("/admin/participant")
    async def put_participant(body: dict) -> dict:
        try:
            participant = Participant.from_dict({**state.participant.to_dict(), **body})
        except TypeError as exc:
            raise HTTPException(400, str(exc)) from exc
        with state.lock:
            state.participant = participant
            state.updated_at = _now_iso()
        return participant.to_dict()

    @app.post("/admin/ssa")
    async def post_ssa(body: dict | None = None) -> dict:
        overrides = {k: (REMOVE if v is None else v) for k, v in ((body or {}).get("overrides") or {}).items()}
        return {"ssa": mint_ssa(state.participant, register_key, overrides=overrides)}

    @app.put("/admin/status/software-product")
    async def put_software_product_status(body: dict) -> dict:
        status = str(body.get("status", "")).upper()
        if status not in SOFTWARE_PRODUCT_STATUSES:
            raise HTTPException(400, f"status must be one of {sorted(SOFTWARE_PRODUCT_STATUSES)}")
        with state.lock:
            state.participant.software_product_status = status
            state.updated_at = _now_iso()
        return {"software_product_status": status}

    @app.put("/admin/status/data-recipient")
    async def put_data_recipient_status(body: dict) -> dict:
        status = str(body.get("status", "")).upper()
        if status not in DATA_RECIPIENT_STATUSES:
            raise HTTPException(400, f"status must be one of {sorted(DATA_RECIPIENT_STATUSES)}")
        with state.lock:
            state.participant.legal_entity_status = status
            state.updated_at = _now_iso()
        return {"data_recipient_status": status}

    @app.get("/admin/requests")
    async def get_requests(since: float | None = None, path_contains: str | None = None) -> dict:
        with state.lock:
            entries = list(state.requests)
        if since is not None:
            entries = [e for e in entries if e["time"] >= since]
        if path_contains:
            entries = [e for e in entries if path_contains in e["path"]]
        return {"requests": entries}

    @app.delete("/admin/requests")
    async def clear_requests() -> dict:
        with state.lock:
            state.requests.clear()
            state.callbacks.clear()
        return {"cleared": True}

    @app.get("/admin/callbacks")
    async def get_callbacks(request: Request) -> dict:
        # Read ``state`` from the query directly: as a parameter it would shadow ``state`` above.
        wanted = request.query_params.get("state")
        with state.lock:
            entries = list(state.callbacks)
        if wanted:
            entries = [e for e in entries if e["params"].get("state") == wanted or _jarm_state(e["params"]) == wanted]
        return {"callbacks": entries}

    return app


def _jarm_state(params: dict) -> str | None:
    """The ``state`` inside an (unverified) JARM ``response``, so callbacks can be matched to requests."""
    from cdr_cts.jose import JoseError, decode

    response = params.get("response")
    if not response:
        return None
    try:
        return decode(response).claims.get("state")
    except JoseError:
        return None

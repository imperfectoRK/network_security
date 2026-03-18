"""
WebAuthn / FIDO2 Authentication Server — FastAPI + fido2 v2.x
Fixes over the original skeleton:
  1. Use PublicKeyCredentialUserEntity (not a plain dict) for register_begin.
  2. Serialize CredentialCreationOptions / CredentialRequestOptions to JSON
     manually — the objects are not directly JSON-serialisable.
  3. Decode base64url-encoded fields that the browser sends back before passing
     them to register_complete / authenticate_complete.
  4. authenticate_begin accepts AttestedCredentialData, not raw dicts.
  5. authenticate_complete needs AttestedCredentialData objects, not dicts.
  6. Store AttestedCredentialData directly so it can be re-used as-is.
  7. Serve the front-end HTML from the same process (no CORS headaches).
"""

import base64
import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestedCredentialData,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
)

# ---------------------------------------------------------------------------
# Server setup
# ---------------------------------------------------------------------------

rp = PublicKeyCredentialRpEntity(id="localhost", name="WebAuthn Demo")
server = Fido2Server(rp)

app = FastAPI(title="WebAuthn Demo")

# In-memory stores  (replace with a real DB in production)
# users[username] = {"credential": AttestedCredentialData, "sign_count": int}
users: dict = {}
# challenges[username] = state blob returned by fido2
challenges: dict = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def b64url_encode(data: bytes) -> str:
    """Standard base64url (no padding) encoding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    """Standard base64url decoding (handles missing padding)."""
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def serialize_creation_options(options) -> dict:
    """
    Convert a CredentialCreationOptions object to a plain JSON-safe dict
    that matches the shape the browser's navigator.credentials.create() expects.
    """
    pk = options.public_key
    out: dict = {
        "challenge": b64url_encode(pk.challenge),
        "rp": {"id": pk.rp.id, "name": pk.rp.name},
        "user": {
            "id": b64url_encode(pk.user.id),
            "name": pk.user.name,
            "displayName": pk.user.display_name,
        },
        "pubKeyCredParams": [
            {"type": p.type.value, "alg": p.alg.value if hasattr(p.alg, 'value') else p.alg}
            for p in pk.pub_key_cred_params
        ],
    }
    if pk.timeout is not None:
        out["timeout"] = pk.timeout
    if pk.attestation is not None:
        out["attestation"] = pk.attestation.value if hasattr(pk.attestation, 'value') else pk.attestation
    if pk.authenticator_selection is not None:
        sel = pk.authenticator_selection
        out["authenticatorSelection"] = {}
        if sel.get("authenticatorAttachment") is not None:
            out["authenticatorSelection"]["authenticatorAttachment"] = sel.get("authenticatorAttachment")
        if sel.get("userVerification") is not None:
            uv = sel.get("userVerification")
            out["authenticatorSelection"]["userVerification"] = uv.value if hasattr(uv, 'value') else uv
        if sel.get("residentKey") is not None:
            rk = sel.get("residentKey")
            out["authenticatorSelection"]["residentKey"] = rk.value if hasattr(rk, 'value') else rk
    if pk.exclude_credentials:
        out["excludeCredentials"] = [
            {"type": c.type.value, "id": b64url_encode(c.id)}
            for c in pk.exclude_credentials
        ]
    return out


def serialize_request_options(options) -> dict:
    """
    Convert a CredentialRequestOptions object to a plain JSON-safe dict
    that matches the shape the browser's navigator.credentials.get() expects.
    """
    pk = options.public_key
    out: dict = {
        "challenge": b64url_encode(pk.challenge),
    }
    if pk.timeout is not None:
        out["timeout"] = pk.timeout
    if pk.rp_id is not None:
        out["rpId"] = pk.rp_id
    if pk.user_verification is not None:
        uv = pk.user_verification
        out["userVerification"] = uv.value if hasattr(uv, 'value') else uv
    if pk.allow_credentials:
        out["allowCredentials"] = [
            {"type": c.type.value, "id": b64url_encode(c.id)}
            for c in pk.allow_credentials
        ]
    return out


def parse_registration_response(data: dict) -> dict:
    """
    The browser sends back base64url strings; fido2's register_complete needs
    raw bytes inside a dict shaped like a RegistrationResponse.
    """
    raw_id = b64url_decode(data["rawId"])
    attestation_object = b64url_decode(data["response"]["attestationObject"])
    client_data_json = b64url_decode(data["response"]["clientDataJSON"])
    return {
        "id": raw_id,
        "rawId": raw_id,
        "response": {
            "attestationObject": attestation_object,
            "clientDataJSON": client_data_json,
        },
        "type": data.get("type", "public-key"),
    }


def parse_authentication_response(data: dict) -> dict:
    """
    Same treatment for the authentication assertion.
    """
    raw_id = b64url_decode(data["rawId"])
    authenticator_data = b64url_decode(data["response"]["authenticatorData"])
    client_data_json = b64url_decode(data["response"]["clientDataJSON"])
    signature = b64url_decode(data["response"]["signature"])
    user_handle = (
        b64url_decode(data["response"]["userHandle"])
        if data["response"].get("userHandle")
        else None
    )
    out = {
        "id": raw_id,
        "rawId": raw_id,
        "response": {
            "authenticatorData": authenticator_data,
            "clientDataJSON": client_data_json,
            "signature": signature,
        },
        "type": data.get("type", "public-key"),
    }
    if user_handle is not None:
        out["response"]["userHandle"] = user_handle
    return out


# ---------------------------------------------------------------------------
# Routes — Registration
# ---------------------------------------------------------------------------

@app.post("/register/start")
async def register_start(request: Request):
    body = await request.json()
    username: str = body.get("username", "").strip()
    if not username:
        raise HTTPException(status_code=400, detail="username is required")

    user_entity = PublicKeyCredentialUserEntity(
        id=username.encode("utf-8"),
        name=username,
        display_name=username,
    )

    # Pass existing credentials to exclude so the same device can't register twice
    existing_credentials = []
    if username in users:
        existing_credentials = [users[username]["credential"]]

    options, state = server.register_begin(
        user_entity,
        credentials=existing_credentials,
        user_verification="preferred",
    )

    challenges[username] = state
    return JSONResponse(serialize_creation_options(options))


@app.post("/register/finish")
async def register_finish(request: Request):
    data = await request.json()
    username: str = data.get("username", "").strip()
    if username not in challenges:
        raise HTTPException(status_code=400, detail="No pending registration for this user")

    state = challenges.pop(username)

    try:
        response = parse_registration_response(data)
        auth_data = server.register_complete(state, response)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Registration failed: {exc}")

    credential: AttestedCredentialData = auth_data.credential_data
    users[username] = {
        "credential": credential,
        "sign_count": auth_data.counter,
    }
    return {"status": "ok", "username": username}


# ---------------------------------------------------------------------------
# Routes — Authentication
# ---------------------------------------------------------------------------

@app.post("/login/start")
async def login_start(request: Request):
    body = await request.json()
    username: str = body.get("username", "").strip()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found — please register first")

    stored = users[username]
    credentials = [stored["credential"]]  # AttestedCredentialData

    options, state = server.authenticate_begin(
        credentials,
        user_verification="preferred",
    )

    challenges[username] = state
    return JSONResponse(serialize_request_options(options))


@app.post("/login/finish")
async def login_finish(request: Request):
    data = await request.json()
    username: str = data.get("username", "").strip()
    if username not in challenges:
        raise HTTPException(status_code=400, detail="No pending authentication for this user")
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")

    state = challenges.pop(username)
    stored = users[username]
    credentials = [stored["credential"]]  # must be AttestedCredentialData

    try:
        response = parse_authentication_response(data)
        credential_used = server.authenticate_complete(state, credentials, response)
    except Exception as exc:
        raise HTTPException(status_code=401, detail=f"Authentication failed: {exc}")

    # Update sign counter to guard against cloned authenticators
    stored["sign_count"] = getattr(credential_used, "counter", stored["sign_count"])
    return {"status": "authenticated", "username": username}


# ---------------------------------------------------------------------------
# Serve front-end
# ---------------------------------------------------------------------------

HTML = Path(__file__).with_name("index.html").read_text()

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(HTML)

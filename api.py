"""FastAPI webhook wrapper around the POPIA masking pipeline.

Lets external POS / e-commerce frontends submit raw transaction payloads
directly, over a production-style HTTP API, instead of the Streamlit form.
Every request goes through the exact same deterministic validation and
masking core as app.py (popia_pipeline.py) -- this file only adds the
HTTP/auth/production concerns on top:

- Bearer-token auth, fail-closed if the token isn't configured (a POPIA
  webhook accepting unauthenticated writes is a worse failure mode than
  briefly refusing traffic).
- A body-size guard, since the payload is always a handful of short fields.
- Persistence to Supabase is best-effort: a masking/validation success is
  still returned to the caller even if the database write fails, with
  `persisted: false` so the caller can decide how to react. This mirrors
  the optional-Supabase pattern already used in app.py.
"""
import os
import logging
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from supabase import create_client

from popia_pipeline import SecureTransactionPayload, process_and_mask_transaction, get_system_salt

load_dotenv()

logger = logging.getLogger("ProfessionalOS.API")

# A valid request is four short fields; this is a generous ceiling that
# still blocks oversized/abusive request bodies.
MAX_BODY_BYTES = 4096

app = FastAPI(
    title="ProfessionalOS Secure Transaction Gateway API",
    version="1.0.0",
    description="POPIA-compliant webhook for POS / e-commerce transaction intake.",
)


class SanitizedTransactionResponse(BaseModel):
    merchant_hash: str
    transaction_value_zar: float
    masked_contact_phone: str
    masked_contact_email: str
    compliance_status: str
    persisted: bool


class HealthResponse(BaseModel):
    status: str
    salt_configured: bool
    supabase_configured: bool


def _get_supabase_client():
    url = os.getenv("SUPABASE_URL", "")
    key = os.getenv("SUPABASE_KEY", "")
    if url and key:
        return create_client(url, key)
    return None


@app.middleware("http")
async def enforce_max_body_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length is not None and int(content_length) > MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"detail": "Payload too large."})
    return await call_next(request)


def require_api_token(authorization: Optional[str] = Header(default=None)) -> None:
    """Fail closed: no configured token means no authenticated access at all."""
    expected = os.getenv("API_WEBHOOK_TOKEN", "")
    if not expected:
        raise HTTPException(status_code=503, detail="API authentication is not configured on this server.")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token.")
    provided = authorization[len("Bearer "):].strip()
    if provided != expected:
        raise HTTPException(status_code=401, detail="Invalid API token.")


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    try:
        get_system_salt()
        salt_ok = True
    except ValueError:
        salt_ok = False

    return HealthResponse(
        status="ok",
        salt_configured=salt_ok,
        supabase_configured=bool(os.getenv("SUPABASE_URL")) and bool(os.getenv("SUPABASE_KEY")),
    )


@app.post(
    "/v1/transactions",
    response_model=SanitizedTransactionResponse,
    dependencies=[Depends(require_api_token)],
)
def create_transaction(payload: SecureTransactionPayload) -> SanitizedTransactionResponse:
    try:
        salt = get_system_salt()
    except ValueError:
        logger.error("Rejected request: POPIA_SALT_KEY missing or insecure.")
        raise HTTPException(status_code=500, detail="Server misconfiguration: compliance salt unavailable.")

    # process_and_mask_transaction re-validates via SecureTransactionPayload
    # internally too -- deliberate defence in depth, not redundant trust.
    sanitized = process_and_mask_transaction(payload.model_dump(), salt)

    persisted = False
    client = _get_supabase_client()
    if client is not None:
        try:
            client.table("anonymized_transactions").insert(sanitized).execute()
            persisted = True
        except Exception as exc:  # noqa: BLE001 -- persistence is best-effort
            logger.warning("Supabase persistence failed: %s", exc)

    return SanitizedTransactionResponse(**sanitized, persisted=persisted)

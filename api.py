"""FastAPI webhook wrapper around the POPIA masking pipeline.

Lets external POS / e-commerce frontends submit raw transaction payloads
directly, over a production-style HTTP API, instead of the Streamlit form.
Every request goes through the exact same deterministic validation and
masking core as app.py (popia_pipeline.py) -- this file only adds the
HTTP/auth/production/multi-tenant concerns on top:

- Per-tenant bearer-token auth (tenant_auth.py): every request is resolved
  to a specific onboarded tenant, and every persisted row is tagged with
  that tenant's id. Fail-closed if tenant auth isn't configured (Supabase
  + TENANT_TOKEN_PEPPER) -- a webhook accepting unauthenticated or
  unattributed writes is a worse failure mode than briefly refusing
  traffic.
- A body-size guard, since a single-transaction payload is always a
  handful of short fields (CSV bulk uploads get a separate, larger cap).
- Persistence to Supabase is best-effort: a masking/validation success is
  still returned to the caller even if the database write fails, with
  `persisted: false` so the caller can decide how to react. This mirrors
  the optional-Supabase pattern already used in app.py.
"""
import os
import logging
from typing import Optional

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from supabase import create_client

from popia_pipeline import SecureTransactionPayload, process_and_mask_transaction, get_system_salt
from csv_ingestion import CsvFormatError, ingest_transactions_csv
from tenant_auth import Tenant, TenantAuthError, get_tenant_token_pepper, resolve_tenant

load_dotenv()

logger = logging.getLogger("ProfessionalOS.API")

# A valid request is four short fields; this is a generous ceiling that
# still blocks oversized/abusive request bodies.
MAX_BODY_BYTES = 4096

# CSV bulk uploads are legitimately larger than a single JSON payload --
# generous enough for MAX_CSV_ROWS short rows, still a hard ceiling.
MAX_CSV_BODY_BYTES = 1_000_000

app = FastAPI(
    title="ProfessionalOS Secure Transaction Gateway API",
    version="1.0.0",
    description="POPIA-compliant, multi-tenant webhook for POS / e-commerce transaction intake.",
)


class SanitizedTransactionResponse(BaseModel):
    merchant_hash: str
    transaction_value_zar: float
    masked_contact_phone: str
    masked_contact_email: str
    compliance_status: str
    tenant_id: str
    persisted: bool


class BulkIngestionRowResponse(BaseModel):
    row_number: int
    status: str
    merchant_hash: Optional[str] = None
    transaction_value_zar: Optional[float] = None
    masked_contact_phone: Optional[str] = None
    masked_contact_email: Optional[str] = None
    compliance_status: Optional[str] = None
    error: Optional[str] = None
    persisted: Optional[bool] = None


class BulkIngestionResponse(BaseModel):
    tenant_id: str
    total_rows: int
    succeeded: int
    failed: int
    persisted_count: int
    results: list[BulkIngestionRowResponse]


class HealthResponse(BaseModel):
    status: str
    salt_configured: bool
    supabase_configured: bool
    tenant_auth_configured: bool


def _get_supabase_client():
    url = os.getenv("SUPABASE_URL", "")
    key = os.getenv("SUPABASE_KEY", "")
    if url and key:
        return create_client(url, key)
    return None


def _lookup_tenant_by_hash(token_hash: str) -> Optional[dict]:
    """Looks up a tenant by its token hash. Returns None on any failure
    (unknown hash, no Supabase configured, or a query error) -- resolve_tenant
    turns every "no record" case into the same generic auth error."""
    client = _get_supabase_client()
    if client is None:
        return None
    try:
        resp = (
            client.table("tenants")
            .select("id,is_active")
            .eq("token_hash", token_hash)
            .limit(1)
            .execute()
        )
        rows = resp.data or []
        return rows[0] if rows else None
    except Exception as exc:  # noqa: BLE001 -- treat any lookup failure as "unknown token"
        logger.warning("Tenant lookup failed: %s", exc)
        return None


@app.middleware("http")
async def enforce_max_body_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length is not None:
        limit = MAX_CSV_BODY_BYTES if request.url.path == "/v1/transactions/bulk" else MAX_BODY_BYTES
        if int(content_length) > limit:
            return JSONResponse(status_code=413, content={"detail": "Payload too large."})
    return await call_next(request)


def require_tenant(authorization: Optional[str] = Header(default=None)) -> Tenant:
    """Fail closed: no configured tenant auth (Supabase + pepper) means no
    authenticated access at all. Resolves the bearer token to a specific
    active tenant, or raises a 401 with a single generic message -- never
    revealing whether the token was malformed, unknown, or deactivated."""
    if not os.getenv("SUPABASE_URL") or not os.getenv("SUPABASE_KEY"):
        raise HTTPException(status_code=503, detail="Tenant authentication is not configured on this server.")

    try:
        pepper = get_tenant_token_pepper()
    except ValueError:
        raise HTTPException(status_code=503, detail="Tenant authentication is not configured on this server.")

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token.")
    token = authorization[len("Bearer "):].strip()

    try:
        return resolve_tenant(token, pepper, _lookup_tenant_by_hash)
    except TenantAuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc))


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    try:
        get_system_salt()
        salt_ok = True
    except ValueError:
        salt_ok = False

    try:
        get_tenant_token_pepper()
        pepper_ok = True
    except ValueError:
        pepper_ok = False

    supabase_ok = bool(os.getenv("SUPABASE_URL")) and bool(os.getenv("SUPABASE_KEY"))

    return HealthResponse(
        status="ok",
        salt_configured=salt_ok,
        supabase_configured=supabase_ok,
        tenant_auth_configured=pepper_ok and supabase_ok,
    )


@app.post("/v1/transactions", response_model=SanitizedTransactionResponse)
def create_transaction(
    payload: SecureTransactionPayload,
    tenant: Tenant = Depends(require_tenant),
) -> SanitizedTransactionResponse:
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
            client.table("anonymized_transactions").insert({**sanitized, "tenant_id": tenant.id}).execute()
            persisted = True
        except Exception as exc:  # noqa: BLE001 -- persistence is best-effort
            logger.warning("Supabase persistence failed: %s", exc)

    return SanitizedTransactionResponse(**sanitized, tenant_id=tenant.id, persisted=persisted)


@app.post("/v1/transactions/bulk", response_model=BulkIngestionResponse)
async def create_transactions_bulk(
    file: UploadFile = File(...),
    tenant: Tenant = Depends(require_tenant),
) -> BulkIngestionResponse:
    """CSV bulk ingestion: same deterministic validation + masking core as
    /v1/transactions, run row-by-row, with per-row results and best-effort
    persistence. One bad row never blocks the rest of the file. Every
    persisted row is tagged with the authenticated tenant's id."""
    raw_bytes = await file.read()
    if len(raw_bytes) > MAX_CSV_BODY_BYTES:
        raise HTTPException(status_code=413, detail="CSV file too large.")

    try:
        csv_text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="CSV file must be UTF-8 encoded.")

    try:
        salt = get_system_salt()
    except ValueError:
        logger.error("Rejected bulk request: POPIA_SALT_KEY missing or insecure.")
        raise HTTPException(status_code=500, detail="Server misconfiguration: compliance salt unavailable.")

    try:
        summary = ingest_transactions_csv(csv_text, salt)
    except CsvFormatError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    client = _get_supabase_client()
    persisted_count = 0
    response_rows: list[BulkIngestionRowResponse] = []

    for row in summary.results:
        persisted: Optional[bool] = None
        if row.status == "success":
            persisted = False
            if client is not None:
                try:
                    client.table("anonymized_transactions").insert({
                        "merchant_hash": row.merchant_hash,
                        "transaction_value_zar": row.transaction_value_zar,
                        "masked_contact_phone": row.masked_contact_phone,
                        "masked_contact_email": row.masked_contact_email,
                        "compliance_status": row.compliance_status,
                        "tenant_id": tenant.id,
                    }).execute()
                    persisted = True
                    persisted_count += 1
                except Exception as exc:  # noqa: BLE001 -- persistence is best-effort
                    logger.warning("Supabase persistence failed for row %s: %s", row.row_number, exc)
        response_rows.append(BulkIngestionRowResponse(**row.model_dump(), persisted=persisted))

    return BulkIngestionResponse(
        tenant_id=tenant.id,
        total_rows=summary.total_rows,
        succeeded=summary.succeeded,
        failed=summary.failed,
        persisted_count=persisted_count,
        results=response_rows,
    )

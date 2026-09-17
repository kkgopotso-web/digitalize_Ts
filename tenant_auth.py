"""Per-tenant API-token authentication for the multi-tenant gateway.

Each onboarded business (tenant) gets its own opaque bearer token,
generated out-of-band (see scripts/create_tenant.py) and stored in
Supabase only as a salted HMAC-SHA256 hash -- the plaintext token is
never persisted anywhere, the same "hash sensitive strings before
persistence" rule the POPIA masking pipeline applies to phone numbers
and emails (popia_pipeline.py). A separate pepper (TENANT_TOKEN_PEPPER)
is used here rather than POPIA_SALT_KEY, deliberately: mixing an
auth secret with the data-masking secret would mean rotating one forces
rotating the other.

The Supabase lookup is injected (`lookup_by_hash`) so the actual
hashing/matching/generic-error logic here stays pure and unit-testable
without a database.
"""
import os
import hmac
import hashlib
import secrets
from typing import Callable, Optional

from pydantic import BaseModel


class Tenant(BaseModel):
    id: str
    is_active: bool


class TenantAuthError(Exception):
    """Raised for any tenant-auth failure. The message is always the same
    generic string, regardless of whether the token was malformed, unknown,
    or belongs to a deactivated tenant -- this avoids giving a caller a
    token-enumeration side channel."""


_GENERIC_AUTH_ERROR = "Invalid or unknown API token."


def get_tenant_token_pepper() -> str:
    """Retrieves and validates the tenant-token pepper from the environment."""
    pepper = os.getenv("TENANT_TOKEN_PEPPER")
    if not pepper or len(pepper) < 16:
        raise ValueError("System security failure: Insecure or missing TENANT_TOKEN_PEPPER in environment.")
    return pepper


def hash_tenant_token(token: str, pepper: str) -> str:
    """Deterministic, irreversible HMAC-SHA256 hash of a tenant bearer token."""
    if not pepper or len(pepper) < 16:
        raise ValueError("System security failure: Invalid or insecure pepper provided.")
    return hmac.new(
        pepper.encode("utf-8"),
        token.strip().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def resolve_tenant(
    token: str,
    pepper: str,
    lookup_by_hash: Callable[[str], Optional[dict]],
) -> Tenant:
    """Hashes the presented token and resolves it to an active Tenant via
    the injected lookup function (typically a Supabase query by
    token_hash). Raises TenantAuthError -- always with the same generic
    message -- for a blank token, an unknown hash, or an inactive tenant."""
    if not token or not token.strip():
        raise TenantAuthError(_GENERIC_AUTH_ERROR)

    token_hash = hash_tenant_token(token, pepper)
    record = lookup_by_hash(token_hash)

    if not record:
        raise TenantAuthError(_GENERIC_AUTH_ERROR)

    tenant = Tenant(id=record["id"], is_active=bool(record.get("is_active", False)))
    if not tenant.is_active:
        raise TenantAuthError(_GENERIC_AUTH_ERROR)

    return tenant


def generate_tenant_token(prefix: str = "tnt") -> str:
    """Generates a new opaque, high-entropy tenant bearer token. Only shown
    once, at creation time (see scripts/create_tenant.py) -- never stored
    anywhere in plaintext, including in the return value of
    build_tenant_record below."""
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def build_tenant_record(tenant_name: str, tenant_slug: str, pepper: str) -> tuple[str, dict]:
    """Generates a fresh tenant token and the Supabase row to insert for it.
    Returns (plaintext_token, row_dict) -- the plaintext token is only ever
    in the first element, never in the row dict, so a caller that logs or
    persists only `record` can never leak it."""
    if not tenant_name or not tenant_name.strip():
        raise ValueError("tenant_name must not be blank.")
    if not tenant_slug or not tenant_slug.strip():
        raise ValueError("tenant_slug must not be blank.")

    token = generate_tenant_token()
    record = {
        "tenant_name": tenant_name.strip(),
        "tenant_slug": tenant_slug.strip(),
        "token_hash": hash_tenant_token(token, pepper),
        "is_active": True,
    }
    return token, record

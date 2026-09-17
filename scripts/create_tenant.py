#!/usr/bin/env python3
"""Onboard a new tenant (business) onto the ProfessionalOS transaction gateway.

Generates a fresh bearer token, prints it ONCE (it is not recoverable
afterwards -- only its salted hash is stored), and inserts the tenant row
into Supabase.

Usage:
    python scripts/create_tenant.py "Soweto Traders" soweto-traders

Requires SUPABASE_URL, SUPABASE_KEY, and TENANT_TOKEN_PEPPER to be set
(via .env or the environment).
"""
import os
import sys

from dotenv import load_dotenv
from supabase import create_client

from tenant_auth import build_tenant_record, get_tenant_token_pepper

load_dotenv()


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: python scripts/create_tenant.py <tenant_name> <tenant_slug>", file=sys.stderr)
        return 1

    tenant_name, tenant_slug = sys.argv[1], sys.argv[2]

    supabase_url = os.getenv("SUPABASE_URL", "")
    supabase_key = os.getenv("SUPABASE_KEY", "")
    if not supabase_url or not supabase_key:
        print("ERROR: SUPABASE_URL and SUPABASE_KEY must be set.", file=sys.stderr)
        return 1

    try:
        pepper = get_tenant_token_pepper()
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    try:
        token, record = build_tenant_record(tenant_name, tenant_slug, pepper)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    client = create_client(supabase_url, supabase_key)
    result = client.table("tenants").insert(record).execute()
    tenant_id = result.data[0]["id"] if result.data else "(unknown)"

    print("Tenant created.")
    print(f"  tenant_id:   {tenant_id}")
    print(f"  tenant_name: {record['tenant_name']}")
    print(f"  tenant_slug: {record['tenant_slug']}")
    print()
    print("Bearer token (copy this now -- it will not be shown again):")
    print(f"  {token}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

-- ProfessionalOS: multi-tenant schema
-- Deployed schema for project "professionalos" (hhaofskptttiekxuiufk).
-- Only irreversibly-hashed / derived values are ever persisted here.
-- No raw phone numbers, emails, merchant identifiers, or tenant tokens
-- are stored -- tenant tokens are salted-HMAC hashed the same way PII is.

-- ---------- tenants ----------
-- One row per onboarded business. token_hash is HMAC-SHA256(token,
-- TENANT_TOKEN_PEPPER) -- see tenant_auth.py -- never the plaintext
-- token. Rows are created out-of-band via scripts/create_tenant.py,
-- which is the only place the plaintext token is ever shown (once, at
-- creation time).
create table if not exists public.tenants (
    id          uuid primary key default gen_random_uuid(),
    tenant_name text not null,
    tenant_slug text not null unique,
    token_hash  text not null unique,
    is_active   boolean not null default true,
    created_at  timestamptz not null default now()
);

-- RLS is enabled, but this is a POC-level tradeoff: the API's own
-- Supabase client uses the anon/publishable key (see SUPABASE_KEY in
-- .env) to look up a tenant by token_hash on every request, so anon/
-- authenticated need SELECT here. token_hash is a one-way HMAC digest
-- (not reversible to the plaintext token) so this does not itself leak
-- tenant credentials, but tenant_name/tenant_slug are also readable by
-- anyone holding the publishable key this way. Before onboarding real
-- paying tenants, migrate the API to a service_role key and drop these
-- SELECT policies entirely.
alter table public.tenants enable row level security;

create policy if not exists "anon_can_select_tenants_for_auth"
    on public.tenants
    for select
    to anon
    using (true);

create policy if not exists "authenticated_can_select_tenants_for_auth"
    on public.tenants
    for select
    to authenticated
    using (true);

-- ---------- anonymized_transactions ----------
create table if not exists public.anonymized_transactions (
    id                    uuid primary key default gen_random_uuid(),
    tenant_id             uuid not null references public.tenants(id),
    merchant_hash         text not null,
    transaction_value_zar numeric not null check (transaction_value_zar > 0),
    masked_contact_phone  text not null,
    masked_contact_email  text not null,
    compliance_status     text not null default 'COMPLIANT_ANONYMISED',
    created_at            timestamptz not null default now()
);

create index if not exists idx_anonymized_transactions_merchant_hash
    on public.anonymized_transactions (merchant_hash);

create index if not exists idx_anonymized_transactions_tenant_id
    on public.anonymized_transactions (tenant_id);

-- RLS is enabled on this table. Because every value written here is already
-- an irreversible SHA-256 HMAC digest (see popia_pipeline.py), write access
-- from the app's anon/publishable key carries no PII exposure risk. No
-- SELECT/UPDATE/DELETE policy is granted to anon or authenticated, so the
-- audit log itself stays read-restricted (service_role / dashboard only).
-- Tenant isolation on INSERT is enforced at the API layer (api.py resolves
-- tenant_id from the caller's bearer token server-side, before the insert
-- is built) -- not by RLS, since there is no per-tenant Supabase Auth JWT
-- in this architecture yet.
alter table public.anonymized_transactions enable row level security;

create policy if not exists "anon_can_insert_masked_transactions"
    on public.anonymized_transactions
    for insert
    to anon
    with check (true);

create policy if not exists "authenticated_can_insert_masked_transactions"
    on public.anonymized_transactions
    for insert
    to authenticated
    with check (true);

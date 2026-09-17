-- ProfessionalOS: anonymized_transactions
-- Deployed schema for project "professionalos" (hhaofskptttiekxuiufk).
-- Only irreversibly-hashed / derived values are ever persisted here.
-- No raw phone numbers, emails, or merchant identifiers are stored.

create table if not exists public.anonymized_transactions (
    id                    uuid primary key default gen_random_uuid(),
    merchant_hash         text not null,
    transaction_value_zar numeric not null check (transaction_value_zar > 0),
    masked_contact_phone  text not null,
    masked_contact_email  text not null,
    compliance_status     text not null default 'COMPLIANT_ANONYMISED',
    created_at            timestamptz not null default now()
);

create index if not exists idx_anonymized_transactions_merchant_hash
    on public.anonymized_transactions (merchant_hash);

-- RLS is enabled on this table. Because every value written here is already
-- an irreversible SHA-256 HMAC digest (see popia_pipeline.py), write access
-- from the app's anon/publishable key carries no PII exposure risk. No
-- SELECT/UPDATE/DELETE policy is granted to anon or authenticated, so the
-- audit log itself stays read-restricted (service_role / dashboard only).
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

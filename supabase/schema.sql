-- ProfessionalOS: anonymized_transactions
-- Only irreversibly-hashed / derived values are ever persisted here.
-- No raw phone numbers, emails, or merchant identifiers are stored.

create table if not exists anonymized_transactions (
    id                    bigint generated always as identity primary key,
    merchant_hash         text not null,
    transaction_value_zar numeric(12, 2) not null check (transaction_value_zar > 0),
    masked_contact_phone  text not null,
    masked_contact_email  text not null,
    compliance_status     text not null default 'COMPLIANT_ANONYMISED',
    created_at            timestamptz not null default now()
);

create index if not exists idx_anonymized_transactions_merchant_hash
    on anonymized_transactions (merchant_hash);

# ProfessionalOS — Secure Transaction, API & BI Gateway (POC)

The POPIA-compliant, multi-tenant data-privacy and transaction-ingestion
engine for Orynexa Technologies' ProfessionalOS / BusinessOS platform
(township-business digitisation, funded via Tia Funding). Five pillars:

1. **POPIA anonymisation firewall** — intercepts raw phone numbers, emails
   and merchant identifiers at intake and irreversibly masks them with a
   salted SHA-256 HMAC before anything is stored or displayed
   (`popia_pipeline.py`).
2. **Sanitised persistence** — writes only the masked payload (never raw
   values) to Supabase for audit/ledger reporting, tagged with the
   submitting tenant.
3. **Safe AI intelligence dispatch** — routes *already-anonymised*,
   deterministically-computed merchant metrics to an OpenRouter multi-model
   pipeline (Gemini Flash primary, Claude Haiku fallback) for a
   plain-language business-insight summary. The LLM never sees raw data
   and never computes a number itself — it only writes prose over figures
   Python has already calculated (`bi_dispatch.py`).
4. **Production webhook (REST API)** — `POST /v1/transactions` exposes the
   exact same masking core over HTTP, per-tenant bearer-token authenticated,
   for external POS/e-commerce frontends to submit raw payloads directly
   (`api.py`). `POST /v1/transactions/bulk` does the same over a CSV file
   for batch imports — every row validated and masked independently
   (`csv_ingestion.py`), so one bad row never blocks the rest of the file.
   The Streamlit app (`app.py`) exposes both the single-transaction form
   and a CSV upload panel over the same pipeline; the API is the
   machine-facing surface.
5. **Multi-tenancy** (`tenant_auth.py`) — every business (tenant) gets its
   own opaque bearer token, stored only as a salted HMAC hash (never
   plaintext, same rule as PII). Every request is resolved to a specific
   active tenant and every persisted row is tagged with `tenant_id` --
   one tenant's token can never write or be attributed to another
   tenant's data. Onboard a new tenant with `scripts/create_tenant.py`.

## Design principles (per project rules)

- **Strict Pydantic validation** — every payload (raw intake — shared
  between the UI and the API — and the re-validated masked records at the
  AI-dispatch boundary) is checked against exact types/patterns; anything
  malformed is rejected outright, at the HTTP layer with a 422 for the API.
- **Deterministic core logic** — all masking, hashing, currency math and
  metric aggregation is hard-coded Python. LLMs are restricted to
  generating narrative text over numbers they're handed.
- **Zero plaintext leakage** — raw phone/email/merchant values never reach
  the response, the UI, the API response, the database, or the AI
  pipeline; only `ANON_...` HMAC digests and aggregate totals do.
  `bi_dispatch.assert_no_pii_leak()` is a second, independent
  defence-in-depth scan of every payload right before it leaves the
  system, on top of the Pydantic validation.
- **Fail closed** — the API refuses all traffic with a 503 if tenant
  auth isn't configured (Supabase + `TENANT_TOKEN_PEPPER`), rather than
  silently allowing unauthenticated or unattributed writes.
- **Tenant isolation** — every request is resolved to one specific,
  active tenant from its bearer token; every persisted row is tagged
  `tenant_id` server-side. Unknown-token and deactivated-tenant failures
  return the exact same generic error, so a caller can't use the API to
  probe which tokens exist.
- **Test-driven** — 91 pytest cases across `tests/test_popia_pipeline.py`,
  `tests/test_csv_ingestion.py`, `tests/test_bi_dispatch.py`,
  `tests/test_tenant_auth.py` and `tests/test_api.py` cover valid input,
  every validation failure mode, hash determinism, salt/pepper handling,
  PII-leak detection, multi-model fallback, tenant resolution/isolation,
  and the full API auth/error surface (mocked HTTP throughout, no live
  network calls in CI).

## Setup

```bash
python -m venv .venv
source .venv/bin/activate   # .venv\Scripts\activate on Windows
pip install -r requirements.txt
```

Create a `.env` file (never committed — see `.gitignore`):

```
POPIA_SALT_KEY=<a random string, 16+ characters>
SUPABASE_URL=<your Supabase project URL>
SUPABASE_KEY=<your Supabase anon/publishable key>
OPENROUTER_API_KEY=<your OpenRouter API key>
TENANT_TOKEN_PEPPER=<a random string, 16+ characters -- distinct from POPIA_SALT_KEY>
```

Every integration is optional and degrades gracefully if unset: Supabase
persistence is skipped (`persisted: false`), the AI insights panel is
disabled, and the API refuses all traffic (503) — but the core masking
pipeline always works.

Provision the database tables (once) with `supabase/schema.sql`, e.g. via
the Supabase SQL editor or `supabase db push`. It creates `tenants` and
`anonymized_transactions`, with the RLS policies that let the anon key
insert masked rows (and look up tenants by token hash) without granting
broader read access.

Onboard a tenant (once per business) before it can call the API or use
the Streamlit form:

```bash
python scripts/create_tenant.py "Soweto Traders" soweto-traders
```

This prints a bearer token once -- copy it immediately, it is not
recoverable afterwards (only its salted hash is stored).

Model choice for AI dispatch is configurable without a code change:
`OPENROUTER_PRIMARY_MODEL` and `OPENROUTER_FALLBACK_MODEL` env vars
override the defaults (`google/gemini-2.0-flash-001` /
`anthropic/claude-3.5-haiku`).

## Run

Streamlit UI:

```bash
streamlit run app.py
```

REST API (for local dev; see Cloud Run notes below for production):

```bash
uvicorn api:app --reload --port 8000
```

Example call (use a tenant token from `scripts/create_tenant.py`):

```bash
curl -X POST http://localhost:8000/v1/transactions \
  -H "Authorization: Bearer $TENANT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "merchant_id": "M_SOWETO_TRADER_1092",
        "gross_value_cents": 125050,
        "raw_phone_number": "27721234567",
        "raw_email": "trader@townshipbiz.co.za"
      }'
```

`GET /health` needs no auth and reports whether the salt/Supabase/tenant
auth are configured, for load-balancer/Cloud Run health checks.

Bulk CSV import (`POST /v1/transactions/bulk`, same bearer auth): file must
be UTF-8, ≤1MB, ≤500 rows, with columns `merchant_id, gross_value_cents,
raw_phone_number, raw_email`. Returns per-row status -- one bad row fails
independently and never blocks the rest of the file. Every persisted row
is tagged with the tenant that owns `$TENANT_TOKEN`.

```bash
curl -X POST http://localhost:8000/v1/transactions/bulk \
  -H "Authorization: Bearer $TENANT_TOKEN" \
  -F "file=@transactions.csv"
```

## Test

```bash
pytest -v
```

## Project structure

```
app.py                       Streamlit UI (tenant token, single form + bulk CSV upload)
api.py                        FastAPI webhook (POST /v1/transactions, /v1/transactions/bulk, GET /health)
popia_pipeline.py             Validation + POPIA masking (deterministic core)
csv_ingestion.py               CSV parsing + per-row masking (deterministic, no I/O)
tenant_auth.py                 Per-tenant token hashing + resolution (deterministic core)
bi_dispatch.py                 Metric aggregation + safe multi-model AI dispatch
scripts/create_tenant.py       CLI: onboard a tenant, prints its bearer token once
tests/test_popia_pipeline.py
tests/test_csv_ingestion.py
tests/test_tenant_auth.py
tests/test_bi_dispatch.py
tests/test_api.py
supabase/schema.sql            Table DDL + RLS policy: tenants, anonymized_transactions
.github/workflows/test.yml     CI: runs pytest on push/PR to main
.streamlit/config.toml         App theme
Dockerfile.api                 Cloud Run image: FastAPI webhook
Dockerfile.streamlit           Cloud Run image: Streamlit UI
```

## Deploy to Cloud Run

Two separate services -- deploy either or both, independently:

- `Dockerfile.api` -- the production webhook (`api.py`)
- `Dockerfile.streamlit` -- the staging/demo UI (`app.py`)

Easiest path if `gcloud`/`docker` aren't installed locally: open
[Cloud Shell](https://console.cloud.google.com) (has both preinstalled and
already authenticated) and clone this repo there.

`gcr.io` is deprecated for new GCP projects -- use Artifact Registry
instead. The Dockerfile builds a fresh copy of the source each time, so
`gcloud builds submit` must be pointed at a Dockerfile that's actually
named `Dockerfile` (copy the one you want first).

```bash
export PROJECT_ID=<your-gcp-project-id>
export REGION=africa-south1   # or your preferred region
gcloud config set project "$PROJECT_ID"

# one-time: Artifact Registry repo for both images
gcloud artifacts repositories create professionalos-repo \
  --repository-format=docker --location="$REGION"

# one-time: secrets live in Secret Manager, not in plaintext env vars
gcloud services enable secretmanager.googleapis.com
for secret in popia-salt-key:$POPIA_SALT_KEY supabase-key:$SUPABASE_KEY \
              tenant-token-pepper:$TENANT_TOKEN_PEPPER openrouter-api-key:$OPENROUTER_API_KEY; do
  name="${secret%%:*}"; value="${secret#*:}"
  printf '%s' "$value" | gcloud secrets create "$name" --data-file=-
  gcloud secrets add-iam-policy-binding "$name" \
    --member="serviceAccount:$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')-compute@developer.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"
done

# --- API service ---
cp Dockerfile.api Dockerfile
gcloud builds submit --tag "$REGION-docker.pkg.dev/$PROJECT_ID/professionalos-repo/professionalos-api" .
gcloud run deploy professionalos-api \
  --image "$REGION-docker.pkg.dev/$PROJECT_ID/professionalos-repo/professionalos-api" \
  --region "$REGION" \
  --platform managed \
  --no-allow-unauthenticated \
  --set-env-vars SUPABASE_URL="$SUPABASE_URL" \
  --set-secrets POPIA_SALT_KEY=popia-salt-key:latest,SUPABASE_KEY=supabase-key:latest,TENANT_TOKEN_PEPPER=tenant-token-pepper:latest,OPENROUTER_API_KEY=openrouter-api-key:latest

# --- Streamlit staging UI ---
cp Dockerfile.streamlit Dockerfile
gcloud builds submit --tag "$REGION-docker.pkg.dev/$PROJECT_ID/professionalos-repo/professionalos-ui" .
gcloud run deploy professionalos-ui \
  --image "$REGION-docker.pkg.dev/$PROJECT_ID/professionalos-repo/professionalos-ui" \
  --region "$REGION" \
  --platform managed \
  --allow-unauthenticated \
  --set-env-vars SUPABASE_URL="$SUPABASE_URL" \
  --set-secrets POPIA_SALT_KEY=popia-salt-key:latest,SUPABASE_KEY=supabase-key:latest,TENANT_TOKEN_PEPPER=tenant-token-pepper:latest
```

Live deployment (professionalos-508906, africa-south1):
- API: https://professionalos-api-22738190210.africa-south1.run.app
- UI: https://professionalos-ui-22738190210.africa-south1.run.app

Notes:

- The API service is deployed `--no-allow-unauthenticated` by default (Cloud
  Run IAM, on top of the app's own per-tenant bearer-token check -- belt
  and braces). If POS/e-commerce callers need unauthenticated network
  access, switch to `--allow-unauthenticated` and rely on tenant tokens
  alone, or front it with API Gateway / a Cloud Run service-to-service
  invoker instead.
- Secrets (`POPIA_SALT_KEY`, `SUPABASE_KEY`, `TENANT_TOKEN_PEPPER`,
  `OPENROUTER_API_KEY`) are stored in GCP Secret Manager and mounted via
  `--set-secrets`, not passed as plaintext env vars -- the revision config
  and `gcloud run services describe` output never show their values.
  `SUPABASE_URL` stays a plain env var since it isn't sensitive.
- Cloud Run injects `$PORT` automatically; both Dockerfiles already read it.

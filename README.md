# ProfessionalOS — Secure Transaction, API & BI Gateway (POC)

The POPIA-compliant data-privacy and transaction-ingestion engine for
Orynexa Technologies' ProfessionalOS / BusinessOS platform
(township-business digitisation, funded via Tia Funding). Four pillars:

1. **POPIA anonymisation firewall** — intercepts raw phone numbers, emails
   and merchant identifiers at intake and irreversibly masks them with a
   salted SHA-256 HMAC before anything is stored or displayed
   (`popia_pipeline.py`).
2. **Sanitised persistence** — writes only the masked payload (never raw
   values) to Supabase for audit/ledger reporting.
3. **Safe AI intelligence dispatch** — routes *already-anonymised*,
   deterministically-computed merchant metrics to an OpenRouter multi-model
   pipeline (Gemini Flash primary, Claude Haiku fallback) for a
   plain-language business-insight summary. The LLM never sees raw data
   and never computes a number itself — it only writes prose over figures
   Python has already calculated (`bi_dispatch.py`).
4. **Production webhook (REST API)** — `POST /v1/transactions` exposes the
   exact same masking core over HTTP, bearer-token authenticated, for
   external POS/e-commerce frontends to submit raw payloads directly
   (`api.py`). The Streamlit app (`app.py`) is the human-facing surface
   over the same pipeline; the API is the machine-facing one.

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
- **Fail closed** — the API refuses all traffic with a 503 if
  `API_WEBHOOK_TOKEN` isn't configured, rather than silently allowing
  unauthenticated writes.
- **Test-driven** — 39 pytest cases across `tests/test_popia_pipeline.py`,
  `tests/test_bi_dispatch.py` and `tests/test_api.py` cover valid input,
  every validation failure mode, hash determinism, salt handling,
  PII-leak detection, multi-model fallback, and the full API auth/error
  surface (mocked HTTP throughout, no live network calls in CI).

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
API_WEBHOOK_TOKEN=<a random shared secret for API callers>
```

Every integration is optional and degrades gracefully if unset: Supabase
persistence is skipped (`persisted: false`), the AI insights panel is
disabled, and the API refuses all traffic (503) — but the core masking
pipeline always works.

Provision the database table (once) with `supabase/schema.sql`, e.g. via the
Supabase SQL editor or `supabase db push`. It includes the RLS policy that
allows the anon key to *insert* masked rows without granting read access.

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

Example call:

```bash
curl -X POST http://localhost:8000/v1/transactions \
  -H "Authorization: Bearer $API_WEBHOOK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "merchant_id": "M_SOWETO_TRADER_1092",
        "gross_value_cents": 125050,
        "raw_phone_number": "27721234567",
        "raw_email": "trader@townshipbiz.co.za"
      }'
```

`GET /health` needs no auth and reports whether the salt/Supabase are
configured, for load-balancer/Cloud Run health checks.

## Test

```bash
pytest -v
```

## Project structure

```
app.py                       Streamlit UI
api.py                        FastAPI webhook (POST /v1/transactions, GET /health)
popia_pipeline.py             Validation + POPIA masking (deterministic core)
bi_dispatch.py                 Metric aggregation + safe multi-model AI dispatch
tests/test_popia_pipeline.py
tests/test_bi_dispatch.py
tests/test_api.py
supabase/schema.sql            Table DDL + RLS policy for anonymized_transactions
.github/workflows/test.yml     CI: runs pytest on push/PR to main
.streamlit/config.toml         App theme
```

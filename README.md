# ProfessionalOS — Secure Transaction & BI Gateway (POC)

A Streamlit proof-of-concept: the POPIA-compliant data-privacy and
transaction-ingestion engine for Orynexa Technologies' ProfessionalOS /
BusinessOS platform (township-business digitisation, funded via Tia
Funding). Three pillars:

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

## Design principles (per project rules)

- **Strict Pydantic validation** — every payload (raw intake and the
  re-validated masked records at the AI-dispatch boundary) is checked
  against exact types/patterns; anything malformed is rejected outright.
- **Deterministic core logic** — all masking, hashing, currency math and
  metric aggregation is hard-coded Python. LLMs are restricted to
  generating narrative text over numbers they're handed.
- **Zero plaintext leakage** — raw phone/email/merchant values never reach
  the response, the UI, the database, or the AI pipeline; only
  `ANON_...` HMAC digests and aggregate totals do.
  `bi_dispatch.assert_no_pii_leak()` is a second, independent
  defence-in-depth scan of every payload right before it leaves the
  system, on top of the Pydantic validation.
- **Test-driven** — 27 pytest cases across `tests/test_popia_pipeline.py`
  and `tests/test_bi_dispatch.py` cover valid input, every validation
  failure mode, hash determinism, salt handling, PII-leak detection, and
  the multi-model fallback behaviour (mocked HTTP, no live calls in CI).

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
```

Every integration is optional and degrades gracefully with a warning if
unset: Supabase persistence is skipped, and the AI insights panel is
disabled, but the core masking pipeline always works.

Provision the database table (once) with `supabase/schema.sql`, e.g. via the
Supabase SQL editor or `supabase db push`. It includes the RLS policy that
allows the anon key to *insert* masked rows without granting read access.

Model choice for AI dispatch is configurable without a code change:
`OPENROUTER_PRIMARY_MODEL` and `OPENROUTER_FALLBACK_MODEL` env vars
override the defaults (`google/gemini-2.0-flash-001` /
`anthropic/claude-3.5-haiku`).

## Run

```bash
streamlit run app.py
```

## Test

```bash
pytest -v
```

## Project structure

```
app.py                       Streamlit UI
popia_pipeline.py            Validation + POPIA masking (deterministic core)
bi_dispatch.py                Metric aggregation + safe multi-model AI dispatch
tests/test_popia_pipeline.py
tests/test_bi_dispatch.py
supabase/schema.sql           Table DDL + RLS policy for anonymized_transactions
.github/workflows/test.yml    CI: runs pytest on push/PR to main
.streamlit/config.toml        App theme

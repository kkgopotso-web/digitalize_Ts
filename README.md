# ProfessionalOS — Secure Transaction Gateway (POC)

A Streamlit proof-of-concept for Orynexa Technologies' ProfessionalOS: a
POPIA-compliant intake pipeline that validates merchant transaction data with
strict Pydantic models, then irreversibly hashes every sensitive field
(phone, email, merchant ID) with a salted SHA-256 HMAC before anything is
persisted or displayed.

## Design principles (per project rules)

- **Strict Pydantic validation** — `SecureTransactionPayload` rejects any
  payload that doesn't match the exact types/format (see `popia_pipeline.py`).
- **Deterministic core logic** — all masking, hashing and currency math is
  hard-coded Python; no LLM is involved in this pipeline.
- **Zero plaintext leakage** — raw phone/email/merchant values never reach
  the response, the UI, or the database; only `ANON_...` HMAC digests do.
- **Test-driven** — `tests/test_popia_pipeline.py` covers valid input,
  every validation failure mode, hash determinism and salt handling.

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
SUPABASE_KEY=<your Supabase anon/service key>
```

If Supabase credentials are omitted, the app still runs and the masking
pipeline still works — persistence is simply skipped with a warning.

Provision the database table (once) with `supabase/schema.sql`, e.g. via the
Supabase SQL editor or `supabase db push`.

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
app.py                      Streamlit UI
popia_pipeline.py           Validation + POPIA masking (deterministic core)
tests/test_popia_pipeline.py
supabase/schema.sql          Table DDL for anonymized_transactions
.github/workflows/test.yml   CI: runs pytest on push/PR to main
.streamlit/config.toml       App theme
```

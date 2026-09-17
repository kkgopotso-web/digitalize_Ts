"""Safe AI Intelligence Dispatch.

Routes ALREADY-ANONYMISED merchant metrics (never raw PII) to an
OpenRouter multi-model pipeline (Gemini Flash primary, Claude Haiku
fallback) for a narrative business-intelligence summary.

Design rules (per project constraints):
- All math/aggregation is deterministic, hard-coded Python. The LLM is
  used exclusively for unstructured text generation over numbers it is
  handed -- it never computes totals, averages, or anything financial.
- Every record entering this module is re-validated with strict Pydantic
  models. A raw phone number or email masquerading as a "masked" value
  fails the ANON_ hash pattern and is rejected before it can travel
  anywhere near an external API.
- assert_no_pii_leak() is a defence-in-depth scan of the exact payload
  about to be sent externally, independent of the Pydantic validation
  above, so a future field added to the metrics model can't silently
  leak PII through this pipeline.
"""
import os
import re
import logging
from typing import Optional

import requests
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger("ProfessionalOS.AIDispatch")

MASKED_VALUE_PATTERN = re.compile(r"^ANON_[a-f0-9]{32}$")

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_PRIMARY_MODEL = os.getenv("OPENROUTER_PRIMARY_MODEL", "google/gemini-2.0-flash-001")
DEFAULT_FALLBACK_MODEL = os.getenv("OPENROUTER_FALLBACK_MODEL", "anthropic/claude-3.5-haiku")
REQUEST_TIMEOUT_SECONDS = 20


class PIILeakError(Exception):
    """Raised when a payload about to leave the system contains apparent PII."""


class AnonymizedTransactionRecord(BaseModel):
    """A single masked transaction, re-validated at the BI-dispatch boundary.

    This is deliberately a *second*, independent validation pass on top of
    popia_pipeline.process_and_mask_transaction's output -- defence in
    depth, not trust in the caller.
    """

    merchant_hash: str = Field(..., pattern=MASKED_VALUE_PATTERN.pattern)
    transaction_value_zar: float = Field(..., gt=0)
    masked_contact_phone: str = Field(..., pattern=MASKED_VALUE_PATTERN.pattern)
    masked_contact_email: str = Field(..., pattern=MASKED_VALUE_PATTERN.pattern)
    compliance_status: str


class MerchantMetricsSummary(BaseModel):
    """Deterministically-computed aggregate handed to the LLM as-is."""

    merchant_hash: str
    transaction_count: int = Field(..., gt=0)
    total_value_zar: float
    average_value_zar: float
    min_value_zar: float
    max_value_zar: float


def compute_merchant_metrics(records: list[dict]) -> MerchantMetricsSummary:
    """Pure, deterministic aggregation over already-masked records.

    No LLM involvement whatsoever -- this is the hard-coded core logic
    the project rules require for anything financial.
    """
    if not records:
        raise ValueError("Cannot compute metrics for an empty record set.")

    validated = [AnonymizedTransactionRecord(**r) for r in records]

    merchant_hashes = {r.merchant_hash for r in validated}
    if len(merchant_hashes) > 1:
        raise ValueError(
            "compute_merchant_metrics expects records for a single merchant_hash; "
            f"got {len(merchant_hashes)} distinct merchants."
        )

    values = [r.transaction_value_zar for r in validated]
    return MerchantMetricsSummary(
        merchant_hash=validated[0].merchant_hash,
        transaction_count=len(validated),
        total_value_zar=round(sum(values), 2),
        average_value_zar=round(sum(values) / len(values), 2),
        min_value_zar=round(min(values), 2),
        max_value_zar=round(max(values), 2),
    )


def assert_no_pii_leak(payload: dict) -> None:
    """Defence-in-depth scan of an outbound payload for apparent PII.

    Independent of Pydantic validation: this looks at the literal
    strings about to be sent externally, so it still catches a leak
    introduced by a future field or a careless caller.
    """
    email_pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    za_phone_pattern = re.compile(r"(\+?27|0)[6-8][0-9]{8}\b")

    for key, value in payload.items():
        text = str(value)
        if email_pattern.search(text):
            raise PIILeakError(f"Potential email address detected in field '{key}'.")
        if za_phone_pattern.search(text):
            raise PIILeakError(f"Potential phone number detected in field '{key}'.")


def build_bi_prompt(metrics: MerchantMetricsSummary) -> list[dict]:
    """Declarative, role-based prompt. The model receives numbers only
    and is explicitly forbidden from inventing or recomputing any.
    """
    payload = metrics.model_dump()
    assert_no_pii_leak(payload)

    system_prompt = (
        "You are a business-intelligence analyst for ProfessionalOS, a South "
        "African township-business platform. You will be given a small set of "
        "pre-computed, already-anonymised transaction metrics for one merchant. "
        "Rules: (1) Do not invent, estimate, or recompute any numeric value -- "
        "use only the figures given. (2) Do not ask for or reference any "
        "personally identifiable information; you have none and must not imply "
        "otherwise. (3) Output 2-3 concise sentences of plain-language business "
        "insight (e.g. spend trend, ticket size), suitable for a non-technical "
        "trader. (4) Do not output JSON, markdown, or repeat the raw numbers "
        "verbatim as a list -- write prose."
    )

    user_prompt = (
        "Merchant metrics (ZAR, this period):\n"
        f"- transaction_count: {payload['transaction_count']}\n"
        f"- total_value_zar: {payload['total_value_zar']}\n"
        f"- average_value_zar: {payload['average_value_zar']}\n"
        f"- min_value_zar: {payload['min_value_zar']}\n"
        f"- max_value_zar: {payload['max_value_zar']}\n\n"
        "Write the business insight now."
    )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


def _call_openrouter(model: str, messages: list[dict], api_key: str) -> str:
    response = requests.post(
        OPENROUTER_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={"model": model, "messages": messages, "temperature": 0.3},
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    if response.status_code >= 400:
        raise RuntimeError(f"OpenRouter request failed ({response.status_code}) for model '{model}'.")
    data = response.json()
    return data["choices"][0]["message"]["content"].strip()


def dispatch_bi_summary(
    metrics: MerchantMetricsSummary,
    api_key: Optional[str] = None,
    primary_model: str = DEFAULT_PRIMARY_MODEL,
    fallback_model: str = DEFAULT_FALLBACK_MODEL,
) -> dict:
    """Multi-model dispatch: try the primary model, fall back once.

    Raises RuntimeError only if every model in the pipeline fails, so a
    caller can degrade gracefully (mirrors how Supabase persistence is
    optional elsewhere in this app).
    """
    key = api_key if api_key is not None else os.getenv("OPENROUTER_API_KEY", "")
    if not key:
        raise ValueError("OPENROUTER_API_KEY is missing -- cannot dispatch to OpenRouter.")

    messages = build_bi_prompt(metrics)

    last_error: Optional[Exception] = None
    for model in (primary_model, fallback_model):
        try:
            summary = _call_openrouter(model, messages, key)
            logger.info("AI BI summary generated via model=%s", model)
            return {"summary": summary, "model_used": model, "metrics": metrics.model_dump()}
        except Exception as exc:  # noqa: BLE001 -- deliberately broad: try next model
            logger.warning("Model '%s' failed in BI dispatch pipeline: %s", model, exc)
            last_error = exc

    raise RuntimeError(f"All models in the BI dispatch pipeline failed. Last error: {last_error}")

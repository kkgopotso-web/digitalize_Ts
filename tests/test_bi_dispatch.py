import pytest
from pydantic import ValidationError

from bi_dispatch import (
    AnonymizedTransactionRecord,
    compute_merchant_metrics,
    build_bi_prompt,
    assert_no_pii_leak,
    dispatch_bi_summary,
    PIILeakError,
)

MASKED_A = "ANON_" + "a" * 32
MASKED_B = "ANON_" + "b" * 32
MASKED_C = "ANON_" + "c" * 32

VALID_RECORDS = [
    {
        "merchant_hash": MASKED_A,
        "transaction_value_zar": 100.0,
        "masked_contact_phone": MASKED_B,
        "masked_contact_email": MASKED_C,
        "compliance_status": "COMPLIANT_ANONYMISED",
    },
    {
        "merchant_hash": MASKED_A,
        "transaction_value_zar": 300.0,
        "masked_contact_phone": MASKED_B,
        "masked_contact_email": MASKED_C,
        "compliance_status": "COMPLIANT_ANONYMISED",
    },
    {
        "merchant_hash": MASKED_A,
        "transaction_value_zar": 50.0,
        "masked_contact_phone": MASKED_B,
        "masked_contact_email": MASKED_C,
        "compliance_status": "COMPLIANT_ANONYMISED",
    },
]


# ---------- record validation ----------

def test_record_accepts_properly_masked_values():
    record = AnonymizedTransactionRecord(**VALID_RECORDS[0])
    assert record.merchant_hash == MASKED_A


def test_record_rejects_raw_email_disguised_as_masked():
    bad = {**VALID_RECORDS[0], "masked_contact_email": "trader@townshipbiz.co.za"}
    with pytest.raises(ValidationError):
        AnonymizedTransactionRecord(**bad)


def test_record_rejects_raw_phone_disguised_as_masked():
    bad = {**VALID_RECORDS[0], "masked_contact_phone": "27721234567"}
    with pytest.raises(ValidationError):
        AnonymizedTransactionRecord(**bad)


def test_record_rejects_non_positive_value():
    bad = {**VALID_RECORDS[0], "transaction_value_zar": 0}
    with pytest.raises(ValidationError):
        AnonymizedTransactionRecord(**bad)


# ---------- deterministic aggregation ----------

def test_compute_merchant_metrics_aggregates_correctly():
    metrics = compute_merchant_metrics(VALID_RECORDS)
    assert metrics.merchant_hash == MASKED_A
    assert metrics.transaction_count == 3
    assert metrics.total_value_zar == 450.0
    assert metrics.average_value_zar == 150.0
    assert metrics.min_value_zar == 50.0
    assert metrics.max_value_zar == 300.0


def test_compute_merchant_metrics_rejects_mixed_merchants():
    mixed = VALID_RECORDS + [{**VALID_RECORDS[0], "merchant_hash": MASKED_B}]
    with pytest.raises(ValueError):
        compute_merchant_metrics(mixed)


def test_compute_merchant_metrics_rejects_empty_input():
    with pytest.raises(ValueError):
        compute_merchant_metrics([])


# ---------- PII leak guard ----------

def test_assert_no_pii_leak_passes_clean_payload():
    assert_no_pii_leak({"total_value_zar": 450.0, "transaction_count": 3})


def test_assert_no_pii_leak_catches_email():
    with pytest.raises(PIILeakError):
        assert_no_pii_leak({"note": "contact trader@townshipbiz.co.za"})


def test_assert_no_pii_leak_catches_phone_number():
    with pytest.raises(PIILeakError):
        assert_no_pii_leak({"note": "call 0721234567 for support"})


# ---------- prompt construction ----------

def test_build_bi_prompt_contains_only_numeric_metrics_and_no_pii():
    metrics = compute_merchant_metrics(VALID_RECORDS)
    messages = build_bi_prompt(metrics)
    assert messages[0]["role"] == "system"
    assert messages[1]["role"] == "user"
    user_content = messages[1]["content"]
    assert "450.0" in user_content or "450" in user_content
    assert MASKED_B not in user_content  # phone hash has no business summarising value
    assert "do not" in messages[0]["content"].lower()


# ---------- dispatch with mocked HTTP ----------

class _FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def _fake_choice(text):
    return {"choices": [{"message": {"content": text}}]}


def test_dispatch_bi_summary_uses_primary_model(monkeypatch):
    metrics = compute_merchant_metrics(VALID_RECORDS)
    calls = []

    def fake_post(url, headers, json, timeout):
        calls.append(json["model"])
        return _FakeResponse(200, _fake_choice("Steady growth this period."))

    monkeypatch.setattr("bi_dispatch.requests.post", fake_post)
    result = dispatch_bi_summary(metrics, api_key="test-key")

    assert result["summary"] == "Steady growth this period."
    assert result["model_used"] == calls[0]
    assert len(calls) == 1


def test_dispatch_bi_summary_falls_back_on_primary_failure(monkeypatch):
    metrics = compute_merchant_metrics(VALID_RECORDS)
    calls = []

    def fake_post(url, headers, json, timeout):
        calls.append(json["model"])
        if len(calls) == 1:
            return _FakeResponse(500, {})
        return _FakeResponse(200, _fake_choice("Fallback summary."))

    monkeypatch.setattr("bi_dispatch.requests.post", fake_post)
    result = dispatch_bi_summary(metrics, api_key="test-key")

    assert result["summary"] == "Fallback summary."
    assert len(calls) == 2
    assert result["model_used"] == calls[1]


def test_dispatch_bi_summary_raises_when_all_models_fail(monkeypatch):
    metrics = compute_merchant_metrics(VALID_RECORDS)

    def fake_post(url, headers, json, timeout):
        return _FakeResponse(500, {})

    monkeypatch.setattr("bi_dispatch.requests.post", fake_post)
    with pytest.raises(RuntimeError):
        dispatch_bi_summary(metrics, api_key="test-key")


def test_dispatch_bi_summary_requires_api_key():
    metrics = compute_merchant_metrics(VALID_RECORDS)
    with pytest.raises(ValueError):
        dispatch_bi_summary(metrics, api_key="")

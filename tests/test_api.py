import pytest
from fastapi.testclient import TestClient

from api import app, MAX_BODY_BYTES

client = TestClient(app)

SALT = "ZA_TEST_SECRET_SALT_KEY_2026_SECURE"
TOKEN = "test-webhook-token-abc123"

VALID_PAYLOAD = {
    "merchant_id": "M_SOWETO_TRADER_1092",
    "gross_value_cents": 125050,
    "raw_phone_number": "27721234567",
    "raw_email": "trader@townshipbiz.co.za",
}


@pytest.fixture(autouse=True)
def _base_env(monkeypatch):
    """Every test gets a working salt + auth token unless it overrides them."""
    monkeypatch.setenv("POPIA_SALT_KEY", SALT)
    monkeypatch.setenv("API_WEBHOOK_TOKEN", TOKEN)
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_KEY", raising=False)


def auth_headers(token=TOKEN):
    return {"Authorization": f"Bearer {token}"}


# ---------- health ----------

def test_health_does_not_require_auth():
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["salt_configured"] is True
    assert body["supabase_configured"] is False


# ---------- auth ----------

def test_transactions_rejects_missing_auth_header():
    resp = client.post("/v1/transactions", json=VALID_PAYLOAD)
    assert resp.status_code == 401


def test_transactions_rejects_wrong_token():
    resp = client.post("/v1/transactions", json=VALID_PAYLOAD, headers=auth_headers("wrong-token"))
    assert resp.status_code == 401


def test_transactions_fails_closed_when_token_not_configured(monkeypatch):
    monkeypatch.delenv("API_WEBHOOK_TOKEN", raising=False)
    resp = client.post("/v1/transactions", json=VALID_PAYLOAD, headers=auth_headers())
    assert resp.status_code == 503


# ---------- happy path ----------

def test_transactions_processes_valid_payload():
    resp = client.post("/v1/transactions", json=VALID_PAYLOAD, headers=auth_headers())
    assert resp.status_code == 200
    body = resp.json()
    assert body["compliance_status"] == "COMPLIANT_ANONYMISED"
    assert body["transaction_value_zar"] == 1250.50
    assert body["merchant_hash"].startswith("ANON_")
    assert body["masked_contact_phone"].startswith("ANON_")
    assert body["masked_contact_email"].startswith("ANON_")
    assert body["persisted"] is False  # no Supabase configured in this test env


def test_transactions_never_echoes_raw_input():
    resp = client.post("/v1/transactions", json=VALID_PAYLOAD, headers=auth_headers())
    serialized = resp.text
    assert VALID_PAYLOAD["raw_phone_number"] not in serialized
    assert VALID_PAYLOAD["raw_email"] not in serialized
    assert VALID_PAYLOAD["merchant_id"] not in serialized


# ---------- validation ----------

def test_transactions_rejects_invalid_phone():
    bad = {**VALID_PAYLOAD, "raw_phone_number": "0821234567"}
    resp = client.post("/v1/transactions", json=bad, headers=auth_headers())
    assert resp.status_code == 422


def test_transactions_rejects_invalid_email():
    bad = {**VALID_PAYLOAD, "raw_email": "not-an-email"}
    resp = client.post("/v1/transactions", json=bad, headers=auth_headers())
    assert resp.status_code == 422


def test_transactions_rejects_zero_value():
    bad = {**VALID_PAYLOAD, "gross_value_cents": 0}
    resp = client.post("/v1/transactions", json=bad, headers=auth_headers())
    assert resp.status_code == 422


def test_transactions_rejects_missing_field():
    bad = {k: v for k, v in VALID_PAYLOAD.items() if k != "raw_email"}
    resp = client.post("/v1/transactions", json=bad, headers=auth_headers())
    assert resp.status_code == 422


# ---------- salt misconfiguration ----------

def test_transactions_returns_500_when_salt_missing(monkeypatch):
    monkeypatch.delenv("POPIA_SALT_KEY", raising=False)
    resp = client.post("/v1/transactions", json=VALID_PAYLOAD, headers=auth_headers())
    assert resp.status_code == 500


# ---------- body size guard ----------

def test_transactions_rejects_oversized_body():
    oversized_payload = {**VALID_PAYLOAD, "raw_email": "a" * (MAX_BODY_BYTES + 500) + "@townshipbiz.co.za"}
    resp = client.post("/v1/transactions", json=oversized_payload, headers=auth_headers())
    assert resp.status_code == 413

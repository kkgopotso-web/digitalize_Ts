import pytest
from fastapi.testclient import TestClient

from api import app, MAX_BODY_BYTES, MAX_CSV_BODY_BYTES
import api as api_module
from tenant_auth import hash_tenant_token

client = TestClient(app)

SALT = "ZA_TEST_SECRET_SALT_KEY_2026_SECURE"
PEPPER = "ZA_TEST_TENANT_PEPPER_2026_SECURE"
TOKEN = "tnt_test_soweto_traders_abc123"
TENANT_ID = "tenant-uuid-test-1"

VALID_PAYLOAD = {
    "merchant_id": "M_SOWETO_TRADER_1092",
    "gross_value_cents": 125050,
    "raw_phone_number": "27721234567",
    "raw_email": "trader@townshipbiz.co.za",
}


def _default_lookup(token_hash):
    """Resolves TOKEN (hashed with PEPPER) to a single active test tenant;
    anything else is an unknown token."""
    if token_hash == hash_tenant_token(TOKEN, PEPPER):
        return {"id": TENANT_ID, "is_active": True}
    return None


@pytest.fixture(autouse=True)
def _base_env(monkeypatch):
    """Every test gets a working salt + tenant auth (Supabase "configured",
    TOKEN resolves to an active tenant) unless it overrides them. The real
    Supabase client is stubbed to None by default so persistence never
    hits the network -- tests that care about persistence override
    api_module._get_supabase_client explicitly."""
    monkeypatch.setenv("POPIA_SALT_KEY", SALT)
    monkeypatch.setenv("TENANT_TOKEN_PEPPER", PEPPER)
    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "fake-key")
    monkeypatch.setattr(api_module, "_lookup_tenant_by_hash", _default_lookup)
    monkeypatch.setattr(api_module, "_get_supabase_client", lambda: None)


def auth_headers(token=TOKEN):
    return {"Authorization": f"Bearer {token}"}


# ---------- health ----------

def test_health_does_not_require_auth():
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["salt_configured"] is True
    assert body["supabase_configured"] is True
    assert body["tenant_auth_configured"] is True


def test_health_reports_not_configured_without_supabase(monkeypatch):
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_KEY", raising=False)
    resp = client.get("/health")
    body = resp.json()
    assert body["supabase_configured"] is False
    assert body["tenant_auth_configured"] is False


def test_health_reports_not_configured_without_pepper(monkeypatch):
    monkeypatch.delenv("TENANT_TOKEN_PEPPER", raising=False)
    resp = client.get("/health")
    body = resp.json()
    assert body["tenant_auth_configured"] is False


# ---------- tenant auth ----------

def test_transactions_rejects_missing_auth_header():
    resp = client.post("/v1/transactions", json=VALID_PAYLOAD)
    assert resp.status_code == 401


def test_transactions_rejects_unknown_token():
    resp = client.post("/v1/transactions", json=VALID_PAYLOAD, headers=auth_headers("tnt_totally_unknown"))
    assert resp.status_code == 401


def test_transactions_rejects_inactive_tenant(monkeypatch):
    monkeypatch.setattr(
        api_module,
        "_lookup_tenant_by_hash",
        lambda token_hash: {"id": TENANT_ID, "is_active": False},
    )
    resp = client.post("/v1/transactions", json=VALID_PAYLOAD, headers=auth_headers())
    assert resp.status_code == 401


def test_transactions_fails_closed_without_supabase(monkeypatch):
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_KEY", raising=False)
    resp = client.post("/v1/transactions", json=VALID_PAYLOAD, headers=auth_headers())
    assert resp.status_code == 503


def test_transactions_fails_closed_without_pepper(monkeypatch):
    monkeypatch.delenv("TENANT_TOKEN_PEPPER", raising=False)
    resp = client.post("/v1/transactions", json=VALID_PAYLOAD, headers=auth_headers())
    assert resp.status_code == 503


def test_transactions_unknown_and_inactive_tokens_give_same_error_body(monkeypatch):
    resp_unknown = client.post("/v1/transactions", json=VALID_PAYLOAD, headers=auth_headers("tnt_unknown"))
    monkeypatch.setattr(
        api_module,
        "_lookup_tenant_by_hash",
        lambda token_hash: {"id": TENANT_ID, "is_active": False},
    )
    resp_inactive = client.post("/v1/transactions", json=VALID_PAYLOAD, headers=auth_headers())
    assert resp_unknown.json()["detail"] == resp_inactive.json()["detail"]


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
    assert body["tenant_id"] == TENANT_ID
    assert body["persisted"] is False  # _get_supabase_client stubbed to None


def test_transactions_never_echoes_raw_input():
    resp = client.post("/v1/transactions", json=VALID_PAYLOAD, headers=auth_headers())
    serialized = resp.text
    assert VALID_PAYLOAD["raw_phone_number"] not in serialized
    assert VALID_PAYLOAD["raw_email"] not in serialized
    assert VALID_PAYLOAD["merchant_id"] not in serialized


def test_transactions_persists_with_tenant_id_when_supabase_configured(monkeypatch):
    inserted = []

    class _FakeTable:
        def insert(self, data):
            inserted.append(data)
            return self

        def execute(self):
            return None

    class _FakeClient:
        def table(self, name):
            assert name == "anonymized_transactions"
            return _FakeTable()

    monkeypatch.setattr(api_module, "_get_supabase_client", lambda: _FakeClient())

    resp = client.post("/v1/transactions", json=VALID_PAYLOAD, headers=auth_headers())
    assert resp.status_code == 200
    assert resp.json()["persisted"] is True
    assert len(inserted) == 1
    assert inserted[0]["tenant_id"] == TENANT_ID


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


# ---------- bulk CSV ingestion ----------

BULK_HEADER = "merchant_id,gross_value_cents,raw_phone_number,raw_email"
BULK_VALID_ROW_1 = "M_SOWETO_TRADER_1092,125050,27721234567,trader@townshipbiz.co.za"
BULK_VALID_ROW_2 = "M_ALEX_SPAZA_SHOP_02,50000,27831234567,spaza@alexbiz.co.za"
BULK_BAD_ROW = "M_BAD,not-a-number,27721234567,trader@townshipbiz.co.za"


def _csv_file(*rows, filename="transactions.csv"):
    content = "\n".join([BULK_HEADER, *rows])
    return {"file": (filename, content, "text/csv")}


def test_bulk_rejects_missing_auth_header():
    resp = client.post("/v1/transactions/bulk", files=_csv_file(BULK_VALID_ROW_1))
    assert resp.status_code == 401


def test_bulk_fails_closed_without_pepper(monkeypatch):
    monkeypatch.delenv("TENANT_TOKEN_PEPPER", raising=False)
    resp = client.post("/v1/transactions/bulk", files=_csv_file(BULK_VALID_ROW_1), headers=auth_headers())
    assert resp.status_code == 503


def test_bulk_processes_all_valid_rows():
    resp = client.post(
        "/v1/transactions/bulk",
        files=_csv_file(BULK_VALID_ROW_1, BULK_VALID_ROW_2),
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["tenant_id"] == TENANT_ID
    assert body["total_rows"] == 2
    assert body["succeeded"] == 2
    assert body["failed"] == 0
    assert body["persisted_count"] == 0  # _get_supabase_client stubbed to None
    assert all(r["status"] == "success" for r in body["results"])
    assert all(r["persisted"] is False for r in body["results"])


def test_bulk_isolates_bad_rows_from_good_rows():
    resp = client.post(
        "/v1/transactions/bulk",
        files=_csv_file(BULK_VALID_ROW_1, BULK_BAD_ROW, BULK_VALID_ROW_2),
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_rows"] == 3
    assert body["succeeded"] == 2
    assert body["failed"] == 1
    assert body["results"][1]["status"] == "error"
    assert body["results"][1]["row_number"] == 2


def test_bulk_never_echoes_raw_input():
    resp = client.post(
        "/v1/transactions/bulk",
        files=_csv_file(BULK_VALID_ROW_1),
        headers=auth_headers(),
    )
    serialized = resp.text
    assert "27721234567" not in serialized
    assert "trader@townshipbiz.co.za" not in serialized
    assert "M_SOWETO_TRADER_1092" not in serialized


def test_bulk_rejects_structurally_invalid_csv():
    resp = client.post(
        "/v1/transactions/bulk",
        files={"file": ("bad.csv", "not,the,right,columns\n1,2,3,4", "text/csv")},
        headers=auth_headers(),
    )
    assert resp.status_code == 400


def test_bulk_rejects_empty_csv():
    resp = client.post(
        "/v1/transactions/bulk",
        files={"file": ("empty.csv", "", "text/csv")},
        headers=auth_headers(),
    )
    assert resp.status_code == 400


def test_bulk_returns_500_when_salt_missing(monkeypatch):
    monkeypatch.delenv("POPIA_SALT_KEY", raising=False)
    resp = client.post(
        "/v1/transactions/bulk",
        files=_csv_file(BULK_VALID_ROW_1),
        headers=auth_headers(),
    )
    assert resp.status_code == 500


def test_bulk_rejects_oversized_file():
    huge_row = f"M_X,100,27721234567,{'a' * (MAX_CSV_BODY_BYTES + 1000)}@x.co.za"
    resp = client.post(
        "/v1/transactions/bulk",
        files=_csv_file(huge_row),
        headers=auth_headers(),
    )
    assert resp.status_code == 413


def test_bulk_persists_successful_rows_with_tenant_id(monkeypatch):
    inserted = []

    class _FakeTable:
        def insert(self, data):
            inserted.append(data)
            return self

        def execute(self):
            return None

    class _FakeClient:
        def table(self, name):
            assert name == "anonymized_transactions"
            return _FakeTable()

    monkeypatch.setattr(api_module, "_get_supabase_client", lambda: _FakeClient())

    resp = client.post(
        "/v1/transactions/bulk",
        files=_csv_file(BULK_VALID_ROW_1, BULK_VALID_ROW_2),
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["persisted_count"] == 2
    assert all(r["persisted"] is True for r in body["results"])
    assert len(inserted) == 2
    assert all(row["tenant_id"] == TENANT_ID for row in inserted)

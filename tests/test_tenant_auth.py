import pytest

from tenant_auth import (
    Tenant,
    TenantAuthError,
    hash_tenant_token,
    get_tenant_token_pepper,
    resolve_tenant,
)

PEPPER = "ZA_TEST_TENANT_PEPPER_2026_SECURE"
TOKEN = "tnt_soweto_traders_abc123xyz"


def test_hash_tenant_token_is_deterministic():
    h1 = hash_tenant_token(TOKEN, PEPPER)
    h2 = hash_tenant_token(TOKEN, PEPPER)
    assert h1 == h2


def test_hash_tenant_token_differs_by_pepper():
    h1 = hash_tenant_token(TOKEN, PEPPER)
    h2 = hash_tenant_token(TOKEN, "ZA_TEST_TENANT_PEPPER_DIFFERENT!!")
    assert h1 != h2


def test_hash_tenant_token_differs_by_token():
    h1 = hash_tenant_token(TOKEN, PEPPER)
    h2 = hash_tenant_token("tnt_other_tenant_999", PEPPER)
    assert h1 != h2


def test_hash_tenant_token_is_hex_sha256_length():
    h = hash_tenant_token(TOKEN, PEPPER)
    assert len(h) == 64
    int(h, 16)  # raises if not valid hex


def test_hash_tenant_token_rejects_short_pepper():
    with pytest.raises(ValueError):
        hash_tenant_token(TOKEN, "short")


def test_get_tenant_token_pepper_reads_env(monkeypatch):
    monkeypatch.setenv("TENANT_TOKEN_PEPPER", PEPPER)
    assert get_tenant_token_pepper() == PEPPER


def test_get_tenant_token_pepper_rejects_missing(monkeypatch):
    monkeypatch.delenv("TENANT_TOKEN_PEPPER", raising=False)
    with pytest.raises(ValueError):
        get_tenant_token_pepper()


def test_get_tenant_token_pepper_rejects_short(monkeypatch):
    monkeypatch.setenv("TENANT_TOKEN_PEPPER", "short")
    with pytest.raises(ValueError):
        get_tenant_token_pepper()


# ---------- resolve_tenant ----------

def _lookup_factory(record):
    calls = []

    def lookup(token_hash):
        calls.append(token_hash)
        return record

    lookup.calls = calls
    return lookup


def test_resolve_tenant_success():
    expected_hash = hash_tenant_token(TOKEN, PEPPER)
    lookup = _lookup_factory({"id": "tenant-uuid-1", "is_active": True})
    tenant = resolve_tenant(TOKEN, PEPPER, lookup)
    assert isinstance(tenant, Tenant)
    assert tenant.id == "tenant-uuid-1"
    assert tenant.is_active is True
    assert lookup.calls == [expected_hash]


def test_resolve_tenant_rejects_unknown_token():
    lookup = _lookup_factory(None)
    with pytest.raises(TenantAuthError):
        resolve_tenant(TOKEN, PEPPER, lookup)


def test_resolve_tenant_rejects_inactive_tenant():
    lookup = _lookup_factory({"id": "tenant-uuid-1", "is_active": False})
    with pytest.raises(TenantAuthError):
        resolve_tenant(TOKEN, PEPPER, lookup)


def test_resolve_tenant_rejects_empty_token():
    lookup = _lookup_factory({"id": "tenant-uuid-1", "is_active": True})
    with pytest.raises(TenantAuthError):
        resolve_tenant("", PEPPER, lookup)
    assert lookup.calls == []  # never even queries for a blank token


def test_resolve_tenant_error_message_never_reveals_reason():
    lookup_unknown = _lookup_factory(None)
    lookup_inactive = _lookup_factory({"id": "x", "is_active": False})
    try:
        resolve_tenant(TOKEN, PEPPER, lookup_unknown)
    except TenantAuthError as e1:
        msg_unknown = str(e1)
    try:
        resolve_tenant(TOKEN, PEPPER, lookup_inactive)
    except TenantAuthError as e2:
        msg_inactive = str(e2)
    assert msg_unknown == msg_inactive  # same generic message either way


def test_resolve_tenant_never_leaks_token_or_hash_in_error():
    lookup = _lookup_factory(None)
    try:
        resolve_tenant(TOKEN, PEPPER, lookup)
    except TenantAuthError as e:
        assert TOKEN not in str(e)
        assert hash_tenant_token(TOKEN, PEPPER) not in str(e)


# ---------- tenant provisioning ----------

from tenant_auth import generate_tenant_token, build_tenant_record


def test_generate_tenant_token_has_expected_prefix():
    token = generate_tenant_token()
    assert token.startswith("tnt_")


def test_generate_tenant_token_is_high_entropy_and_unique():
    tokens = {generate_tenant_token() for _ in range(50)}
    assert len(tokens) == 50  # no collisions across 50 generations


def test_build_tenant_record_hashes_the_token_not_stores_it():
    token, record = build_tenant_record("Soweto Traders", "soweto-traders", PEPPER)
    assert record["token_hash"] == hash_tenant_token(token, PEPPER)
    assert "token" not in record
    assert token not in str(record.values())


def test_build_tenant_record_sets_expected_fields():
    token, record = build_tenant_record("Soweto Traders", "soweto-traders", PEPPER)
    assert record["tenant_name"] == "Soweto Traders"
    assert record["tenant_slug"] == "soweto-traders"
    assert record["is_active"] is True


def test_build_tenant_record_rejects_blank_name():
    with pytest.raises(ValueError):
        build_tenant_record("", "soweto-traders", PEPPER)


def test_build_tenant_record_rejects_blank_slug():
    with pytest.raises(ValueError):
        build_tenant_record("Soweto Traders", "", PEPPER)

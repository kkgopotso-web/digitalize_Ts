import pytest
from pydantic import ValidationError

from popia_pipeline import (
    process_and_mask_transaction,
    generate_popia_hash,
    get_system_salt,
)

SALT = "ZA_TEST_SECRET_SALT_KEY_2026_SECURE"

VALID_PAYLOAD = {
    "merchant_id": "M_SOWETO_TRADER_1092",
    "gross_value_cents": 125050,
    "raw_phone_number": "27721234567",
    "raw_email": "trader@townshipbiz.co.za",
}


def test_valid_payload_processing():
    result = process_and_mask_transaction(VALID_PAYLOAD, SALT)
    assert result["compliance_status"] == "COMPLIANT_ANONYMISED"
    assert result["transaction_value_zar"] == 1250.50
    assert result["merchant_hash"].startswith("ANON_")
    assert result["masked_contact_phone"].startswith("ANON_")
    assert result["masked_contact_email"].startswith("ANON_")


def test_no_plaintext_leakage_in_output():
    result = process_and_mask_transaction(VALID_PAYLOAD, SALT)
    serialized = str(result)
    assert VALID_PAYLOAD["raw_phone_number"] not in serialized
    assert VALID_PAYLOAD["raw_email"] not in serialized
    assert VALID_PAYLOAD["merchant_id"] not in serialized


def test_invalid_phone_format():
    payload = {**VALID_PAYLOAD, "raw_phone_number": "0821234567"}
    with pytest.raises(ValidationError):
        process_and_mask_transaction(payload, SALT)


def test_invalid_email_format():
    payload = {**VALID_PAYLOAD, "raw_email": "not-an-email"}
    with pytest.raises(ValidationError):
        process_and_mask_transaction(payload, SALT)


def test_merchant_id_too_short():
    payload = {**VALID_PAYLOAD, "merchant_id": "M_1"}
    with pytest.raises(ValidationError):
        process_and_mask_transaction(payload, SALT)


def test_zero_value_rejected():
    payload = {**VALID_PAYLOAD, "gross_value_cents": 0}
    with pytest.raises(ValidationError):
        process_and_mask_transaction(payload, SALT)


def test_negative_value_rejected():
    payload = {**VALID_PAYLOAD, "gross_value_cents": -500}
    with pytest.raises(ValidationError):
        process_and_mask_transaction(payload, SALT)


def test_hash_is_deterministic():
    h1 = generate_popia_hash("27721234567", SALT)
    h2 = generate_popia_hash("27721234567", SALT)
    assert h1 == h2


def test_hash_differs_with_different_salt():
    h1 = generate_popia_hash("27721234567", SALT)
    h2 = generate_popia_hash("27721234567", "ANOTHER_DIFFERENT_SALT_VALUE_2026")
    assert h1 != h2


def test_generate_hash_rejects_short_salt():
    with pytest.raises(ValueError):
        generate_popia_hash("27721234567", "short")


def test_get_system_salt_missing(monkeypatch):
    monkeypatch.delenv("POPIA_SALT_KEY", raising=False)
    with pytest.raises(ValueError):
        get_system_salt()


def test_get_system_salt_too_short(monkeypatch):
    monkeypatch.setenv("POPIA_SALT_KEY", "short")
    with pytest.raises(ValueError):
        get_system_salt()

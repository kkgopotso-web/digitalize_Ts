import pytest
from pydantic import ValidationError
from popia_pipeline import process_and_mask_transaction

def test_valid_payload_processing():
    salt = "ZA_TEST_SECRET_SALT_KEY_2026_SECURE"
    payload = {
        "merchant_id": "M_SOWETO_TRADER_1092",
        "gross_value_cents": 125050,
        "raw_phone_number": "27721234567",
        "raw_email": "trader@townshipbiz.co.za"
    }
    result = process_and_mask_transaction(payload, salt)
    assert result["compliance_status"] == "COMPLIANT_ANONYMISED"
    assert result["transaction_value_zar"] == 1250.50
    assert result["merchant_hash"].startswith("ANON_")

def test_invalid_phone_format():
    salt = "ZA_TEST_SECRET_SALT_KEY_2026_SECURE"
    payload = {
        "merchant_id": "M_SOWETO_TRADER_1092",
        "gross_value_cents": 1000,
        "raw_phone_number": "0821234567", # Invalid international/local structure missing +27/27 spec
        "raw_email": "trader@townshipbiz.co.za"
    }
    with pytest.raises(ValidationError):
        process_and_mask_transaction(payload, salt)
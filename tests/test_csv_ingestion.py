import pytest

from csv_ingestion import (
    MAX_CSV_ROWS,
    CsvFormatError,
    CsvIngestionSummary,
    parse_csv_rows,
    ingest_transactions_csv,
)
from popia_pipeline import process_and_mask_transaction

SALT = "ZA_TEST_SECRET_SALT_KEY_2026_SECURE"

HEADER = "merchant_id,gross_value_cents,raw_phone_number,raw_email"

VALID_ROW_1 = "M_SOWETO_TRADER_1092,125050,27721234567,trader@townshipbiz.co.za"
VALID_ROW_2 = "M_ALEX_SPAZA_SHOP_02,50000,27831234567,spaza@alexbiz.co.za"


def csv_text(*rows: str) -> str:
    return "\n".join([HEADER, *rows])


# ---------- parse_csv_rows: structural validation ----------

def test_parse_csv_rows_returns_row_dicts():
    rows = parse_csv_rows(csv_text(VALID_ROW_1, VALID_ROW_2))
    assert len(rows) == 2
    assert rows[0]["merchant_id"] == "M_SOWETO_TRADER_1092"
    assert rows[1]["raw_email"] == "spaza@alexbiz.co.za"


def test_parse_csv_rows_rejects_empty_content():
    with pytest.raises(CsvFormatError):
        parse_csv_rows("")


def test_parse_csv_rows_rejects_whitespace_only_content():
    with pytest.raises(CsvFormatError):
        parse_csv_rows("   \n   ")


def test_parse_csv_rows_rejects_missing_required_column():
    bad_header = "merchant_id,gross_value_cents,raw_phone_number"  # no raw_email
    with pytest.raises(CsvFormatError) as exc_info:
        parse_csv_rows(bad_header + "\n" + "M_X,100,27721234567")
    assert "raw_email" in str(exc_info.value)


def test_parse_csv_rows_rejects_header_only_no_data_rows():
    with pytest.raises(CsvFormatError):
        parse_csv_rows(HEADER)


def test_parse_csv_rows_rejects_too_many_rows():
    rows = [VALID_ROW_1 for _ in range(MAX_CSV_ROWS + 1)]
    with pytest.raises(CsvFormatError) as exc_info:
        parse_csv_rows(csv_text(*rows))
    assert str(MAX_CSV_ROWS) in str(exc_info.value)


def test_parse_csv_rows_accepts_exactly_max_rows():
    rows = [VALID_ROW_1 for _ in range(MAX_CSV_ROWS)]
    parsed = parse_csv_rows(csv_text(*rows))
    assert len(parsed) == MAX_CSV_ROWS


# ---------- ingest_transactions_csv: deterministic per-row processing ----------

def test_ingest_all_valid_rows_succeed():
    summary = ingest_transactions_csv(csv_text(VALID_ROW_1, VALID_ROW_2), SALT)
    assert isinstance(summary, CsvIngestionSummary)
    assert summary.total_rows == 2
    assert summary.succeeded == 2
    assert summary.failed == 0
    assert all(r.status == "success" for r in summary.results)


def test_ingest_row_matches_direct_pipeline_call():
    summary = ingest_transactions_csv(csv_text(VALID_ROW_1), SALT)
    direct = process_and_mask_transaction(
        {
            "merchant_id": "M_SOWETO_TRADER_1092",
            "gross_value_cents": 125050,
            "raw_phone_number": "27721234567",
            "raw_email": "trader@townshipbiz.co.za",
        },
        SALT,
    )
    row = summary.results[0]
    assert row.merchant_hash == direct["merchant_hash"]
    assert row.transaction_value_zar == direct["transaction_value_zar"]
    assert row.masked_contact_phone == direct["masked_contact_phone"]
    assert row.masked_contact_email == direct["masked_contact_email"]
    assert row.compliance_status == direct["compliance_status"]


def test_ingest_row_numbers_are_1_indexed_against_data_rows():
    summary = ingest_transactions_csv(csv_text(VALID_ROW_1, VALID_ROW_2), SALT)
    assert [r.row_number for r in summary.results] == [1, 2]


def test_ingest_partial_failure_isolates_bad_rows():
    bad_row = "M_BAD,not-a-number,27721234567,trader@townshipbiz.co.za"
    summary = ingest_transactions_csv(csv_text(VALID_ROW_1, bad_row, VALID_ROW_2), SALT)
    assert summary.total_rows == 3
    assert summary.succeeded == 2
    assert summary.failed == 1
    assert summary.results[0].status == "success"
    assert summary.results[1].status == "error"
    assert summary.results[1].row_number == 2
    assert summary.results[2].status == "success"


def test_ingest_invalid_phone_row_fails_with_error_message():
    bad_row = "M_SOWETO_TRADER_1092,125050,0821234567,trader@townshipbiz.co.za"
    summary = ingest_transactions_csv(csv_text(bad_row), SALT)
    assert summary.failed == 1
    assert summary.results[0].error is not None
    assert summary.results[0].merchant_hash is None


def test_ingest_invalid_email_row_fails():
    bad_row = "M_SOWETO_TRADER_1092,125050,27721234567,not-an-email"
    summary = ingest_transactions_csv(csv_text(bad_row), SALT)
    assert summary.failed == 1


def test_ingest_zero_value_row_fails():
    bad_row = "M_SOWETO_TRADER_1092,0,27721234567,trader@townshipbiz.co.za"
    summary = ingest_transactions_csv(csv_text(bad_row), SALT)
    assert summary.failed == 1


def test_ingest_error_messages_never_leak_raw_pii():
    bad_row = "M_SOWETO_TRADER_1092,125050,0821234567,leaky-secret@townshipbiz.co.za"
    summary = ingest_transactions_csv(csv_text(bad_row), SALT)
    serialized = summary.model_dump_json()
    assert "0821234567" not in serialized
    assert "leaky-secret@townshipbiz.co.za" not in serialized


def test_ingest_raises_csv_format_error_for_structurally_invalid_csv():
    with pytest.raises(CsvFormatError):
        ingest_transactions_csv("", SALT)

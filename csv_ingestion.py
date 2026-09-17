"""Deterministic CSV bulk-ingestion core for the POPIA transaction pipeline.

Parses a CSV of raw transaction rows and runs every row through the exact
same deterministic validation + masking core as the single-transaction
path (popia_pipeline.process_and_mask_transaction). No LLM involvement,
no row silently skipped: every row ends up either "success" (masked
payload) or "error" (a POPIA-safe message that never echoes the row's
raw field values). Persistence is intentionally NOT handled here -- that
stays an API-layer concern (see api.py), so this module has no I/O and
is trivially unit-testable.
"""
import csv
import io
from typing import Optional

from pydantic import BaseModel, ValidationError

from popia_pipeline import process_and_mask_transaction

# Hard ceiling on rows per upload. Keeps a single request's processing
# time bounded and deterministic, and blocks abuse of the bulk endpoint.
MAX_CSV_ROWS = 500

REQUIRED_COLUMNS = {"merchant_id", "gross_value_cents", "raw_phone_number", "raw_email"}


class CsvFormatError(Exception):
    """Raised for structural CSV problems (bad header, no rows, too many
    rows) -- distinct from a single row failing field validation."""


class RowIngestionResult(BaseModel):
    row_number: int
    status: str  # "success" | "error"
    merchant_hash: Optional[str] = None
    transaction_value_zar: Optional[float] = None
    masked_contact_phone: Optional[str] = None
    masked_contact_email: Optional[str] = None
    compliance_status: Optional[str] = None
    error: Optional[str] = None


class CsvIngestionSummary(BaseModel):
    total_rows: int
    succeeded: int
    failed: int
    results: list[RowIngestionResult]


def parse_csv_rows(csv_text: str) -> list[dict]:
    """Parses raw CSV text into row dicts, or raises CsvFormatError for
    structural problems. Checked up front, before any row processing."""
    if not csv_text or not csv_text.strip():
        raise CsvFormatError("CSV content is empty.")

    reader = csv.DictReader(io.StringIO(csv_text))
    if reader.fieldnames is None:
        raise CsvFormatError("CSV has no header row.")

    present = {col.strip() for col in reader.fieldnames if col}
    missing = REQUIRED_COLUMNS - present
    if missing:
        raise CsvFormatError(f"CSV is missing required columns: {', '.join(sorted(missing))}")

    rows = list(reader)
    if not rows:
        raise CsvFormatError("CSV has a header but no data rows.")
    if len(rows) > MAX_CSV_ROWS:
        raise CsvFormatError(f"CSV has {len(rows)} rows; the maximum per upload is {MAX_CSV_ROWS}.")

    return rows


def _row_to_payload_dict(row: dict) -> dict:
    """Coerces raw CSV string values into the types SecureTransactionPayload
    expects. Leaves values it can't coerce as-is so Pydantic produces the
    real validation error instead of this function raising directly."""
    payload = dict(row)
    raw_value = payload.get("gross_value_cents", "")
    try:
        payload["gross_value_cents"] = int(str(raw_value).strip())
    except (TypeError, ValueError):
        pass
    return payload


def _describe_validation_error(exc: ValidationError) -> str:
    """Field names/types only -- never the raw input value, which may be PII."""
    fields = sorted({".".join(str(part) for part in err["loc"]) for err in exc.errors()})
    return f"invalid/missing field(s): {', '.join(fields)}"


def ingest_transactions_csv(csv_text: str, salt_key: str) -> CsvIngestionSummary:
    """Deterministic core: validates + masks every row. Never raises on a
    single row's failure -- only parse_csv_rows' structural CsvFormatError
    propagates. Row numbers are 1-indexed against the data rows (header
    excluded), matching what a spreadsheet user expects."""
    rows = parse_csv_rows(csv_text)

    results: list[RowIngestionResult] = []
    succeeded = 0
    failed = 0

    for index, row in enumerate(rows, start=1):
        try:
            sanitized = process_and_mask_transaction(_row_to_payload_dict(row), salt_key)
            results.append(RowIngestionResult(row_number=index, status="success", **sanitized))
            succeeded += 1
        except ValidationError as exc:
            results.append(RowIngestionResult(
                row_number=index,
                status="error",
                error=f"Validation failed: {_describe_validation_error(exc)}",
            ))
            failed += 1
        except ValueError as exc:
            results.append(RowIngestionResult(row_number=index, status="error", error=str(exc)))
            failed += 1
        except Exception:  # noqa: BLE001 -- never let an unexpected error leak row content
            results.append(RowIngestionResult(
                row_number=index,
                status="error",
                error="Unexpected error processing this row.",
            ))
            failed += 1

    return CsvIngestionSummary(
        total_rows=len(rows),
        succeeded=succeeded,
        failed=failed,
        results=results,
    )

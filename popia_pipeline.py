import os
import hmac
import hashlib
import logging
from decimal import Decimal
from pydantic import BaseModel, Field, EmailStr, field_validator

logger = logging.getLogger("ProfessionalOS.Compliance")

class SecureTransactionPayload(BaseModel):
    merchant_id: str = Field(..., min_length=5, max_length=50)
    gross_value_cents: int = Field(..., gt=0)
    raw_phone_number: str = Field(..., pattern=r"^\+?27[6781][0-9]{8}$")
    raw_email: EmailStr

    @field_validator('gross_value_cents')
    @classmethod
    def validate_positive_currency(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("Transaction financial metrics must be strictly greater than zero.")
        return v

def generate_popia_hash(sensitive_value: str, salt_secret: str) -> str:
    """Generates a cryptographically secure, irreversible SHA-256 HMAC hash."""
    if not salt_secret or len(salt_secret) < 16:
        raise ValueError("System security failure: Invalid or insecure salt key provided.")
    hashed = hmac.new(
        salt_secret.encode('utf-8'),
        sensitive_value.strip().encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return f"ANON_{hashed[:32]}"

def process_and_mask_transaction(payload_data: dict, salt_key: str) -> dict:
    """Ingests raw operational data, executes schema validation, and returns a POPIA-compliant payload."""
    validated_data = SecureTransactionPayload(**payload_data)
    
    masked_phone = generate_popia_hash(validated_data.raw_phone_number, salt_key)
    masked_email = generate_popia_hash(validated_data.raw_email, salt_key)
    
    # Enforce Decimal precision for ZAR conversion
    zar_value = Decimal(validated_data.gross_value_cents) / Decimal(100)
    
    logger.info("Transaction successfully masked under POPIA compliance protocols.")
    return {
        "merchant_hash": generate_popia_hash(validated_data.merchant_id, salt_key),
        "transaction_value_zar": float(zar_value),
        "masked_contact_phone": masked_phone,
        "masked_contact_email": masked_email,
        "compliance_status": "COMPLIANT_ANONYMISED"
    }
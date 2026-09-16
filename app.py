import os
from datetime import datetime, timezone

import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from supabase import create_client

from popia_pipeline import process_and_mask_transaction, get_system_salt

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None

st.set_page_config(
    page_title="ProfessionalOS | Secure Transaction Gateway",
    page_icon="\U0001F6E1️",
    layout="wide",
)

if "history" not in st.session_state:
    st.session_state.history = []

# ---------- Sidebar: system status ----------
with st.sidebar:
    st.markdown("### Orynexa Technologies")
    st.caption("ProfessionalOS — POC 1")

    try:
        get_system_salt()
        st.success("POPIA salt key: configured")
    except ValueError:
        st.error("POPIA salt key: missing / insecure")

    if supabase:
        st.success("Supabase: connected")
    else:
        st.warning("Supabase: not configured")

    st.divider()
    st.markdown("**Session summary**")
    st.metric("Transactions processed", len(st.session_state.history))
    total_zar = sum(item["transaction_value_zar"] for item in st.session_state.history)
    st.metric("Total value (ZAR)", f"R {total_zar:,.2f}")

    if st.session_state.history:
        st.divider()
        if st.button("Clear session history", use_container_width=True):
            st.session_state.history = []
            st.rerun()

# ---------- Header ----------
st.title("\U0001F6E1️ ProfessionalOS: Enterprise Secure Transaction Gateway")
st.caption(
    "Validates, hashes and anonymises merchant transaction data under POPIA "
    "before persistence — all sensitive fields are irreversibly masked."
)

form_col, result_col = st.columns([1, 1], gap="large")

# ---------- Form ----------
with form_col:
    st.subheader("New transaction")
    with st.form("transaction_form", border=True):
        merchant_id = st.text_input("Merchant ID", "M_SOWETO_TRADER_1092")
        gross_cents = st.number_input(
            "Gross Value (Cents)", min_value=1, value=125050, step=1,
            help="Amount in cents, e.g. R1250.50 = 125050",
        )
        phone = st.text_input("Raw Phone Number", "27721234567")
        email = st.text_input("Raw Email", "trader@townshipbiz.co.za")
        submitted = st.form_submit_button("Process & Sanitize Payload", use_container_width=True, type="primary")

    if submitted:
        try:
            salt = get_system_salt()
            raw_payload = {
                "merchant_id": merchant_id,
                "gross_value_cents": int(gross_cents),
                "raw_phone_number": phone,
                "raw_email": email,
            }

            with st.spinner("Validating and anonymising payload..."):
                sanitized = process_and_mask_transaction(raw_payload, salt)

                if supabase:
                    supabase.table("anonymized_transactions").insert(sanitized).execute()
                    sanitized["_persisted"] = True
                else:
                    sanitized["_persisted"] = False

            sanitized["_processed_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            st.session_state.history.insert(0, sanitized)

            st.success("Payload successfully validated and anonymised under POPIA guidelines.")
            if not supabase:
                st.warning("Supabase credentials missing — persistence step bypassed.")

        except Exception as e:
            st.error(f"Validation or processing error: {e}")

# ---------- Latest result ----------
with result_col:
    st.subheader("Latest sanitized payload")
    if st.session_state.history:
        latest = st.session_state.history[0]
        c1, c2 = st.columns(2)
        c1.metric("Transaction value", f"R {latest['transaction_value_zar']:,.2f}")
        c2.metric("Status", latest["compliance_status"])
        st.json({k: v for k, v in latest.items() if not k.startswith("_")})
    else:
        st.info("Submit a transaction to see the anonymised payload here.")

# ---------- Session history ----------
st.divider()
st.subheader("Session audit log")
if st.session_state.history:
    df = pd.DataFrame(st.session_state.history)
    display_cols = [
        "_processed_at", "merchant_hash", "transaction_value_zar",
        "masked_contact_phone", "masked_contact_email", "compliance_status", "_persisted",
    ]
    df = df[[c for c in display_cols if c in df.columns]].rename(columns={
        "_processed_at": "processed_at (UTC)",
        "_persisted": "persisted_to_supabase",
    })
    st.dataframe(df, use_container_width=True, hide_index=True)
    st.download_button(
        "Download audit log (CSV)",
        df.to_csv(index=False).encode("utf-8"),
        file_name="popia_audit_log.csv",
        mime="text/csv",
    )
else:
    st.caption("No transactions processed yet this session.")

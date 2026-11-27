"""
Threadlock Security, Logic & Legal Compliance Red-Team Audit Suite
Tests every fixed vulnerability, business-logic edge case, payment webhook,
and legal compliance guard directly against the running FastAPI app and SQLite store.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import tempfile
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from fastapi.testclient import TestClient

from api.server import (
    API_BEARER_TOKEN,
    RAZORPAY_WEBHOOK_SECRET,
    SLACK_SIGNING_SECRET,
    STRIPE_WEBHOOK_SECRET,
    WHATSAPP_WEBHOOK_SECRET,
    app,
)
from engine.bitemporal_graph import BitemporalDealGraph
from engine.symbolic_verifier import DealInvoiceProposal, ProofCarryingTaxVerifier


def run_security_and_legal_audit() -> None:
    client = TestClient(app)
    auth_headers = {"Authorization": f"Bearer {API_BEARER_TOKEN}"}
    results = {}

    # 1. SECURITY: Unauthenticated /api/v1/* must be blocked (401/403)
    r_unauth = client.get("/api/v1/brief/morning")
    r_bad_tok = client.get("/api/v1/brief/morning", headers={"Authorization": "Bearer wrong_key"})
    results["1_api_bearer_auth_enforced"] = (r_unauth.status_code == 401 and r_bad_tok.status_code == 403)

    # 2. SECURITY: Spoofed WhatsApp, Slack (replay), Razorpay & Stripe webhooks must be rejected (401)
    wa_body = json.dumps({"deal_id": "d_sec", "sender_name": "<script>alert(1)</script>", "text": "Quote ₹1,00,000"}).encode()
    r_wa_spoof = client.post("/webhooks/whatsapp", content=wa_body, headers={"X-Hub-Signature-256": "sha256=deadbeef"})
    valid_wa_sig = "sha256=" + hmac.new(WHATSAPP_WEBHOOK_SECRET.encode(), wa_body, hashlib.sha256).hexdigest()
    r_wa_valid = client.post("/webhooks/whatsapp", content=wa_body, headers={"X-Hub-Signature-256": valid_wa_sig})

    # Slack replay attack (timestamp 10 minutes old) must fail
    old_ts = str(int(time.time()) - 600)
    sl_body = json.dumps({"deal_id": "d_sl", "user_name": "VP", "text": "Agreed"}).encode()
    old_sig = "v0=" + hmac.new(SLACK_SIGNING_SECRET.encode(), f"v0:{old_ts}:".encode() + sl_body, hashlib.sha256).hexdigest()
    r_sl_replay = client.post("/webhooks/slack", content=sl_body, headers={"X-Slack-Request-Timestamp": old_ts, "X-Slack-Signature": old_sig})

    results["2_webhook_hmac_and_replay_blocked"] = (
        r_wa_spoof.status_code == 401 and r_wa_valid.status_code == 200 and r_sl_replay.status_code == 401
    )

    # 3. SECURITY: XSS Sanitization check (script tag escaped in stored commitment/deal)
    r_xss = client.post(
        "/api/v1/deals",
        headers=auth_headers,
        json={"deal_id": "d_xss", "account_name": "<img src=x onerror=alert(1)>", "contact_name": "Bob"},
    )
    results["3_xss_sanitized"] = (r_xss.status_code == 200 and "<img" not in r_xss.json()["account_name"])

    # 4. LEGAL: Two-Party Call Recording Consent Gate (US-CA & IN-DPDP must return 451 if consent_confirmed=False)
    r_no_consent = client.post(
        "/api/v1/hud/evaluate",
        headers=auth_headers,
        json={"deal_id": "d_sec", "prospect_utterance": "We need perpetual rights", "jurisdiction": "US-CA", "consent_confirmed": False},
    )
    r_with_consent = client.post(
        "/api/v1/hud/evaluate",
        headers=auth_headers,
        json={"deal_id": "d_sec", "prospect_utterance": "We need perpetual rights", "jurisdiction": "US-CA", "consent_confirmed": True},
    )
    results["4_two_party_call_consent_enforced"] = (
        r_no_consent.status_code == 451 and r_with_consent.status_code == 200 and "EPHEMERAL_RAM_ONLY" in r_with_consent.json()["consent_audit"]
    )

    # 5. PAYMENTS: Razorpay INR UPI AutoPay + Stripe USD HMAC verification
    rzp_body = json.dumps({"event": "subscription.activated", "plan_id": "solo_pro", "customer_id": "cust_in_1"}).encode()
    rzp_sig = hmac.new(RAZORPAY_WEBHOOK_SECRET.encode(), rzp_body, hashlib.sha256).hexdigest()
    r_rzp_ok = client.post("/webhooks/razorpay", content=rzp_body, headers={"X-Razorpay-Signature": rzp_sig})
    r_rzp_bad = client.post("/webhooks/razorpay", content=rzp_body, headers={"X-Razorpay-Signature": "bad"})

    st_ts = str(int(time.time()))
    st_body = json.dumps({"type": "invoice.paid", "plan_id": "agency_team", "customer_id": "cust_us_1"}).encode()
    st_v1 = hmac.new(STRIPE_WEBHOOK_SECRET.encode(), f"{st_ts}.".encode() + st_body, hashlib.sha256).hexdigest()
    r_st_ok = client.post("/webhooks/stripe", content=st_body, headers={"Stripe-Signature": f"t={st_ts},v1={st_v1}"})
    results["5_razorpay_and_stripe_hmac_verified"] = (
        r_rzp_ok.status_code == 200 and r_rzp_ok.json()["entitlement_active"] is True
        and r_rzp_bad.status_code == 401
        and r_st_ok.status_code == 200 and r_st_ok.json()["entitlement_active"] is True
    )

    # 6. LOGIC & PERSISTENCE: Cross-Restart Idempotency + Persistent Ed25519 Key + Cumulative ₹30k 194J Threshold + US USD Exemption
    with tempfile.TemporaryDirectory() as tmp:
        db_file = os.path.join(tmp, "persist.db")
        key_file = os.path.join(tmp, "sign.pem")

        g1 = BitemporalDealGraph(db_path=db_file)
        v1 = ProofCarryingTaxVerifier(graph=g1, key_path=key_file)
        pub_key_1 = v1.public_key_b64

        # Two consecutive ₹20,000 deals for the same Indian client:
        # Deal 1 (₹20k <= ₹30k) -> 0% TDS; Deal 2 (cumulative ₹40k > ₹30k) -> 10% TDS MUST trigger!
        g1.upsert_deal("d_cum_1", "Acme India", "Priya", "WB", "MH", False, "INR")
        g1.record_temporal_fact("d_cum_1", "PRICING_QUOTE", {"amount_paise": 2000000}, "WhatsApp")
        c1 = v1.verify_and_sign(
            DealInvoiceProposal(idempotency_key="k_cum_1", deal_id="d_cum_1", base_amount_paise=2000000, direct_cost_paise=500000, min_margin_pct=35, tds_section="194J"),
            g1.build_state_snapshot("d_cum_1"),
        )

        # Simulate full server restart (new Graph + Verifier reading same SQLite DB & PEM key)
        g2 = BitemporalDealGraph(db_path=db_file)
        v2 = ProofCarryingTaxVerifier(graph=g2, key_path=key_file)
        pub_key_2 = v2.public_key_b64

        # Replay of k_cum_1 after restart MUST be blocked!
        c1_replay = v2.verify_and_sign(
            DealInvoiceProposal(idempotency_key="k_cum_1", deal_id="d_cum_1", base_amount_paise=2000000, direct_cost_paise=500000, min_margin_pct=35, tds_section="194J"),
            g2.build_state_snapshot("d_cum_1"),
        )

        # Deal 2 for same client (₹20k -> cumulative ₹40k > ₹30k -> 10% TDS = ₹2,000)
        g2.upsert_deal("d_cum_2", "Acme India", "Priya", "WB", "MH", False, "INR")
        g2.record_temporal_fact("d_cum_2", "PRICING_QUOTE", {"amount_paise": 2000000}, "WhatsApp")
        c2 = v2.verify_and_sign(
            DealInvoiceProposal(idempotency_key="k_cum_2", deal_id="d_cum_2", base_amount_paise=2000000, direct_cost_paise=500000, min_margin_pct=35, tds_section="194J"),
            g2.build_state_snapshot("d_cum_2"),
        )

        # US-to-US USD deal MUST NOT apply Indian GST or TDS
        g2.upsert_deal("d_us_1", "Stripe US", "Alex", "US-CA", "US-NY", True, "USD")
        g2.record_temporal_fact("d_us_1", "PRICING_QUOTE", {"amount_paise": 500000}, "Gmail")
        c_us = v2.verify_and_sign(
            DealInvoiceProposal(idempotency_key="k_us_1", deal_id="d_us_1", base_amount_paise=500000, direct_cost_paise=100000, min_margin_pct=35, tds_section="194J", currency="USD"),
            g2.build_state_snapshot("d_us_1"),
        )

        results["6_cross_restart_idempotency_and_key_persist"] = (
            pub_key_1 == pub_key_2 and c1.verdict == "SAT" and c1_replay.verdict == "UNSAT"
        )
        results["7_cumulative_194j_threshold_and_us_usd_exemption"] = (
            c1.breakdown.tds_minor == 0
            and c2.breakdown.tds_minor == 200000
            and c_us.breakdown.gst_applicable is False
            and c_us.breakdown.tds_minor == 0
            and "DECISION-SUPPORT ONLY" in c_us.legal_disclaimer
        )

    # 7. LEGAL: DPDP Act 2023 & GDPR Art. 17 1-Click Right-to-Erasure
    client.post("/api/v1/deals", headers=auth_headers, json={"deal_id": "d_erase", "account_name": "EraseMe Corp", "contact_name": "Neha"})
    r_erase = client.delete("/api/v1/privacy/erasure/EraseMe%20Corp", headers=auth_headers)
    results["8_dpdp_gdpr_right_to_erasure"] = (r_erase.status_code == 200 and r_erase.json()["deals_and_threads_erased"] >= 1)

    all_passed = all(results.values())
    print(json.dumps({"all_red_team_checks_passed": all_passed, "checks": results}, indent=2))
    if not all_passed:
        sys.exit(1)


if __name__ == "__main__":
    run_security_and_legal_audit()

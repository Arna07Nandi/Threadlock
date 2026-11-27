"""
Threadlock Billing & Subscriptions — Razorpay (India INR / UPI AutoPay) + Stripe (Global USD)
Provides PPP plan definitions, checkout payload builders, and HMAC-verified webhook handlers.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Dict, Optional

from compliance.legal_guard import verify_hmac_sha256

PPP_PLANS: Dict[str, Dict[str, Any]] = {
    "free": {
        "name": "Free Viral Hook",
        "inr_paise_monthly": 0,
        "usd_cents_monthly": 0,
        "limits": {"tracked_deals": 2, "contract_scans": "unlimited"},
    },
    "solo_pro": {
        "name": "Solo Pro (Creators & Reps)",
        "inr_paise_monthly": 79900,  # ₹799/mo
        "usd_cents_monthly": 2900,   # $29/mo
        "limits": {"tracked_deals": "unlimited", "stealth_hud": True, "whatsapp_brief": True},
    },
    "agency_team": {
        "name": "Team / Agency Roster",
        "inr_paise_monthly": 499900,  # ₹4,999/mo
        "usd_cents_monthly": 7900,    # $79/seat/mo
        "limits": {"tracked_deals": "unlimited", "shared_deal_graph": True, "brand_portals": True},
    },
}


def verify_razorpay_webhook(secret: str, raw_body: bytes, signature: Optional[str]) -> bool:
    """Razorpay sends raw hex HMAC-SHA256 in X-Razorpay-Signature (no prefix)."""
    return verify_hmac_sha256(secret, raw_body, signature, prefix="")


def verify_stripe_webhook(secret: str, raw_body: bytes, stripe_sig_header: Optional[str]) -> bool:
    """Verifies Stripe-Signature header format: t=<timestamp>,v1=<hex_hmac>."""
    if not secret or not stripe_sig_header:
        return False
    parts = dict(item.split("=", 1) for item in stripe_sig_header.split(",") if "=" in item)
    ts = parts.get("t")
    v1 = parts.get("v1")
    if not ts or not v1:
        return False
    signed_payload = f"{ts}.".encode("utf-8") + raw_body
    expected = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, v1)


def handle_subscription_event(provider: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Normalizes Razorpay UPI AutoPay & Stripe subscription lifecycle webhooks."""
    event_type = payload.get("event") or payload.get("type") or "unknown"
    plan_id = payload.get("plan_id", "solo_pro")
    customer_id = payload.get("customer_id", "cust_unknown")
    active = event_type in {
        "subscription.activated",
        "subscription.charged",
        "invoice.paid",
        "checkout.session.completed",
    }
    return {
        "provider": provider,
        "event_type": event_type,
        "customer_id": customer_id,
        "plan_id": plan_id,
        "entitlement_active": active,
    }

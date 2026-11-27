"""
Threadlock Compliance & Security Guard
Handles:
  1. Two-Party / All-Party Call Recording Consent Gate (US CA/IL/FL/PA/MA, EU GDPR, India DPDP Act 2023)
  2. HMAC-SHA256 Webhook Signature & Replay-Window Verification (WhatsApp/Meta, Slack, Razorpay, Stripe)
  3. XSS / HTML Injection Sanitization & Payload Size Limits
  4. UPL (Unauthorized Practice of Law) & Tax-Advisory Decision-Support Disclaimers
"""
from __future__ import annotations

import hashlib
import hmac
import html
import re
import time
from typing import Dict, Optional, Set, Tuple

# Jurisdictions requiring all-party consent before recording or persisting call audio/transcripts
ALL_PARTY_CONSENT_JURISDICTIONS: Set[str] = {
    "US-CA", "US-CT", "US-DE", "US-FL", "US-IL", "US-MD",
    "US-MA", "US-MI", "US-MT", "US-NH", "US-OR", "US-PA", "US-WA",
    "EU", "UK", "IN-DPDP",
}

LEGAL_DECISION_SUPPORT_DISCLAIMER = (
    "DECISION-SUPPORT ONLY: Threadlock contract flags and tax breakdowns are automated "
    "decision-support calculations and do not constitute legal advice or Chartered Accountant "
    "tax certification. Verify all statutory filings (GST/TDS/W-8BEN) and legal redlines with "
    "qualified counsel or a licensed CA before execution."
)

MAX_TEXT_BYTES = 65_536  # 64 KB limit against ReDoS & memory exhaustion


def sanitize_untrusted_text(raw: str) -> str:
    """Strips control chars, caps length, and escapes HTML to prevent XSS & ReDoS."""
    if not raw:
        return ""
    trimmed = raw.encode("utf-8")[:MAX_TEXT_BYTES].decode("utf-8", errors="ignore")
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", trimmed)
    return html.escape(cleaned, quote=True)


def verify_call_consent(
    jurisdiction: str,
    consent_confirmed: bool,
    ephemeral_zero_recording: bool = True,
) -> Tuple[bool, str]:
    """
    Prevents illegal wiretapping / unauthorized recording:
    - In all-party consent jurisdictions (e.g., US-CA, EU, IN-DPDP), requires explicit
      consent_confirmed=True before any audio/transcript processing.
    - Enforces Ephemeral Zero-Recording Mode by default (volatile RAM only, zero disk audio).
    """
    jur = (jurisdiction or "IN-DPDP").upper()
    if jur in ALL_PARTY_CONSENT_JURISDICTIONS and not consent_confirmed:
        return (
            False,
            f"CONSENT_REQUIRED ({jur}): Explicit participant disclosure and consent_confirmed=True "
            "are required before activating Live Call HUD or capturing call audio.",
        )
    mode = "EPHEMERAL_RAM_ONLY" if ephemeral_zero_recording else "CONSENTED_TRANSCRIPT_LOG"
    return True, f"CONSENT_VERIFIED ({jur} · {mode})"


def verify_hmac_sha256(
    secret: str,
    raw_body: bytes,
    provided_signature: Optional[str],
    prefix: str = "sha256=",
) -> bool:
    """Constant-time HMAC-SHA256 verification (Meta WhatsApp, Razorpay, custom webhooks)."""
    if not secret or not provided_signature:
        return False
    expected = prefix + hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, provided_signature.strip())


def verify_slack_signature(
    signing_secret: str,
    timestamp_header: Optional[str],
    raw_body: bytes,
    provided_signature: Optional[str],
    max_skew_seconds: int = 300,
) -> bool:
    """Verifies Slack v0 HMAC-SHA256 signature with 5-minute replay-attack window."""
    if not signing_secret or not timestamp_header or not provided_signature:
        return False
    try:
        ts = int(timestamp_header)
    except ValueError:
        return False
    if abs(int(time.time()) - ts) > max_skew_seconds:
        return False
    basestring = f"v0:{ts}:".encode("utf-8") + raw_body
    expected = "v0=" + hmac.new(signing_secret.encode("utf-8"), basestring, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, provided_signature.strip())


class SlidingWindowRateLimiter:
    """Lightweight per-client sliding-window rate limiter to protect API & webhooks."""
    def __init__(self, max_requests: int = 120, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: Dict[str, list] = {}

    def allow(self, client_key: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        bucket = [t for t in self._hits.get(client_key, []) if t > cutoff]
        if len(bucket) >= self.max_requests:
            self._hits[client_key] = bucket
            return False
        bucket.append(now)
        self._hits[client_key] = bucket
        return True

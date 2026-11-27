"""
Threadlock Hardened Production FastAPI Server
Enforces:
  - HMAC-SHA256 webhook signatures (WhatsApp, Slack w/ replay window, Razorpay, Stripe)
  - Timing-safe Bearer API key auth on /api/v1/* + Per-IP sliding-window rate limiting
  - Mandatory Two-Party Call Recording Consent Gate on /api/v1/hud/evaluate
  - XSS sanitization on all untrusted inbound messages
  - DPDP Act 2023 / GDPR Art. 17 Right-to-Erasure endpoint
"""
from __future__ import annotations

import hmac
import json
import os
from typing import Any, Dict, List, Optional

import uuid
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from compliance.security_firewall import inspect_malicious_payload, redact_secrets
from engine.business_math import compute_deal_economics, extract_gst_inclusive
from engine.llm_client import ProductionLLMRouter
from engine.usage_meter import UsageQuotaGuard
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from compliance.legal_guard import (
    SlidingWindowRateLimiter,
    sanitize_untrusted_text,
    verify_call_consent,
    verify_hmac_sha256,
    verify_slack_signature,
)
from engine.bitemporal_graph import BitemporalDealGraph
from engine.dual_speed_pipeline import DualSpeedDealBrain
from engine.symbolic_verifier import (
    DealInvoiceProposal,
    ProofCarryingTaxVerifier,
    scan_contract_clauses,
)
from integrations.connectors import (
    normalize_gmail_webhook,
    normalize_slack_webhook,
    normalize_whatsapp_webhook,
    run_90_day_history_import,
)
from integrations.oauth_flow import OAuthConnectorManager
from integrations.payments import (
    PPP_PLANS,
    handle_subscription_event,
    verify_razorpay_webhook,
    verify_stripe_webhook,
)

DB_PATH = os.environ.get("THREADLOCK_DB_PATH", ":memory:")
AUDIT_PATH = os.environ.get("THREADLOCK_AUDIT_PATH", ".threadlock/audit.jsonl")
SIGNING_KEY_PATH = os.environ.get("THREADLOCK_SIGNING_KEY_PATH", ".threadlock/signing_key.pem")
API_BEARER_TOKEN = os.environ.get("THREADLOCK_API_KEY", "tl_dev_secret_change_in_prod")
WHATSAPP_WEBHOOK_SECRET = os.environ.get("WHATSAPP_WEBHOOK_SECRET", "wa_dev_secret")
WHATSAPP_VERIFY_TOKEN = os.environ.get("WHATSAPP_VERIFY_TOKEN", "tl_meta_verify_token")
GMAIL_PUBSUB_TOKEN = os.environ.get("GMAIL_PUBSUB_TOKEN", "tl_gmail_pubsub_secret")
SLACK_SIGNING_SECRET = os.environ.get("SLACK_SIGNING_SECRET", "slack_dev_secret")
RAZORPAY_WEBHOOK_SECRET = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "rzp_dev_secret")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "whsec_dev_secret")

app = FastAPI(title="Threadlock — Hardened Deal Chief of Staff API", version="2.0.0")
graph = BitemporalDealGraph(db_path=DB_PATH)
brain = DualSpeedDealBrain(graph=graph)
verifier = ProofCarryingTaxVerifier(graph=graph, key_path=SIGNING_KEY_PATH, audit_log_path=AUDIT_PATH)
rate_limiter = SlidingWindowRateLimiter(max_requests=180, window_seconds=60)
llm_router = ProductionLLMRouter()
oauth_manager = OAuthConnectorManager()
usage_meter = UsageQuotaGuard(conn=graph.conn)

allowed_origins = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "http://localhost:8000").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Hub-Signature-256", "X-Slack-Signature", "X-Slack-Request-Timestamp", "X-Razorpay-Signature", "Stripe-Signature"],
)

@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    req_id = request.headers.get("X-Request-ID") or f"req_{uuid.uuid4().hex[:12]}"
    response = await call_next(request)
    response.headers["X-Request-ID"] = req_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


def _to_dict(model: BaseModel) -> Dict[str, Any]:
    return model.model_dump() if hasattr(model, "model_dump") else model.dict()


def require_api_auth(
    request: Request, authorization: Optional[str] = Header(default=None)
) -> None:
    client_ip = request.client.host if request.client else "local"
    if not rate_limiter.allow(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer API token.")
    token = authorization.split(" ", 1)[1].strip()
    if not hmac.compare_digest(token, API_BEARER_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid API token.")


class HudRequest(BaseModel):
    deal_id: str
    prospect_utterance: str
    jurisdiction: str = "IN-DPDP"
    consent_confirmed: bool = False
    ephemeral_zero_recording: bool = True


class ContractScanRequest(BaseModel):
    text: str


class DealUpsertRequest(BaseModel):
    deal_id: str
    account_name: str
    contact_name: str
    supplier_state: str = "WB"
    buyer_state: str = "MH"
    is_export_lut: bool = False
    currency: str = "INR"


@app.get("/", response_class=HTMLResponse)
def serve_frontend() -> str:
    web_path = os.path.join(os.path.dirname(__file__), "..", "web", "index.html")
    if os.path.exists(web_path):
        with open(web_path, "r", encoding="utf-8") as fh:
            return fh.read()
    return "<h1>Threadlock Hardened API Running</h1>"


@app.get("/health")
def health_check() -> Dict[str, str]:
    return {"status": "ok", "public_key_ed25519": verifier.public_key_b64, "live_llm_enabled": llm_router.is_live_enabled}


@app.get("/api/v1/plans")
def get_pricing_plans() -> Dict[str, Any]:
    return {"plans": PPP_PLANS}


@app.post("/api/v1/deals", dependencies=[Depends(require_api_auth)])
def create_or_update_deal(req: DealUpsertRequest) -> Dict[str, Any]:
    d = _to_dict(req)
    d["account_name"] = sanitize_untrusted_text(d["account_name"])
    d["contact_name"] = sanitize_untrusted_text(d["contact_name"])
    return graph.upsert_deal(**d)


@app.post("/webhooks/whatsapp")
async def webhook_whatsapp(
    request: Request, x_hub_signature_256: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    raw = await request.body()
    if not verify_hmac_sha256(WHATSAPP_WEBHOOK_SECRET, raw, x_hub_signature_256, prefix="sha256="):
        raise HTTPException(status_code=401, detail="Invalid WhatsApp HMAC-SHA256 signature.")
    payload = json.loads(raw.decode("utf-8"))
    norm = normalize_whatsapp_webhook(payload)
    norm["sender"] = sanitize_untrusted_text(norm["sender"])
    norm["body"] = sanitize_untrusted_text(norm["body"])
    graph.upsert_deal(norm["deal_id"], sanitize_untrusted_text(payload.get("account_name", norm["sender"])), norm["sender"])
    return brain.ingest_cross_app_message(**norm)


@app.post("/webhooks/slack")
async def webhook_slack(
    request: Request,
    x_slack_request_timestamp: Optional[str] = Header(default=None),
    x_slack_signature: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    raw = await request.body()
    if not verify_slack_signature(SLACK_SIGNING_SECRET, x_slack_request_timestamp, raw, x_slack_signature):
        raise HTTPException(status_code=401, detail="Invalid or expired Slack signature.")
    payload = json.loads(raw.decode("utf-8"))
    norm = normalize_slack_webhook(payload)
    norm["sender"] = sanitize_untrusted_text(norm["sender"])
    norm["body"] = sanitize_untrusted_text(norm["body"])
    graph.upsert_deal(norm["deal_id"], sanitize_untrusted_text(payload.get("account_name", norm["sender"])), norm["sender"])
    return brain.ingest_cross_app_message(**norm)


@app.post("/webhooks/razorpay")
async def webhook_razorpay(
    request: Request, x_razorpay_signature: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    raw = await request.body()
    if not verify_razorpay_webhook(RAZORPAY_WEBHOOK_SECRET, raw, x_razorpay_signature):
        raise HTTPException(status_code=401, detail="Invalid Razorpay webhook signature.")
    return handle_subscription_event("razorpay", json.loads(raw.decode("utf-8")))


@app.post("/webhooks/stripe")
async def webhook_stripe(
    request: Request, stripe_signature: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    raw = await request.body()
    if not verify_stripe_webhook(STRIPE_WEBHOOK_SECRET, raw, stripe_signature):
        raise HTTPException(status_code=401, detail="Invalid Stripe webhook signature.")
    return handle_subscription_event("stripe", json.loads(raw.decode("utf-8")))


@app.post("/api/v1/import/90-day", dependencies=[Depends(require_api_auth)])
def import_history(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    sanitized = []
    for ev in events:
        copy_ev = dict(ev)
        copy_ev["body"] = sanitize_untrusted_text(str(ev.get("body", "")))
        copy_ev["sender"] = sanitize_untrusted_text(str(ev.get("sender", "Contact")))
        sanitized.append(copy_ev)
    return run_90_day_history_import(graph, brain, sanitized)


@app.post("/api/v1/hud/evaluate", dependencies=[Depends(require_api_auth)])
async def evaluate_hud(req: HudRequest) -> Dict[str, Any]:
    ok, msg = verify_call_consent(req.jurisdiction, req.consent_confirmed, req.ephemeral_zero_recording)
    if not ok:
        raise HTTPException(status_code=451, detail=msg)
    res = await brain.evaluate_live_hud_smart(req.deal_id, sanitize_untrusted_text(req.prospect_utterance), llm_router)
    res["consent_audit"] = msg
    return res


@app.get("/api/v1/brief/morning", dependencies=[Depends(require_api_auth)])
def get_morning_brief() -> Dict[str, Any]:
    return brain.compile_morning_brief()


@app.post("/api/v1/brief/{commitment_id}/approve", dependencies=[Depends(require_api_auth)])
def approve_brief_item(commitment_id: str) -> Dict[str, Any]:
    ok = graph.approve_commitment(commitment_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Commitment not found or already approved.")
    return {"status": "approved_sent", "commitment_id": commitment_id}


@app.post("/api/v1/contracts/scan", dependencies=[Depends(require_api_auth)])
def scan_contract(req: ContractScanRequest) -> Dict[str, Any]:
    return scan_contract_clauses(sanitize_untrusted_text(req.text))


@app.post("/api/v1/deals/verify-invoice", dependencies=[Depends(require_api_auth)])
def verify_deal_invoice(proposal: DealInvoiceProposal) -> Dict[str, Any]:
    try:
        snapshot = graph.build_state_snapshot(proposal.deal_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    cert = verifier.verify_and_sign(proposal, snapshot)
    return _to_dict(cert)


@app.delete("/api/v1/privacy/erasure/{account_name}", dependencies=[Depends(require_api_auth)])
def erase_account_data(account_name: str) -> Dict[str, Any]:
    """DPDP Act 2023 & GDPR Art. 17 1-Click Right-to-Erasure."""
    result = graph.erase_account_pii(sanitize_untrusted_text(account_name))
    return {"status": "erased", "account": account_name, **result}


@app.get("/auth/status")
def oauth_status() -> Dict[str, Any]:
    return {"providers": oauth_manager.list_connections()}


@app.get("/auth/{provider}/start")
def oauth_start(provider: str) -> Dict[str, Any]:
    try:
        return oauth_manager.build_authorize_url(provider)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/auth/{provider}/callback")
async def oauth_callback(provider: str, code: str, state: str) -> Dict[str, Any]:
    try:
        return await oauth_manager.exchange_code(provider, code, state)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


class HudSummonRequest(BaseModel):
    deal_id: str
    user_query: str
    jurisdiction: str = "IN-DPDP"
    consent_confirmed: bool = True
    ephemeral_zero_recording: bool = True


class BriefPrefsRequest(BaseModel):
    brief_time: str = "08:00"
    timezone: str = "UTC"
    delivery_channel: str = "WhatsApp"


@app.post("/api/v1/hud/summon", dependencies=[Depends(require_api_auth)])
def summon_hud_manually(req: HudSummonRequest) -> Dict[str, Any]:
    """On-Demand Hotkey Summon (Cmd+Shift+Space) if Threadlock stayed silent during a call."""
    ok, msg = verify_call_consent(req.jurisdiction, req.consent_confirmed, req.ephemeral_zero_recording)
    if not ok:
        raise HTTPException(status_code=451, detail=msg)
    res = brain.summon_live_hud(req.deal_id, sanitize_untrusted_text(req.user_query))
    res["consent_audit"] = msg
    return res


@app.get("/api/v1/preferences/brief", dependencies=[Depends(require_api_auth)])
def get_brief_prefs() -> Dict[str, str]:
    return graph.get_brief_preferences()


@app.put("/api/v1/preferences/brief", dependencies=[Depends(require_api_auth)])
def update_brief_prefs(req: BriefPrefsRequest) -> Dict[str, str]:
    try:
        return graph.set_brief_preferences(req.brief_time, req.timezone, req.delivery_channel)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


class DealEconomicsRequest(BaseModel):
    base_minor: int
    direct_cost_minor: int
    proposed_discount_pct: int = 0
    payment_days: int = 30
    estimated_hours: int = 20
    extra_unpaid_hours: int = 0
    upfront_gst_pct: int = 0


class UsageConsumeRequest(BaseModel):
    user_id: str = "default"
    minutes: int = 30
    is_new_call: bool = True


@app.post("/api/v1/deals/economics", dependencies=[Depends(require_api_auth)])
def evaluate_deal_economics(req: DealEconomicsRequest) -> Dict[str, Any]:
    return compute_deal_economics(**_to_dict(req))


@app.post("/api/v1/usage/consume-call", dependencies=[Depends(require_api_auth)])
def consume_call_quota(req: UsageConsumeRequest) -> Dict[str, Any]:
    allowed, info = usage_meter.consume_call_minutes(req.user_id, req.minutes, req.is_new_call)
    if not allowed:
        raise HTTPException(status_code=402, detail=info)
    return info


@app.post("/api/v1/security/inspect", dependencies=[Depends(require_api_auth)])
def inspect_input_safety(req: ContractScanRequest) -> Dict[str, Any]:
    check = inspect_malicious_payload(req.text)
    return {
        **check,
        "redacted_preview": redact_secrets(sanitize_untrusted_text(req.text)),
    }


class WaitlistRequest(BaseModel):
    email: str
    platform: str = "macOS"


@app.post("/api/v1/waitlist")
def join_waitlist(request: Request, req: WaitlistRequest) -> Dict[str, Any]:
    client_ip = request.client.host if request.client else "local"
    if not rate_limiter.allow(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests.")
    email_clean = sanitize_untrusted_text(req.email).strip().lower()
    if "@" not in email_clean or "." not in email_clean.split("@")[-1]:
        raise HTTPException(status_code=422, detail="Please enter a valid email address.")
    plat = req.platform if req.platform in ("macOS", "Windows") else "macOS"
    graph.conn.execute(
        """
        CREATE TABLE IF NOT EXISTS waitlist_signups (
            email TEXT PRIMARY KEY,
            platform TEXT NOT NULL,
            trial_days INTEGER NOT NULL DEFAULT 14,
            created_at TEXT NOT NULL
        );
        """
    )
    from engine.bitemporal_graph import utc_now_iso
    graph.conn.execute(
        "INSERT OR IGNORE INTO waitlist_signups(email, platform, trial_days, created_at) VALUES (?, ?, 14, ?)",
        (email_clean, plat, utc_now_iso()),
    )
    graph.conn.commit()
    return {"status": "reserved", "email": email_clean, "platform": plat, "trial_days": 14}


@app.get("/webhooks/whatsapp")
def verify_whatsapp_webhook_handshake(request: Request):
    """Required Meta WhatsApp Business API hub.challenge handshake."""
    mode = request.query_params.get("hub.mode")
    token = request.query_params.get("hub.verify_token")
    challenge = request.query_params.get("hub.challenge")
    if mode == "subscribe" and token and hmac.compare_digest(token, WHATSAPP_VERIFY_TOKEN) and challenge:
        return HTMLResponse(content=challenge, status_code=200)
    raise HTTPException(status_code=403, detail="Invalid Meta WhatsApp verify_token.")


@app.post("/webhooks/gmail")
async def webhook_gmail(request: Request, x_gmail_pubsub_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    if not x_gmail_pubsub_token or not hmac.compare_digest(x_gmail_pubsub_token, GMAIL_PUBSUB_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid Gmail Pub/Sub verification token.")
    raw = await request.body()
    payload = json.loads(raw.decode("utf-8"))
    norm = normalize_gmail_webhook(payload)
    norm["sender"] = sanitize_untrusted_text(norm["sender"])
    norm["body"] = sanitize_untrusted_text(norm["body"])
    graph.upsert_deal(norm["deal_id"], sanitize_untrusted_text(payload.get("account_name", norm["sender"])), norm["sender"])
    return brain.ingest_cross_app_message(**norm)


@app.post("/api/v1/deals/gst-inclusive", dependencies=[Depends(require_api_auth)])
def calc_gst_inclusive(gross_minor: int, gst_pct: int = 18) -> Dict[str, int]:
    try:
        return extract_gst_inclusive(gross_minor, gst_pct)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

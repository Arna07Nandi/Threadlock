"""
Threadlock Engine — Hardened Proof-Carrying Neuro-Symbolic Business Math & Tax Verifier
Fixes:
  - Persistent Ed25519 signing key (survives restarts; chmod 0o600)
  - SQLite-backed cross-restart idempotency & hash chain (blocks replays even after reboot)
  - Atomic FY revenue ledger update on SAT (cumulative ₹20L GST & ₹30k 194J thresholds work accurately)
  - Currency-aware jurisdiction logic (US-to-US USD deals never get Indian GST/TDS applied)
  - Sec 194C 1% (Individual/HUF) vs 2% (Company/Firm) + Sec 194J 10%
  - Mandatory UPL / Chartered Accountant decision-support disclaimer on every certificate
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, Field

from compliance.legal_guard import LEGAL_DECISION_SUPPORT_DISCLAIMER
from engine.bitemporal_graph import BitemporalDealGraph, StateSnapshot

try:
    import z3  # type: ignore
    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False


class DealInvoiceProposal(BaseModel):
    idempotency_key: str = Field(..., min_length=4, max_length=128)
    deal_id: str
    base_amount_paise: int = Field(..., ge=0)
    direct_cost_paise: int = Field(0, ge=0)
    min_margin_pct: int = Field(35, ge=0, le=95)
    tds_section: str = Field("194J")  # "194J" | "194C_IND" | "194C_CORP" | "NONE"
    proposed_quote_edge_id: Optional[str] = None
    currency: str = Field("INR")


class TaxBreakdown(BaseModel):
    currency: str
    base_minor: int
    gst_applicable: bool
    cgst_minor: int
    sgst_minor: int
    igst_minor: int
    gross_invoice_minor: int
    tds_minor: int
    tds_rule_applied: str
    net_receivable_minor: int
    gross_margin_bps: int


class ProofCertificate(BaseModel):
    verdict: str  # "SAT" | "UNSAT"
    solver_backend: str
    idempotency_key: str
    snapshot_hash: str
    invariants_passed: Dict[str, bool]
    violations: List[str]
    breakdown: TaxBreakdown
    prev_audit_hash: str
    entry_hash: str
    ed25519_signature_b64: str
    legal_disclaimer: str
    issued_at: str


CONTRACT_RULES: List[Tuple[str, str, str, str, str]] = [
    (
        "PERPETUITY_WHITELISTING",
        "CRITICAL",
        r"\b(in\s+perpetuity|perpetual|irrevocable|forever|worldwide\s+unlimited)\b",
        "Grants lifetime paid ad/usage rights without recurring licensing fees (3x-5x value leak).",
        "Limit paid ad whitelisting to 60 days from publish; extensions billed at 25% of base fee per 30 days.",
    ),
    (
        "UNLIMITED_REVISIONS",
        "HIGH",
        r"\b(unlimited\s+(revisions?|edits?|reshoots?|changes?)|until\s+fully\s+satisfied)\b",
        "Exposes team to unbounded unpaid scope creep.",
        "Cap deliverables at 2 consolidated revision rounds; additional edits billed at 15% per round.",
    ),
    (
        "DELAYED_PAYMENT_TRAP",
        "HIGH",
        r"\b(net[\s-]*60|net[\s-]*90|net[\s-]*120|90\s+days\s+from\s+completion)\b",
        "Forces 2-4 months working-capital lockup while GST must be remitted upfront.",
        "Require 50% advance on Deal Portal sign-off and 50% Net-15 post-delivery.",
    ),
    (
        "OVERBROAD_EXCLUSIVITY",
        "MEDIUM",
        r"\b(12\s+months?\s+exclusiv|entire\s+category|any\s+competing\s+brand)\b",
        "Blocks high-paying future deals across broad verticals without an exclusivity fee.",
        "Restrict exclusivity to 3 named direct competitors for 30 days post-publish.",
    ),
]


def scan_contract_clauses(contract_text: str) -> Dict[str, object]:
    findings: List[Dict[str, str]] = []
    for code, severity, pattern, why, redline in CONTRACT_RULES:
        if re.search(pattern, contract_text, flags=re.IGNORECASE):
            findings.append(
                {"code": code, "severity": severity, "why": why, "counter_redline": redline}
            )
    return {"red_flags": findings, "legal_disclaimer": LEGAL_DECISION_SUPPORT_DISCLAIMER}


def _to_dict(model: BaseModel) -> Dict[str, object]:
    return model.model_dump() if hasattr(model, "model_dump") else model.dict()


def _to_json(model: BaseModel) -> str:
    return model.model_dump_json() if hasattr(model, "model_dump_json") else model.json()


class ProofCarryingTaxVerifier:
    GST_THRESHOLD_PAISE = 2_000_000 * 100
    TDS_194J_THRESHOLD_PAISE = 30_000 * 100

    def __init__(
        self,
        graph: BitemporalDealGraph,
        key_path: Optional[str] = None,
        audit_log_path: Optional[str] = None,
    ) -> None:
        self.graph = graph
        self._audit_log_path = audit_log_path
        self._private_key = self._load_or_create_key(key_path)
        self._public_key_b64 = base64.b64encode(
            self._private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).decode("ascii")
        if audit_log_path:
            os.makedirs(os.path.dirname(audit_log_path), exist_ok=True)

    @staticmethod
    def _load_or_create_key(key_path: Optional[str]) -> Ed25519PrivateKey:
        if key_path and os.path.exists(key_path):
            with open(key_path, "rb") as fh:
                return serialization.load_pem_private_key(fh.read(), password=None)
        key = Ed25519PrivateKey.generate()
        if key_path:
            os.makedirs(os.path.dirname(key_path), exist_ok=True)
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            with open(key_path, "wb") as fh:
                fh.write(pem)
            try:
                os.chmod(key_path, 0o600)
            except OSError:
                pass
        return key

    @property
    def public_key_b64(self) -> str:
        return self._public_key_b64

    @staticmethod
    def _round_half_up_pct(amount_minor: int, pct_int: int) -> int:
        return (amount_minor * pct_int + 50) // 100

    def verify_and_sign(self, proposal: DealInvoiceProposal, snapshot: StateSnapshot) -> ProofCertificate:
        violations: List[str] = []

        # 1. Persistent SQLite Idempotency Check (survives server restarts!)
        is_fresh_key = not self.graph.has_sat_idempotency_key(proposal.idempotency_key)
        if not is_fresh_key:
            violations.append(f"DUPLICATE_IDEMPOTENCY_KEY: {proposal.idempotency_key}")

        # 2. Temporal Non-Supersession Check
        quote_is_current = True
        if proposal.proposed_quote_edge_id and snapshot.active_edge_ids:
            quote_is_current = proposal.proposed_quote_edge_id in snapshot.active_edge_ids
            if not quote_is_current:
                violations.append("STALE_SUPERSEDED_QUOTE: Proposed quote edge was superseded.")

        if snapshot.active_quote_paise > 0 and proposal.base_amount_paise != snapshot.active_quote_paise:
            quote_is_current = False
            violations.append(
                f"QUOTE_MISMATCH: Proposal ({proposal.base_amount_paise}) != active quote ({snapshot.active_quote_paise})."
            )

        # 3. Jurisdiction-Aware Exact Integer-Minor-Unit Tax Determination
        base = proposal.base_amount_paise
        curr = proposal.currency.upper()
        is_indian_domestic = (curr == "INR") and (not snapshot.is_export_lut)

        if is_indian_domestic:
            projected_fy = snapshot.fy_turnover_paise + base
            gst_applicable = projected_fy >= self.GST_THRESHOLD_PAISE
            gst_total = self._round_half_up_pct(base, 18) if gst_applicable else 0
            if snapshot.supplier_state.upper() == snapshot.buyer_state.upper():
                cgst = gst_total // 2
                sgst = gst_total - cgst
                igst = 0
            else:
                cgst, sgst, igst = 0, 0, gst_total

            client_projected = snapshot.client_ytd_paise + base
            if proposal.tds_section == "194J":
                if base > self.TDS_194J_THRESHOLD_PAISE or client_projected > self.TDS_194J_THRESHOLD_PAISE:
                    tds = self._round_half_up_pct(base, 10)
                    tds_rule = "Sec 194J (10%; > ₹30,000 FY threshold)"
                else:
                    tds = 0
                    tds_rule = "Sec 194J (0%; within ₹30,000 FY threshold)"
            elif proposal.tds_section == "194C_IND":
                tds = self._round_half_up_pct(base, 1)
                tds_rule = "Sec 194C (1% Individual/HUF Contractor)"
            elif proposal.tds_section in ("194C", "194C_CORP"):
                tds = self._round_half_up_pct(base, 2)
                tds_rule = "Sec 194C (2% Corporate Contractor)"
            else:
                tds = 0
                tds_rule = "No TDS Applied"
        else:
            # Global USD / Cross-Border Export under LUT + W-8BEN (never apply Indian GST/TDS!)
            gst_applicable = False
            cgst = sgst = igst = 0
            tds = 0
            tds_rule = "0% Non-INR / Export LUT + W-8BEN Treaty Exempt"

        gross = base + cgst + sgst + igst
        net = gross - tds

        # 4. Exact Margin Floor Guard
        profit = base - proposal.direct_cost_paise
        margin_bps = (profit * 10_000) // base if base > 0 else 0
        margin_ok = (profit * 100) >= (proposal.min_margin_pct * base) and base > 0
        if not margin_ok:
            violations.append(
                f"MARGIN_FLOOR_BREACH: Actual margin {margin_bps / 100:.2f}% < floor {proposal.min_margin_pct}%."
            )

        # 5. Formal SMT / Hoare Postcondition Verification
        if HAS_Z3:
            s = z3.Solver()
            zb, zc, zs, zi, zg, zt, zn = z3.Ints("b c s i g t n")
            s.add(zb == base, zc == cgst, zs == sgst, zi == igst, zg == gross, zt == tds, zn == net,
                  zb > 0, zg == zb + zc + zs + zi, zn == zg - zt, zn > 0)
            smt_balance_ok = s.check() == z3.sat
            solver_name = "z3-smt-exact-int"
        else:
            smt_balance_ok = base > 0 and gross == base + cgst + sgst + igst and net == gross - tds and net > 0
            solver_name = "hoare-exact-int-kernel"

        invariants = {
            "idempotent_fresh_key": is_fresh_key,
            "bitemporal_quote_current": quote_is_current,
            "double_entry_tax_balance": smt_balance_ok,
            "margin_floor_satisfied": margin_ok,
        }
        verdict = "SAT" if all(invariants.values()) else "UNSAT"

        breakdown = TaxBreakdown(
            currency=curr,
            base_minor=base,
            gst_applicable=gst_applicable,
            cgst_minor=cgst,
            sgst_minor=sgst,
            igst_minor=igst,
            gross_invoice_minor=gross,
            tds_minor=tds,
            tds_rule_applied=tds_rule,
            net_receivable_minor=net,
            gross_margin_bps=margin_bps,
        )

        # 6. Persistent Hash-Chained Ed25519 Receipt
        prev_hash = self.graph.get_last_audit_hash()
        issued_at = datetime.now(timezone.utc).isoformat()
        payload_for_hash = {
            "verdict": verdict,
            "idempotency_key": proposal.idempotency_key,
            "snapshot_hash": snapshot.canonical_hash,
            "breakdown": _to_dict(breakdown),
            "invariants": invariants,
            "prev_audit_hash": prev_hash,
            "issued_at": issued_at,
        }
        canonical_bytes = json.dumps(payload_for_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
        entry_hash = hashlib.sha256(canonical_bytes).hexdigest()
        sig_b64 = base64.b64encode(self._private_key.sign(canonical_bytes)).decode("ascii")

        cert = ProofCertificate(
            verdict=verdict,
            solver_backend=solver_name,
            idempotency_key=proposal.idempotency_key,
            snapshot_hash=snapshot.canonical_hash,
            invariants_passed=invariants,
            violations=violations,
            breakdown=breakdown,
            prev_audit_hash=prev_hash,
            entry_hash=entry_hash,
            ed25519_signature_b64=sig_b64,
            legal_disclaimer=LEGAL_DECISION_SUPPORT_DISCLAIMER,
            issued_at=issued_at,
        )

        cert_json = _to_json(cert)
        self.graph.persist_audit_receipt(
            idempotency_key=proposal.idempotency_key,
            verdict=verdict,
            deal_id=proposal.deal_id,
            entry_hash=entry_hash,
            prev_audit_hash=prev_hash,
            certificate_json=cert_json,
            issued_at=issued_at,
            record_fy_amount_paise=base if (verdict == "SAT" and is_indian_domestic) else None,
        )

        if self._audit_log_path:
            with open(self._audit_log_path, "a", encoding="utf-8") as fh:
                fh.write(cert_json + "\n")

        return cert

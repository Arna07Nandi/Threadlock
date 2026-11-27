"""
Threadlock Engine — Dual-Speed Pipeline (Upgraded with On-Demand Summon, Custom Brief Timing & Non-Hurting Personalization)
  - Pipeline A (Auto + On-Demand Live Call HUD): Silent when not needed, OR user can manually summon via
    hotkey (Cmd+Shift+Space -> summon_live_hud) if Threadlock didn't auto-trigger.
  - Pipeline B (Memory-Adaptive Personalization + Non-Hurting Tone Guard): As the local Bitemporal Deal Graph
    grows, drafts become warmer and more context-aware while deterministically blocking/softening harsh phrases.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from engine.bitemporal_graph import BitemporalDealGraph
from compliance.security_firewall import inspect_malicious_payload, redact_secrets
from engine.llm_client import ProductionLLMRouter
from engine.symbolic_verifier import scan_contract_clauses

# Deterministic Non-Hurting Tone Guard: softens harsh/blaming phrases so drafts never damage relationships
HARSH_PHRASE_REWRITES = [
    (r"\byou\s+failed\s+to\s+pay\b", "our invoice is still open on our end"),
    (r"\bwhy\s+haven['’]?t\s+you\s+replied\b", "just gently floating this back to the top of your inbox"),
    (r"\bfinal\s+warning\b", "quick reminder so we can keep things moving smoothly"),
    (r"\bbreach\s+of\s+contract\b", "a small alignment check against what we agreed"),
    (r"\bunacceptable\b", "something we'd love to smooth out together"),
]


def enforce_non_hurting_tone(draft: str) -> Dict[str, Any]:
    """Ensures every staged follow-up stays warm, respectful, and non-accusatory."""
    softened = draft
    rewrites_applied = 0
    for pattern, replacement in HARSH_PHRASE_REWRITES:
        updated, count = re.subn(pattern, replacement, softened, flags=re.IGNORECASE)
        if count > 0:
            softened = updated
            rewrites_applied += count
    return {"draft": softened, "tone_softened": rewrites_applied > 0, "rewrites_count": rewrites_applied}


class DualSpeedDealBrain:
    def __init__(self, graph: BitemporalDealGraph) -> None:
        self.graph = graph

    def evaluate_live_hud(self, deal_id: str, prospect_utterance: str) -> Dict[str, Any]:
        """Pipeline A (Auto-Trigger): Sub-millisecond objection & temporal memory HUD router."""
        t0 = time.perf_counter()
        text = prospect_utterance.lower()

        if any(k in text for k in ["perpetuity", "perpetual", "whitelisting", "forever", "unlimited ads"]):
            return self._hud_resp(
                t0,
                "USAGE_TRAP",
                "Push back gently on permanent rights",
                "Offer 60-day paid usage now and keep monthly extensions optional so both sides stay flexible.",
                "Permanent rights typically carry 3x the base fee.",
            )

        if any(k in text for k in ["quoted", "earlier quote", "last month", "discount", "cheaper", "budget"]):
            active = self.graph.get_active_fact(deal_id, "PRICING_QUOTE")
            history = self.graph.get_fact_history(deal_id, "PRICING_QUOTE")
            if active and len(history) >= 2:
                prev_amt = history[-2]["value"].get("amount_paise", 0) / 100
                curr_amt = active["value"].get("amount_paise", 0) / 100
                return self._hud_resp(
                    t0,
                    "TEMPORAL_CONFLICT",
                    "Clarify updated quote calmly",
                    f"Active quote is {curr_amt:,.0f} (updating {prev_amt:,.0f} from {history[-2]['source_channel']}) to reflect the expanded scope.",
                    f"Latest edge active via {active['source_channel']}.",
                )
            return self._hud_resp(
                t0,
                "PRICING",
                "Hold value, offer flexible milestones",
                "Keep the base rate intact and offer a 50% start / 50% delivery split instead of discounting.",
                "Protects deal margin floor.",
            )

        if any(k in text for k in ["net 90", "net-90", "net 60", "net-60", "90 days"]):
            return self._hud_resp(
                t0,
                "PAYMENT_TERMS",
                "Counter Net-90 with split milestones",
                "Propose 50% upfront on sign-off and 50% Net-15 on delivery to keep cash flow healthy.",
                "Reduces average collection wait from 90+ days to 15 days.",
            )

        if any(k in text for k in ["bot", "recording", "ciso", "soc 2", "privacy", "train ai"]):
            return self._hud_resp(
                t0,
                "SECURITY",
                "Zero bots · Private by default",
                "Reassure them: no bot joins the call, audio stays ephemeral in memory, and nothing trains AI.",
                "Zero-retention processing active.",
            )

        return {"trigger": False, "latency_ms": round((time.perf_counter() - t0) * 1000, 3)}

    def summon_live_hud(self, deal_id: str, user_query: str) -> Dict[str, Any]:
        """
        Manual On-Demand Summon (Cmd+Shift+Space / Ctrl+Shift+Space):
        If Threadlock stayed silent during a subtle moment in a call, the user can manually
        summon it anytime and pull active memory, last promises, and quote history immediately.
        """
        t0 = time.perf_counter()
        active_quote = self.graph.get_active_fact(deal_id, "PRICING_QUOTE")
        quote_history = self.graph.get_fact_history(deal_id, "PRICING_QUOTE")
        depth = self.graph.get_deal_relationship_depth(deal_id)
        pending = [c for c in self.graph.list_pending_commitments() if c["deal_id"] == deal_id]

        # First check if user's manual query matches a known objection/clause cue
        auto_check = self.evaluate_live_hud(deal_id, user_query)
        if auto_check.get("trigger"):
            auto_check["summoned_manually"] = True
            return auto_check

        quote_summary = (
            f"Current agreed quote: {active_quote['value'].get('raw_text', active_quote['value'].get('amount_paise', 0) / 100)} "
            f"(via {active_quote['source_channel']}; {len(quote_history)} version(s) tracked)."
            if active_quote
            else "No active quote logged yet for this deal."
        )
        open_promises = (
            f"{len(pending)} open promise(s): {pending[0]['description']}"
            if pending
            else "No overdue promises on this account."
        )
        return {
            "trigger": True,
            "summoned_manually": True,
            "category": "MANUAL_SUMMON",
            "hud_headline": f"Context for {depth['contact_name']} ({depth['account_name']})",
            "suggested_pivot": f"{quote_summary} {open_promises}",
            "proof_point": f"Local graph memory: {depth['interaction_count']} tracked interaction(s) · Query: {user_query[:80]}",
            "latency_ms": round((time.perf_counter() - t0) * 1000, 3),
        }

    @staticmethod
    def _hud_resp(t0: float, category: str, headline: str, pivot: str, proof: str) -> Dict[str, Any]:
        return {
            "trigger": True,
            "summoned_manually": False,
            "category": category,
            "hud_headline": headline,
            "suggested_pivot": pivot,
            "proof_point": proof,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 3),
        }

    def compose_personalized_draft(
        self, deal_id: str, sender: str, channel: str, is_cash: bool, raw_context: str = ""
    ) -> Dict[str, Any]:
        """
        Memory-Adaptive Personalization:
        - Early relationship (0–2 memory nodes): crisp, polite, respectful.
        - Growing relationship (3+ memory nodes): warmer, references active quote & prior touchpoints,
          while passing through enforce_non_hurting_tone() so it NEVER sounds pushy or blaming.
        """
        depth = self.graph.get_deal_relationship_depth(deal_id)
        active_quote = self.graph.get_active_fact(deal_id, "PRICING_QUOTE")
        quote_ref = f" ({active_quote['value'].get('raw_text', '')})" if active_quote else ""
        interactions = depth["interaction_count"]

        if interactions >= 3:
            personalization_tier = "warm_established"
            if is_cash:
                draft = (
                    f"Hey {sender} — hope your week is going well! Just gently checking in on our open invoice{quote_ref} "
                    f"from our recent work together. Whenever finance has a moment, the link is ready for one-tap clearance—no rush at all, just keeping our books tidy."
                )
            else:
                draft = (
                    f"Hey {sender} — great chatting again on {channel}! As promised, here is the follow-up we discussed{quote_ref} "
                    f"so we stay aligned without any back-and-forth. Let me know if you'd like to tweak anything."
                )
        else:
            personalization_tier = "polite_first_touch"
            if is_cash:
                draft = (
                    f"Hi {sender} — sharing a polite reminder regarding our open invoice{quote_ref}. "
                    f"Please let me know if your team needs any updated paperwork to process it."
                )
            else:
                draft = (
                    f"Hi {sender} — following up as promised from our {channel} conversation{quote_ref}. "
                    f"Sharing the requested details here for your review."
                )

        if raw_context:
            # If user/LLM draft contained harsh wording, the Non-Hurting Guard automatically softens it
            tone_checked = enforce_non_hurting_tone(raw_context)
            if tone_checked["tone_softened"]:
                draft = tone_checked["draft"]

        safe = enforce_non_hurting_tone(draft)
        return {
            "draft": safe["draft"],
            "personalization_tier": personalization_tier,
            "relationship_interactions": interactions,
            "tone_softened": safe["tone_softened"],
        }

    def ingest_cross_app_message(
        self,
        deal_id: str,
        channel: str,
        sender: str,
        body: str,
        due_date: str = "2026-11-27",
    ) -> Dict[str, Any]:
        """Pipeline B: Extracts quotes (INR/USD/EUR/GBP), commitments, and contract red flags."""
        actions: List[str] = []
        lower = body.lower()

        # Detect revised pricing quote (₹, Rs, INR, $, €, £ — supports Indian lakh/comma formats too)
        money_match = re.search(r"(?:₹|rs\.?|inr|\$|€|£)\s*([0-9][0-9,]{2,})", body, flags=re.IGNORECASE)
        if money_match and any(w in lower for w in ["quote", "revised", "proposal", "final", "agreed", "budget", "invoice"]):
            amt_major = int(money_match.group(1).replace(",", ""))
            self.graph.record_temporal_fact(
                deal_id=deal_id,
                predicate="PRICING_QUOTE",
                value={"amount_paise": amt_major * 100, "raw_text": money_match.group(0)},
                source_channel=channel,
            )
            actions.append(f"SUPERSEDED_QUOTE:{amt_major}")

        if any(w in lower for w in ["i'll send", "will send", "will share", "promised", "by friday", "tomorrow", "soc 2"]):
            p = self.compose_personalized_draft(deal_id, sender, channel, is_cash=False)
            cid = self.graph.add_commitment(
                deal_id=deal_id,
                owner_type="REP",
                description=f"Follow up with {sender}: {body[:110]}",
                channel=channel,
                due_date=due_date,
                staged_draft=p["draft"],
            )
            actions.append(f"COMMITMENT_STAGED:{cid}:{p['personalization_tier']}")

        if any(w in lower for w in ["overdue", "pending invoice", "net-60", "net 60", "tds", "payment pending", "failed to pay"]):
            p = self.compose_personalized_draft(deal_id, sender, channel, is_cash=True)
            cid = self.graph.add_commitment(
                deal_id=deal_id,
                owner_type="PROSPECT",
                description=f"Cash Chaser ({channel}): {body[:100]}",
                channel=channel,
                due_date=due_date,
                staged_draft=p["draft"],
            )
            actions.append(f"CASH_CHASER_STAGED:{cid}:{p['personalization_tier']}")

        red_flags = scan_contract_clauses(body)
        return {"deal_id": deal_id, "channel": channel, "actions": actions, "contract_red_flags": red_flags}

    def compile_morning_brief(self, user_id: str = "default") -> Dict[str, Any]:
        """Builds the personalized Morning Whisper using the user's custom brief_time & timezone."""
        prefs = self.graph.get_brief_preferences(user_id=user_id)
        pending = self.graph.list_pending_commitments()
        lines = [f"Good morning ({prefs['brief_time']} {prefs['timezone']}). {len(pending)} item(s) ready for 1-tap approval:"]
        for idx, item in enumerate(pending[:5], 1):
            lines.append(
                f"{idx}. [{item['account_name']} via {item['channel']}] {item['description']} (Due {item['due_date']})"
            )
        return {
            "brief_time": prefs["brief_time"],
            "timezone": prefs["timezone"],
            "delivery_channel": prefs["delivery_channel"],
            "pending_count": len(pending),
            "message_text": "\n".join(lines),
            "items": pending,
        }

    async def evaluate_live_hud_smart(
        self, deal_id: str, prospect_utterance: str, llm_router: ProductionLLMRouter
    ) -> Dict[str, Any]:
        """
        Dual-speed hybrid router:
          1. Inspects input with Security Firewall (blocks prompt injection).
          2. Runs <1ms deterministic fast-path first (zero LLM cost).
          3. Falls back to live ZDR LLM (1.8s timeout) ONLY if configured and deterministic returned silent.
        """
        sec = inspect_malicious_payload(prospect_utterance)
        if not sec["safe"]:
            return {"trigger": False, "blocked_threats": sec["threats_detected"], "latency_ms": 0.1}

        fast = self.evaluate_live_hud(deal_id, prospect_utterance)
        if fast.get("trigger") or not llm_router.is_live_enabled:
            return fast

        sys_prompt = (
            "You are a silent live-call whisper. Output strict JSON: "
            '{"trigger": bool, "category": "PRICING|USAGE|SECURITY|PROMISE", '
            '"hud_headline": "max 6 words", "suggested_pivot": "max 22 words", "proof_point": "short fact"}'
        )
        llm_res = await llm_router.extract_structured_json(sys_prompt, prospect_utterance, timeout_s=1.8)
        if llm_res and llm_res.get("trigger"):
            return {
                "trigger": True,
                "summoned_manually": False,
                "category": str(llm_res.get("category", "LIVE_CUE")),
                "hud_headline": redact_secrets(str(llm_res.get("hud_headline", "")))[:80],
                "suggested_pivot": redact_secrets(str(llm_res.get("suggested_pivot", "")))[:200],
                "proof_point": redact_secrets(str(llm_res.get("proof_point", "ZDR Live Assist")))[:160],
                "source": "zdr_llm_fallback",
            }
        return fast

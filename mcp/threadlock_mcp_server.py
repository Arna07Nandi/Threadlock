"""
Threadlock MCP JSON-RPC 2.0 Stdio Server (Relic-Hardened Pattern)
Exposes Threadlock's local Bitemporal Deal Graph, Everyday Business Math Engine,
and Proof-Carrying Tax Verifier to Claude Desktop, Cursor, or any MCP client—
strictly guarded by the Adversarial Security Firewall and Secret Redaction.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from compliance.security_firewall import inspect_malicious_payload, redact_secrets
from engine.bitemporal_graph import BitemporalDealGraph
from engine.business_math import compute_deal_economics
from engine.dual_speed_pipeline import DualSpeedDealBrain


class ThreadlockMCPServer:
    def __init__(self, db_path: str = ":memory:") -> None:
        self.graph = BitemporalDealGraph(db_path=db_path)
        self.brain = DualSpeedDealBrain(graph=self.graph)

    def handle_jsonrpc(self, request: Dict[str, Any]) -> Dict[str, Any]:
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params") or {}

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {"name": "threadlock_morning_brief", "description": "Fetch pending 1-tap commitments from local Bitemporal Deal Graph."},
                        {"name": "threadlock_deal_economics", "description": "Compute exact integer discount-erosion, Net-90 cash drag, and hourly dilution."},
                        {"name": "threadlock_summon_context", "description": "Recall active quote & open promises for a deal."},
                    ]
                },
            }

        if method == "tools/call":
            tool_name = params.get("name", "")
            args = params.get("arguments") or {}

            # Security Firewall inspection on all MCP arguments
            raw_args_str = json.dumps(args)
            check = inspect_malicious_payload(raw_args_str)
            if not check["safe"]:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32001, "message": f"BLOCKED_BY_SECURITY_FIREWALL: {check['threats_detected']}"},
                }

            if tool_name == "threadlock_morning_brief":
                res = self.brain.compile_morning_brief()
            elif tool_name == "threadlock_deal_economics":
                res = compute_deal_economics(
                    base_minor=int(args.get("base_minor", 100000)),
                    direct_cost_minor=int(args.get("direct_cost_minor", 40000)),
                    proposed_discount_pct=int(args.get("proposed_discount_pct", 0)),
                    payment_days=int(args.get("payment_days", 30)),
                    estimated_hours=int(args.get("estimated_hours", 20)),
                    extra_unpaid_hours=int(args.get("extra_unpaid_hours", 0)),
                )
            elif tool_name == "threadlock_summon_context":
                res = self.brain.summon_live_hud(
                    deal_id=str(args.get("deal_id", "")),
                    user_query=str(args.get("user_query", "")),
                )
            else:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"}}

            safe_json = json.loads(redact_secrets(json.dumps(res)))
            return {"jsonrpc": "2.0", "id": req_id, "result": safe_json}

        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown method: {method}"}}


if __name__ == "__main__":
    srv = ThreadlockMCPServer(db_path=os.environ.get("THREADLOCK_DB_PATH", ".threadlock/threadlock.db"))
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        sys.stdout.write(json.dumps(srv.handle_jsonrpc(req)) + "\n")
        sys.stdout.flush()

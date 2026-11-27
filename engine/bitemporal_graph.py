"""
Threadlock Engine — ANIMA Bitemporal Deal-Memory Graph (SQLite + Persistent Audit Ledger + DPDP Erasure)
Tracks accounts, deals, temporal fact edges (valid_from / valid_until / superseded_by),
cross-app commitments, persistent idempotency receipts, and 1-click DPDP/GDPR Right-to-Erasure.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class StateSnapshot:
    """Immutable versioned state slice for Proof-Carrying Execution (TOCTOU-safe)."""
    snapshot_id: str
    deal_id: str
    fy_turnover_paise: int
    client_ytd_paise: int
    active_quote_paise: int
    supplier_state: str
    buyer_state: str
    is_export_lut: bool
    currency: str
    active_edge_ids: List[str]
    created_at: str
    canonical_hash: str


class BitemporalDealGraph:
    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA foreign_keys=ON;")
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self.conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS deals (
                deal_id TEXT PRIMARY KEY,
                account_name TEXT NOT NULL,
                contact_name TEXT NOT NULL,
                supplier_state TEXT NOT NULL DEFAULT 'WB',
                buyer_state TEXT NOT NULL DEFAULT 'MH',
                is_export_lut INTEGER NOT NULL DEFAULT 0,
                currency TEXT NOT NULL DEFAULT 'INR',
                stage TEXT NOT NULL DEFAULT 'negotiation',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS memory_edges (
                edge_id TEXT PRIMARY KEY,
                deal_id TEXT NOT NULL,
                predicate TEXT NOT NULL,
                value_json TEXT NOT NULL,
                source_channel TEXT NOT NULL,
                confidence_score REAL NOT NULL,
                valid_from TEXT NOT NULL,
                valid_until TEXT,
                tx_time TEXT NOT NULL,
                superseded_by TEXT,
                FOREIGN KEY(deal_id) REFERENCES deals(deal_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS commitments (
                commitment_id TEXT PRIMARY KEY,
                deal_id TEXT NOT NULL,
                owner_type TEXT NOT NULL,
                description TEXT NOT NULL,
                channel TEXT NOT NULL,
                due_date TEXT NOT NULL,
                staged_draft TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending_approval',
                created_at TEXT NOT NULL,
                FOREIGN KEY(deal_id) REFERENCES deals(deal_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS fy_ledger (
                ledger_id TEXT PRIMARY KEY,
                fy_code TEXT NOT NULL,
                account_name TEXT NOT NULL,
                deal_id TEXT NOT NULL,
                amount_paise INTEGER NOT NULL,
                recorded_at TEXT NOT NULL
            );

            -- Persistent Cross-Restart Idempotency & Hash-Chained Audit Ledger
            CREATE TABLE IF NOT EXISTS audit_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                idempotency_key TEXT NOT NULL,
                verdict TEXT NOT NULL,
                deal_id TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                prev_audit_hash TEXT NOT NULL,
                certificate_json TEXT NOT NULL,
                issued_at TEXT NOT NULL
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_sat_idem
                ON audit_receipts(idempotency_key) WHERE verdict = 'SAT';
            CREATE INDEX IF NOT EXISTS idx_edges_active ON memory_edges(deal_id, predicate, superseded_by);
            CREATE INDEX IF NOT EXISTS idx_commitments_status ON commitments(status, due_date);

            CREATE TABLE IF NOT EXISTS user_preferences (
                user_id TEXT PRIMARY KEY,
                brief_time TEXT NOT NULL DEFAULT '08:00',
                timezone TEXT NOT NULL DEFAULT 'UTC',
                delivery_channel TEXT NOT NULL DEFAULT 'WhatsApp',
                updated_at TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    def upsert_deal(
        self,
        deal_id: str,
        account_name: str,
        contact_name: str,
        supplier_state: str = "WB",
        buyer_state: str = "MH",
        is_export_lut: bool = False,
        currency: str = "INR",
        stage: str = "negotiation",
    ) -> Dict[str, Any]:
        now = utc_now_iso()
        self.conn.execute(
            """
            INSERT INTO deals(deal_id, account_name, contact_name, supplier_state, buyer_state, is_export_lut, currency, stage, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(deal_id) DO UPDATE SET
                account_name=excluded.account_name,
                contact_name=excluded.contact_name,
                supplier_state=excluded.supplier_state,
                buyer_state=excluded.buyer_state,
                is_export_lut=excluded.is_export_lut,
                currency=excluded.currency,
                stage=excluded.stage
            """,
            (deal_id, account_name, contact_name, supplier_state, buyer_state, int(is_export_lut), currency.upper(), stage, now),
        )
        self.conn.commit()
        return {"deal_id": deal_id, "account_name": account_name, "stage": stage, "currency": currency.upper()}

    def record_temporal_fact(
        self,
        deal_id: str,
        predicate: str,
        value: Any,
        source_channel: str,
        confidence_score: float = 0.95,
        valid_from: Optional[str] = None,
    ) -> Dict[str, Any]:
        now = utc_now_iso()
        v_from = valid_from or now
        new_edge_id = f"edge_{uuid.uuid4().hex[:12]}"
        cur = self.conn.cursor()

        cur.execute(
            "SELECT edge_id FROM memory_edges WHERE deal_id = ? AND predicate = ? AND superseded_by IS NULL",
            (deal_id, predicate),
        )
        prior_ids = [r["edge_id"] for r in cur.fetchall()]
        if prior_ids:
            cur.execute(
                "UPDATE memory_edges SET valid_until = ?, superseded_by = ? WHERE deal_id = ? AND predicate = ? AND superseded_by IS NULL",
                (now, new_edge_id, deal_id, predicate),
            )

        cur.execute(
            """
            INSERT INTO memory_edges(
                edge_id, deal_id, predicate, value_json, source_channel,
                confidence_score, valid_from, valid_until, tx_time, superseded_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, NULL)
            """,
            (new_edge_id, deal_id, predicate, json.dumps(value, sort_keys=True), source_channel, confidence_score, v_from, now),
        )
        self.conn.commit()
        return {
            "edge_id": new_edge_id,
            "deal_id": deal_id,
            "predicate": predicate,
            "value": value,
            "superseded_edge_ids": prior_ids,
        }

    def get_active_fact(self, deal_id: str, predicate: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            "SELECT * FROM memory_edges WHERE deal_id = ? AND predicate = ? AND superseded_by IS NULL ORDER BY tx_time DESC LIMIT 1",
            (deal_id, predicate),
        ).fetchone()
        if not row:
            return None
        return {
            "edge_id": row["edge_id"],
            "predicate": row["predicate"],
            "value": json.loads(row["value_json"]),
            "source_channel": row["source_channel"],
            "valid_from": row["valid_from"],
        }

    def get_fact_history(self, deal_id: str, predicate: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM memory_edges WHERE deal_id = ? AND predicate = ? ORDER BY tx_time ASC",
            (deal_id, predicate),
        ).fetchall()
        return [
            {
                "edge_id": r["edge_id"],
                "value": json.loads(r["value_json"]),
                "source_channel": r["source_channel"],
                "valid_from": r["valid_from"],
                "valid_until": r["valid_until"],
                "superseded_by": r["superseded_by"],
            }
            for r in rows
        ]

    def add_commitment(
        self, deal_id: str, owner_type: str, description: str, channel: str, due_date: str, staged_draft: str
    ) -> str:
        cid = f"cmt_{uuid.uuid4().hex[:10]}"
        self.conn.execute(
            """
            INSERT INTO commitments(commitment_id, deal_id, owner_type, description, channel, due_date, staged_draft, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending_approval', ?)
            """,
            (cid, deal_id, owner_type, description, channel, due_date, staged_draft, utc_now_iso()),
        )
        self.conn.commit()
        return cid

    def list_pending_commitments(self) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT c.*, d.account_name, d.contact_name
            FROM commitments c JOIN deals d ON c.deal_id = d.deal_id
            WHERE c.status = 'pending_approval'
            ORDER BY c.due_date ASC
            """
        ).fetchall()
        return [dict(r) for r in rows]

    def approve_commitment(self, commitment_id: str) -> bool:
        cur = self.conn.execute(
            "UPDATE commitments SET status = 'approved_sent' WHERE commitment_id = ? AND status = 'pending_approval'",
            (commitment_id,),
        )
        self.conn.commit()
        return cur.rowcount > 0

    def record_fy_revenue(self, fy_code: str, account_name: str, deal_id: str, amount_paise: int) -> None:
        self.conn.execute(
            "INSERT INTO fy_ledger(ledger_id, fy_code, account_name, deal_id, amount_paise, recorded_at) VALUES (?, ?, ?, ?, ?, ?)",
            (f"ldg_{uuid.uuid4().hex[:10]}", fy_code, account_name, deal_id, int(amount_paise), utc_now_iso()),
        )
        self.conn.commit()

    def has_sat_idempotency_key(self, idempotency_key: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM audit_receipts WHERE idempotency_key = ? AND verdict = 'SAT' LIMIT 1",
            (idempotency_key,),
        ).fetchone()
        return row is not None

    def get_last_audit_hash(self) -> str:
        row = self.conn.execute("SELECT entry_hash FROM audit_receipts ORDER BY seq DESC LIMIT 1").fetchone()
        return row["entry_hash"] if row else ("0" * 64)

    def persist_audit_receipt(
        self,
        idempotency_key: str,
        verdict: str,
        deal_id: str,
        entry_hash: str,
        prev_audit_hash: str,
        certificate_json: str,
        issued_at: str,
        record_fy_amount_paise: Optional[int] = None,
        fy_code: str = "FY2026-27",
    ) -> None:
        """Atomically writes receipt + FY revenue ledger in one transaction (fixes TOCTOU & restart replay)."""
        cur = self.conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            cur.execute(
                """
                INSERT INTO audit_receipts(idempotency_key, verdict, deal_id, entry_hash, prev_audit_hash, certificate_json, issued_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (idempotency_key, verdict, deal_id, entry_hash, prev_audit_hash, certificate_json, issued_at),
            )
            if verdict == "SAT" and record_fy_amount_paise and record_fy_amount_paise > 0:
                deal = cur.execute("SELECT account_name FROM deals WHERE deal_id = ?", (deal_id,)).fetchone()
                acct = deal["account_name"] if deal else "Unknown"
                cur.execute(
                    "INSERT INTO fy_ledger(ledger_id, fy_code, account_name, deal_id, amount_paise, recorded_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (f"ldg_{uuid.uuid4().hex[:10]}", fy_code, acct, deal_id, int(record_fy_amount_paise), issued_at),
                )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def erase_account_pii(self, account_name: str) -> Dict[str, int]:
        """
        India DPDP Act 2023 & GDPR Art. 17 Right-to-Erasure:
        Deletes all deals, memory_edges, and commitments for an account via CASCADE,
        and anonymizes account_name in fy_ledger to preserve statutory tax totals without PII.
        """
        cur = self.conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            deals_deleted = cur.execute("DELETE FROM deals WHERE account_name = ?", (account_name,)).rowcount
            anon_id = "ANON_" + hashlib.sha256(account_name.encode("utf-8")).hexdigest()[:12]
            ledger_anon = cur.execute(
                "UPDATE fy_ledger SET account_name = ? WHERE account_name = ?",
                (anon_id, account_name),
            ).rowcount
            self.conn.commit()
            return {"deals_and_threads_erased": deals_deleted, "tax_ledger_rows_anonymized": ledger_anon}
        except Exception:
            self.conn.rollback()
            raise

    def build_state_snapshot(self, deal_id: str, fy_code: str = "FY2026-27") -> StateSnapshot:
        deal = self.conn.execute("SELECT * FROM deals WHERE deal_id = ?", (deal_id,)).fetchone()
        if not deal:
            raise ValueError(f"Deal not found: {deal_id}")

        fy_row = self.conn.execute(
            "SELECT COALESCE(SUM(amount_paise), 0) AS total FROM fy_ledger WHERE fy_code = ?",
            (fy_code,),
        ).fetchone()
        client_row = self.conn.execute(
            "SELECT COALESCE(SUM(amount_paise), 0) AS total FROM fy_ledger WHERE fy_code = ? AND account_name = ?",
            (fy_code, deal["account_name"]),
        ).fetchone()

        active_quote = self.get_active_fact(deal_id, "PRICING_QUOTE")
        active_quote_paise = int(active_quote["value"].get("amount_paise", 0)) if active_quote else 0

        active_edges = self.conn.execute(
            "SELECT edge_id FROM memory_edges WHERE deal_id = ? AND superseded_by IS NULL ORDER BY edge_id ASC",
            (deal_id,),
        ).fetchall()
        edge_ids = [r["edge_id"] for r in active_edges]

        canonical_payload = {
            "deal_id": deal_id,
            "fy_turnover_paise": int(fy_row["total"]),
            "client_ytd_paise": int(client_row["total"]),
            "active_quote_paise": active_quote_paise,
            "supplier_state": deal["supplier_state"],
            "buyer_state": deal["buyer_state"],
            "is_export_lut": bool(deal["is_export_lut"]),
            "currency": deal["currency"],
            "active_edge_ids": edge_ids,
        }
        canonical_hash = hashlib.sha256(
            json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        return StateSnapshot(
            snapshot_id=f"snap_{uuid.uuid4().hex[:10]}",
            created_at=utc_now_iso(),
            canonical_hash=f"sha256:{canonical_hash}",
            **canonical_payload,
        )

    def set_brief_preferences(
        self, brief_time: str, tz_name: str = "UTC", delivery_channel: str = "WhatsApp", user_id: str = "default"
    ) -> Dict[str, str]:
        import re
        if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", brief_time):
            raise ValueError("brief_time must be HH:MM in 24-hour format (e.g. 07:30 or 09:00).")
        if delivery_channel not in ("WhatsApp", "Slack", "Email", "Desktop"):
            raise ValueError("Unsupported delivery_channel.")
        now = utc_now_iso()
        self.conn.execute(
            """
            INSERT INTO user_preferences(user_id, brief_time, timezone, delivery_channel, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                brief_time=excluded.brief_time,
                timezone=excluded.timezone,
                delivery_channel=excluded.delivery_channel,
                updated_at=excluded.updated_at
            """,
            (user_id, brief_time, tz_name, delivery_channel, now),
        )
        self.conn.commit()
        return {"user_id": user_id, "brief_time": brief_time, "timezone": tz_name, "delivery_channel": delivery_channel}

    def get_brief_preferences(self, user_id: str = "default") -> Dict[str, str]:
        row = self.conn.execute("SELECT * FROM user_preferences WHERE user_id = ?", (user_id,)).fetchone()
        if not row:
            return {"user_id": user_id, "brief_time": "08:00", "timezone": "UTC", "delivery_channel": "WhatsApp"}
        return {
            "user_id": row["user_id"],
            "brief_time": row["brief_time"],
            "timezone": row["timezone"],
            "delivery_channel": row["delivery_channel"],
        }

    def get_deal_relationship_depth(self, deal_id: str) -> Dict[str, Any]:
        edge_count = self.conn.execute("SELECT COUNT(*) AS c FROM memory_edges WHERE deal_id = ?", (deal_id,)).fetchone()["c"]
        cmt_count = self.conn.execute("SELECT COUNT(*) AS c FROM commitments WHERE deal_id = ?", (deal_id,)).fetchone()["c"]
        deal = self.conn.execute("SELECT * FROM deals WHERE deal_id = ?", (deal_id,)).fetchone()
        return {
            "interaction_count": int(edge_count + cmt_count),
            "account_name": deal["account_name"] if deal else "there",
            "contact_name": deal["contact_name"] if deal else "there",
            "currency": deal["currency"] if deal else "USD",
        }

"""
Threadlock Usage-Capped Reverse Trial & API Budget Guard (SQLite-backed)
Prevents free-trial abuse and heavy-caller margin bleed by enforcing strict
per-plan audio minute & call caps before invoking Deepgram / LLM APIs.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Dict, Tuple

PLAN_QUOTAS: Dict[str, Dict[str, int]] = {
    "free_trial": {"max_calls": 5, "max_audio_minutes": 150, "max_hud_queries": 120},
    "solo_pro": {"max_calls": 30, "max_audio_minutes": 600, "max_hud_queries": 1000},
    "agency_team": {"max_calls": 80, "max_audio_minutes": 1200, "max_hud_queries": 4000},
}


class UsageQuotaGuard:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS usage_quotas (
                user_id TEXT PRIMARY KEY,
                plan_id TEXT NOT NULL DEFAULT 'free_trial',
                calls_used INTEGER NOT NULL DEFAULT 0,
                audio_minutes_used INTEGER NOT NULL DEFAULT 0,
                hud_queries_used INTEGER NOT NULL DEFAULT 0,
                period_month TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    @staticmethod
    def _current_month() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m")

    def _ensure_user(self, user_id: str, plan_id: str = "free_trial") -> sqlite3.Row:
        month = self._current_month()
        row = self.conn.execute("SELECT * FROM usage_quotas WHERE user_id = ?", (user_id,)).fetchone()
        if not row:
            self.conn.execute(
                "INSERT INTO usage_quotas(user_id, plan_id, calls_used, audio_minutes_used, hud_queries_used, period_month) VALUES (?, ?, 0, 0, 0, ?)",
                (user_id, plan_id, month),
            )
            self.conn.commit()
            return self.conn.execute("SELECT * FROM usage_quotas WHERE user_id = ?", (user_id,)).fetchone()
        if row["period_month"] != month and row["plan_id"] != "free_trial":
            self.conn.execute(
                "UPDATE usage_quotas SET calls_used = 0, audio_minutes_used = 0, hud_queries_used = 0, period_month = ? WHERE user_id = ?",
                (month, user_id),
            )
            self.conn.commit()
            return self.conn.execute("SELECT * FROM usage_quotas WHERE user_id = ?", (user_id,)).fetchone()
        return row

    def set_plan(self, user_id: str, plan_id: str) -> Dict[str, object]:
        if plan_id not in PLAN_QUOTAS:
            raise ValueError(f"Unknown plan: {plan_id}")
        self._ensure_user(user_id, plan_id)
        self.conn.execute("UPDATE usage_quotas SET plan_id = ? WHERE user_id = ?", (plan_id, user_id))
        self.conn.commit()
        return self.get_status(user_id)

    def consume_call_minutes(self, user_id: str, minutes: int, is_new_call: bool = True) -> Tuple[bool, Dict[str, object]]:
        row = self._ensure_user(user_id)
        limits = PLAN_QUOTAS.get(row["plan_id"], PLAN_QUOTAS["free_trial"])
        next_calls = row["calls_used"] + (1 if is_new_call else 0)
        next_mins = row["audio_minutes_used"] + max(0, int(minutes))
        if next_calls > limits["max_calls"] or next_mins > limits["max_audio_minutes"]:
            return False, {
                "allowed": False,
                "reason": f"PLAN_QUOTA_EXCEEDED ({row['plan_id']}): Limit {limits['max_calls']} calls / {limits['max_audio_minutes']} mins.",
                "upgrade_required": True,
                "used": {"calls": row["calls_used"], "audio_minutes": row["audio_minutes_used"]},
                "limits": limits,
            }
        self.conn.execute(
            "UPDATE usage_quotas SET calls_used = ?, audio_minutes_used = ? WHERE user_id = ?",
            (next_calls, next_mins, user_id),
        )
        self.conn.commit()
        return True, self.get_status(user_id)

    def get_status(self, user_id: str) -> Dict[str, object]:
        row = self._ensure_user(user_id)
        limits = PLAN_QUOTAS.get(row["plan_id"], PLAN_QUOTAS["free_trial"])
        return {
            "user_id": user_id,
            "plan_id": row["plan_id"],
            "used": {
                "calls": row["calls_used"],
                "audio_minutes": row["audio_minutes_used"],
                "hud_queries": row["hud_queries_used"],
            },
            "limits": limits,
            "remaining_minutes": max(0, limits["max_audio_minutes"] - row["audio_minutes_used"]),
        }

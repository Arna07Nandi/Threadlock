"""
Threadlock Production LLM Client (Optional ZDR Claude + Multi-Key Gemini Rotation)
Runs deterministically offline when API keys are unset; automatically upgrades to live
Zero-Data-Retention LLM synthesis when ANTHROPIC_API_KEY or GEMINI_API_KEYS is configured.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

import httpx


class ProductionLLMRouter:
    def __init__(self) -> None:
        self.anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        raw_gemini = os.environ.get("GEMINI_API_KEYS", "")
        self.gemini_keys: List[str] = [k.strip() for k in raw_gemini.split(",") if k.strip()]

    @property
    def is_live_enabled(self) -> bool:
        return bool(self.anthropic_key or self.gemini_keys)

    async def extract_structured_json(
        self, system_prompt: str, user_text: str, timeout_s: float = 8.0
    ) -> Optional[Dict[str, Any]]:
        """
        Attempts live structured JSON extraction with automatic key rotation & timeout guards.
        Returns None if offline or rate-limited so the deterministic engine handles it cleanly.
        """
        if self.anthropic_key:
            res = await self._call_anthropic(system_prompt, user_text, timeout_s)
            if res is not None:
                return res

        for key in self.gemini_keys:
            res = await self._call_gemini(key, system_prompt, user_text, timeout_s)
            if res is not None:
                return res

        return None

    async def _call_anthropic(
        self, system_prompt: str, user_text: str, timeout_s: float
    ) -> Optional[Dict[str, Any]]:
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.anthropic_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": os.environ.get("ANTHROPIC_MODEL", "claude-3-5-haiku-latest"),
            "max_tokens": 512,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_text}],
        }
        try:
            async with httpx.AsyncClient(timeout=timeout_s) as client:
                r = await client.post(url, headers=headers, json=payload)
                if r.status_code != 200:
                    return None
                text = r.json()["content"][0]["text"]
                return self._safe_parse_json(text)
        except Exception:
            return None

    async def _call_gemini(
        self, api_key: str, system_prompt: str, user_text: str, timeout_s: float
    ) -> Optional[Dict[str, Any]]:
        model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        payload = {
            "contents": [{"parts": [{"text": f"{system_prompt}\n\nINPUT:\n{user_text}"}]}],
            "generationConfig": {"responseMimeType": "application/json"},
        }
        try:
            async with httpx.AsyncClient(timeout=timeout_s) as client:
                r = await client.post(url, json=payload)
                if r.status_code != 200:
                    return None
                text = r.json()["candidates"][0]["content"]["parts"][0]["text"]
                return self._safe_parse_json(text)
        except Exception:
            return None

    @staticmethod
    def _safe_parse_json(raw: str) -> Optional[Dict[str, Any]]:
        try:
            start = raw.find("{")
            end = raw.rfind("}")
            if start != -1 and end != -1:
                return json.loads(raw[start : end + 1])
            return json.loads(raw)
        except Exception:
            return None

"""
Threadlock Real OAuth 2.0 Connector Engine
Handles real 1-click OAuth 2.0 authorization redirects, cryptographic CSRF state validation,
and authorization-code token exchange for Google (Gmail + Calendar), Slack, HubSpot,
and Meta WhatsApp Business Embedded Signup.
"""
from __future__ import annotations

import os
import secrets
import time
import urllib.parse
from typing import Any, Dict, Optional, Tuple

import httpx

OAUTH_PROVIDERS: Dict[str, Dict[str, str]] = {
    "google": {
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "client_id_env": "GOOGLE_CLIENT_ID",
        "client_secret_env": "GOOGLE_CLIENT_SECRET",
        "scope": "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/calendar.readonly",
    },
    "slack": {
        "auth_url": "https://slack.com/oauth/v2/authorize",
        "token_url": "https://slack.com/api/oauth.v2.access",
        "client_id_env": "SLACK_CLIENT_ID",
        "client_secret_env": "SLACK_CLIENT_SECRET",
        "scope": "channels:history,im:history,chat:write,users:read",
    },
    "hubspot": {
        "auth_url": "https://app.hubspot.com/oauth/authorize",
        "token_url": "https://api.hubapi.com/oauth/v1/token",
        "client_id_env": "HUBSPOT_CLIENT_ID",
        "client_secret_env": "HUBSPOT_CLIENT_SECRET",
        "scope": "crm.objects.deals.read crm.objects.deals.write crm.objects.contacts.read",
    },
    "whatsapp": {
        "auth_url": "https://www.facebook.com/v21.0/dialog/oauth",
        "token_url": "https://graph.facebook.com/v21.0/oauth/access_token",
        "client_id_env": "META_APP_ID",
        "client_secret_env": "META_APP_SECRET",
        "scope": "whatsapp_business_messaging,whatsapp_business_management",
    },
}


class OAuthConnectorManager:
    """Manages CSRF-protected OAuth 2.0 flows and persists connected status."""

    def __init__(self, base_redirect_url: Optional[str] = None) -> None:
        self.base_redirect_url = (
            base_redirect_url or os.environ.get("THREADLOCK_PUBLIC_URL", "http://localhost:8000")
        ).rstrip("/")
        # Maps csrf_state -> (provider, expires_at)
        self._pending_states: Dict[str, Tuple[str, float]] = {}
        self._connected_providers: Dict[str, Dict[str, Any]] = {}

    def build_authorize_url(self, provider: str) -> Dict[str, Any]:
        prov = provider.lower()
        if prov not in OAUTH_PROVIDERS:
            raise ValueError(f"Unsupported OAuth provider: {provider}")
        cfg = OAUTH_PROVIDERS[prov]
        client_id = os.environ.get(cfg["client_id_env"], "").strip()
        state_token = secrets.token_urlsafe(24)
        self._pending_states[state_token] = (prov, time.time() + 600)
        redirect_uri = f"{self.base_redirect_url}/auth/{prov}/callback"

        params = {
            "client_id": client_id or f"CONFIGURE_{cfg['client_id_env']}",
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": cfg["scope"],
            "state": state_token,
        }
        if prov == "google":
            params["access_type"] = "offline"
            params["prompt"] = "consent"

        url = f"{cfg['auth_url']}?{urllib.parse.urlencode(params)}"
        return {
            "provider": prov,
            "configured": bool(client_id),
            "authorize_url": url,
            "redirect_uri": redirect_uri,
            "state": state_token,
        }

    def validate_state(self, provider: str, state_token: str) -> bool:
        entry = self._pending_states.pop(state_token, None)
        if not entry:
            return False
        expected_prov, expires_at = entry
        return expected_prov == provider.lower() and time.time() <= expires_at

    async def exchange_code(self, provider: str, code: str, state_token: str) -> Dict[str, Any]:
        prov = provider.lower()
        if not self.validate_state(prov, state_token):
            raise PermissionError("Invalid or expired OAuth CSRF state token.")
        cfg = OAUTH_PROVIDERS[prov]
        client_id = os.environ.get(cfg["client_id_env"], "").strip()
        client_secret = os.environ.get(cfg["client_secret_env"], "").strip()
        if not client_id or not client_secret:
            raise RuntimeError(f"Set {cfg['client_id_env']} and {cfg['client_secret_env']} in server environment.")

        redirect_uri = f"{self.base_redirect_url}/auth/{prov}/callback"
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(cfg["token_url"], data=data)
            resp.raise_for_status()
            token_data = resp.json()

        self._connected_providers[prov] = {
            "connected_at": int(time.time()),
            "scope": token_data.get("scope", cfg["scope"]),
            "has_refresh_token": bool(token_data.get("refresh_token")),
        }
        return {"provider": prov, "status": "connected", **self._connected_providers[prov]}

    def list_connections(self) -> Dict[str, Any]:
        return {
            p: {
                "configured_on_server": bool(os.environ.get(cfg["client_id_env"], "").strip()),
                "connected": p in self._connected_providers,
            }
            for p, cfg in OAUTH_PROVIDERS.items()
        }

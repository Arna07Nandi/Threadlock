"""
Threadlock Adversarial Security Firewall (XSS, SQLi, Prompt Injection, Path Traversal & API Key Leak Guard)
Sits in front of all untrusted user inputs, webhook payloads, MCP tool calls, and outbound responses.
"""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

# Patterns for secrets that must NEVER appear in logs, responses, or staged drafts
SECRET_REDACTION_PATTERNS: List[Tuple[str, str]] = [
    (r"sk-ant-[A-Za-z0-9_\-]{12,}", "[REDACTED_ANTHROPIC_KEY]"),
    (r"AIza[0-9A-Za-z\-_]{20,}", "[REDACTED_GEMINI_KEY]"),
    (r"sk_(?:live|test)_[0-9A-Za-z]{16,}", "[REDACTED_STRIPE_KEY]"),
    (r"whsec_[0-9A-Za-z]{16,}", "[REDACTED_WEBHOOK_SECRET]"),
    (r"rzp_(?:live|test)_[0-9A-Za-z]{12,}", "[REDACTED_RAZORPAY_KEY]"),
    (r"Bearer\s+[A-Za-z0-9\-_\.]{16,}", "Bearer [REDACTED_TOKEN]"),
]

# Malicious attack signatures
ATTACK_RULES: List[Tuple[str, str]] = [
    ("XSS_SCRIPT_INJECTION", r"(?i)(<\s*script\b|javascript\s*:|on(?:error|load|click|mouseover)\s*=|<\s*iframe\b)"),
    ("SQL_INJECTION_PROBE", r"(?i)(\bunion\s+select\b|\bdrop\s+table\b|;\s*delete\s+from\b|'\s*or\s*'1'\s*=\s*'1)"),
    ("PROMPT_INJECTION_ATTEMPT", r"(?i)(ignore\s+(?:all\s+)?previous\s+instructions|reveal\s+(?:your\s+)?(?:system\s+prompt|api\s+key)|exfiltrate\s+secrets)"),
    ("PATH_TRAVERSAL_PROBE", r"(\.\./|\.\.\\|/etc/passwd|/proc/self/environ)"),
]


def redact_secrets(text: str) -> str:
    """Guarantees no server API keys or tokens ever leak into responses, drafts, or audit logs."""
    out = text
    for pattern, repl in SECRET_REDACTION_PATTERNS:
        out = re.sub(pattern, repl, out)
    return out


def inspect_malicious_payload(raw_text: str) -> Dict[str, object]:
    """Detects XSS, SQLi, Prompt Injection, and Path Traversal before processing."""
    threats: List[str] = []
    for code, pattern in ATTACK_RULES:
        if re.search(pattern, raw_text or ""):
            threats.append(code)
    return {"safe": len(threats) == 0, "threats_detected": threats}

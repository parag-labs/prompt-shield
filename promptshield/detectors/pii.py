"""Outbound PII / secret redaction.

Scans model responses for personal data and secrets before they reach the user
or downstream systems, redacting matches. Regex-based by default (deterministic,
no deps); swap in Presidio/spaCy NER for broader coverage.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

PII_PATTERNS: dict[str, str] = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
    "phone": r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "aws_key": r"AKIA[0-9A-Z]{16}",
    "api_key": r"(?i)(sk|pk|api|secret)[-_][A-Za-z0-9]{16,}",
    "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}


@dataclass
class RedactionResult:
    redacted_text: str
    found: dict[str, int] = field(default_factory=dict)

    @property
    def had_pii(self) -> bool:
        return bool(self.found)


def redact(text: str) -> RedactionResult:
    found: dict[str, int] = {}
    out = text
    for label, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, out)
        if matches:
            found[label] = len(matches)
            out = re.sub(pattern, f"[REDACTED_{label.upper()}]", out)
    return RedactionResult(redacted_text=out, found=found)

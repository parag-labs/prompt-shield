"""PromptShield firewall: middleware wrapping an LLM call.

Inbound: block prompt-injection attempts. Outbound: redact PII/secrets.
Modes: 'block' (raise), 'redact' (sanitize), or 'warn' (annotate only).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from promptshield.detectors.injection import detect_injection
from promptshield.detectors.pii import redact

Mode = Literal["block", "redact", "warn"]


class InjectionBlocked(Exception):
    pass


@dataclass
class ShieldConfig:
    inbound_mode: Mode = "block"
    outbound_mode: Mode = "redact"
    injection_threshold: float = 0.5


@dataclass
class ShieldStats:
    blocked_injections: int = 0
    redacted_responses: int = 0
    pii_counts: dict[str, int] = field(default_factory=dict)


class PromptShield:
    def __init__(self, config: ShieldConfig | None = None):
        self.config = config or ShieldConfig()
        self.stats = ShieldStats()

    def guard(self, prompt: str, llm: Callable[[str], str]) -> str:
        # --- INBOUND ---
        inj = detect_injection(prompt, self.config.injection_threshold)
        if inj.is_injection:
            self.stats.blocked_injections += 1
            if self.config.inbound_mode == "block":
                raise InjectionBlocked(f"injection risk={inj.risk} patterns={inj.matched}")

        response = llm(prompt)

        # --- OUTBOUND ---
        result = redact(response)
        if result.had_pii:
            for k, v in result.found.items():
                self.stats.pii_counts[k] = self.stats.pii_counts.get(k, 0) + v
            if self.config.outbound_mode == "redact":
                self.stats.redacted_responses += 1
                return result.redacted_text
        return response

"""Inbound prompt-injection / jailbreak detection.

Heuristic + pattern-based detector for the most common injection techniques
(OWASP LLM01). Returns a risk score and the patterns that matched. In production,
augment with an embedding-similarity check against a known-attack corpus or a
small fine-tuned classifier -- the interface stays the same.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

INJECTION_PATTERNS = [
    r"(?i)ignore (all |any |the )?(previous |prior |above )?(instructions|prompts|rules)",
    r"(?i)disregard (the |all |any )?(previous |prior )?(above|instructions|rules)",
    r"(?i)you are now (a|an|in) .{0,40}(mode|dan|developer)",
    r"(?i)(reveal|print|show|leak) (your|the) (system|initial) prompt",
    r"(?i)pretend (to be|you are)",
    r"(?i)(jailbreak|bypass) (the|your) (safety|guardrails|filters)",
    r"(?i)act as .{0,30}(unfiltered|uncensored|no restrictions)",
    r"(?i)repeat (everything|the text) (above|before)",
    r"(?i)new (instructions|system prompt)\s*:",
]


@dataclass
class InjectionResult:
    is_injection: bool
    risk: float           # 0..1
    matched: list[str]


def detect_injection(text: str, threshold: float = 0.5) -> InjectionResult:
    # Collapse runs of whitespace so "ignore   previous   instructions" can't slip
    # past patterns written with single spaces. This is a cheap, high-value
    # normalization; heavier obfuscation (letter-spacing, homoglyphs) is out of scope
    # and belongs to an embedding/classifier augmentation.
    normalized = re.sub(r"\s+", " ", text)
    matched = [p for p in INJECTION_PATTERNS if re.search(p, normalized)]
    # Simple risk: saturate quickly as patterns accumulate.
    risk = min(1.0, 0.5 * len(matched) + (0.2 if len(text) > 2000 else 0.0))
    return InjectionResult(is_injection=risk >= threshold, risk=round(risk, 3), matched=matched)

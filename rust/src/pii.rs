//! Outbound PII / secret redaction.
//!
//! [`redact`] scans model responses for personal data and secrets before they
//! reach the user or downstream systems, replacing every match with a labelled
//! placeholder. It is regex-based by default (deterministic, no heavyweight
//! dependencies); swap in Presidio/spaCy NER for broader coverage behind the
//! same interface.

use std::sync::LazyLock;

use regex::{NoExpand, Regex};

struct PiiRule {
    label: &'static str,
    re: Regex,
}

/// The redaction rules, listed in the order they are applied. Order matters:
/// earlier patterns redact first, so e.g. an SSN (3-2-4) is caught before the
/// phone pattern (3-3-4) can consider the same span. Note the per-pattern case
/// sensitivity: `aws_key` is case-sensitive (`AKIA...`) while `api_key` is
/// case-insensitive (`(?i)...`).
const PII_SPECS: [(&str, &str); 7] = [
    ("email", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    ("ssn", r"\b\d{3}-\d{2}-\d{4}\b"),
    ("credit_card", r"\b(?:\d[ -]*?){13,16}\b"),
    (
        "phone",
        r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    ),
    ("aws_key", r"AKIA[0-9A-Z]{16}"),
    ("api_key", r"(?i)(sk|pk|api|secret)[-_][A-Za-z0-9]{16,}"),
    ("ip", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
];

static PII_RULES: LazyLock<Vec<PiiRule>> = LazyLock::new(|| {
    PII_SPECS
        .iter()
        .map(|&(label, pat)| PiiRule {
            label,
            re: Regex::new(pat).expect("built-in PII pattern must compile"),
        })
        .collect()
});

/// The outcome of a single [`redact`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionResult {
    /// The input with every matched secret replaced by a `[REDACTED_LABEL]`
    /// placeholder.
    pub redacted_text: String,
    /// Each PII label that fired paired with the number of matches redacted, in
    /// the order the rules were applied.
    pub found: Vec<(String, usize)>,
}

impl RedactionResult {
    /// Whether any PII or secret was found and redacted.
    pub fn had_pii(&self) -> bool {
        !self.found.is_empty()
    }

    /// The number of matches redacted for `label` (0 if it did not fire).
    pub fn count(&self, label: &str) -> usize {
        self.found
            .iter()
            .find(|(l, _)| l == label)
            .map_or(0, |(_, c)| *c)
    }

    /// The labels that fired, in application order.
    pub fn labels(&self) -> Vec<&str> {
        self.found.iter().map(|(l, _)| l.as_str()).collect()
    }
}

/// Replaces known PII and secret shapes in `text` with labelled placeholders.
///
/// Rules are applied sequentially in declaration order, each operating on the
/// output of the previous one, so overlapping shapes redact deterministically.
/// The placeholders never re-match a rule, so redaction is idempotent.
pub fn redact(text: &str) -> RedactionResult {
    let mut found: Vec<(String, usize)> = Vec::new();
    let mut out = text.to_string();
    for rule in PII_RULES.iter() {
        let count = rule.re.find_iter(&out).count();
        if count > 0 {
            found.push((rule.label.to_string(), count));
            let replacement = format!("[REDACTED_{}]", rule.label.to_uppercase());
            out = rule
                .re
                .replace_all(&out, NoExpand(replacement.as_str()))
                .into_owned();
        }
    }
    RedactionResult {
        redacted_text: out,
        found,
    }
}

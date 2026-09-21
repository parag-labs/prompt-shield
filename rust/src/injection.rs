//! Inbound prompt-injection / jailbreak detection.
//!
//! A heuristic, pattern-based detector for the most common injection techniques
//! (OWASP LLM01). It returns a risk score and the patterns that matched. In
//! production, augment it with an embedding-similarity check against a
//! known-attack corpus or a small fine-tuned classifier -- the interface stays
//! the same.

use std::sync::LazyLock;

use regex::Regex;

/// The injection risk threshold used when a caller does not specify one. A
/// prompt is flagged when its risk is greater than or equal to this value.
pub const DEFAULT_THRESHOLD: f64 = 0.5;

/// The raw, case-insensitive regular-expression strings used to spot common
/// injection and jailbreak phrasings. They are returned verbatim in
/// [`InjectionResult::matched`] so callers can see which signature fired.
pub const INJECTION_PATTERNS: [&str; 9] = [
    r"(?i)ignore (all |any |the )?(previous |prior |above )?(instructions|prompts|rules)",
    r"(?i)disregard (the |all |any )?(previous |prior )?(above|instructions|rules)",
    r"(?i)you are now (a|an|in) .{0,40}(mode|dan|developer)",
    r"(?i)(reveal|print|show|leak) (your|the) (system|initial) prompt",
    r"(?i)pretend (to be|you are)",
    r"(?i)(jailbreak|bypass) (the|your) (safety|guardrails|filters)",
    r"(?i)act as .{0,30}(unfiltered|uncensored|no restrictions)",
    r"(?i)repeat (everything|the text) (above|before)",
    r"(?i)new (instructions|system prompt)\s*:",
];

static INJECTION_REGEXPS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    INJECTION_PATTERNS
        .iter()
        .map(|p| Regex::new(p).expect("built-in injection pattern must compile"))
        .collect()
});

static WHITESPACE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\s+").expect("whitespace pattern must compile"));

/// The outcome of a single [`detect_injection`] call.
#[derive(Debug, Clone, PartialEq)]
pub struct InjectionResult {
    /// Whether the risk met or exceeded the threshold.
    pub is_injection: bool,
    /// The computed risk score in `[0, 1]`, rounded to three decimals.
    pub risk: f64,
    /// The raw pattern strings that fired, in declaration order.
    pub matched: Vec<String>,
}

/// Scores `text` for prompt-injection risk against the built-in signatures.
///
/// Whitespace runs are collapsed to a single space before matching, so
/// `"ignore   previous   instructions"` cannot slip past a pattern written with
/// single spaces. The risk saturates as patterns accumulate (0.5 each) with a
/// small bump for very long inputs, and is capped at 1.0. A prompt is flagged
/// when its risk is greater than or equal to `threshold`.
pub fn detect_injection(text: &str, threshold: f64) -> InjectionResult {
    let normalized = WHITESPACE_RE.replace_all(text, " ");
    let mut matched = Vec::new();
    for (pattern, re) in INJECTION_PATTERNS.iter().zip(INJECTION_REGEXPS.iter()) {
        if re.is_match(&normalized) {
            matched.push((*pattern).to_string());
        }
    }
    let mut risk = 0.5 * matched.len() as f64;
    if text.len() > 2000 {
        risk += 0.2;
    }
    if risk > 1.0 {
        risk = 1.0;
    }
    let is_injection = risk >= threshold;
    let risk = (risk * 1000.0).round() / 1000.0;
    InjectionResult {
        is_injection,
        risk,
        matched,
    }
}

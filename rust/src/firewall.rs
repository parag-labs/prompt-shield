//! PromptShield firewall: middleware wrapping an LLM call.
//!
//! Inbound: block prompt-injection attempts. Outbound: redact PII/secrets.
//! Modes: [`Mode::Block`] (error), [`Mode::Redact`] (sanitize), or
//! [`Mode::Warn`] (annotate only).

use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use crate::injection::{detect_injection, DEFAULT_THRESHOLD};
use crate::pii::redact;

/// How the shield reacts on a given direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Return an [`InjectionBlocked`] error on inbound injection.
    Block,
    /// Sanitize outbound responses (inbound, this only counts the hit).
    Redact,
    /// Annotate/count without blocking or redacting.
    Warn,
}

/// Returned by [`Shield::guard`] when an inbound prompt is flagged as an
/// injection attempt and the inbound mode is [`Mode::Block`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectionBlocked {
    /// A description of the risk score and matched patterns.
    pub message: String,
}

impl fmt::Display for InjectionBlocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for InjectionBlocked {}

/// Controls the shield's inbound/outbound behaviour.
#[derive(Debug, Clone, Copy)]
pub struct ShieldConfig {
    /// How injection attempts are handled.
    pub inbound_mode: Mode,
    /// How PII in responses is handled.
    pub outbound_mode: Mode,
    /// The risk score at or above which a prompt is treated as an injection.
    pub injection_threshold: f64,
}

impl Default for ShieldConfig {
    fn default() -> Self {
        Self {
            inbound_mode: Mode::Block,
            outbound_mode: Mode::Redact,
            injection_threshold: DEFAULT_THRESHOLD,
        }
    }
}

/// Records what the shield has done over its lifetime.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShieldStats {
    /// Prompts flagged as injection (counted in every mode).
    pub blocked_injections: u64,
    /// Responses redacted (redact outbound mode only).
    pub redacted_responses: u64,
    /// Per-label counts of redacted PII, accumulated across calls.
    pub pii_counts: HashMap<String, usize>,
}

/// Drop-in middleware between an app and a model: it blocks injection inbound
/// and redacts PII/secrets outbound while tracking [`ShieldStats`].
#[derive(Debug, Clone, Default)]
pub struct Shield {
    /// The active configuration.
    pub config: ShieldConfig,
    /// The running counters.
    pub stats: ShieldStats,
}

impl Shield {
    /// Builds a shield with the given configuration. Use [`Shield::default`] for
    /// the default block-inbound / redact-outbound policy.
    pub fn new(config: ShieldConfig) -> Self {
        Self {
            config,
            stats: ShieldStats::default(),
        }
    }

    /// Runs `prompt` through inbound injection detection, invokes `llm`, then
    /// runs the response through outbound PII redaction, honouring the
    /// configured modes.
    ///
    /// Inbound: when the prompt is flagged, `blocked_injections` is incremented
    /// in every mode; when the inbound mode is [`Mode::Block`] an
    /// [`InjectionBlocked`] error is returned before `llm` is ever called.
    /// Outbound: when PII is found, `pii_counts` is always accumulated; when the
    /// outbound mode is [`Mode::Redact`] the redacted text is returned and
    /// `redacted_responses` is incremented, otherwise the original response is
    /// returned unchanged.
    pub fn guard<F>(&mut self, prompt: &str, llm: F) -> Result<String, InjectionBlocked>
    where
        F: Fn(&str) -> String,
    {
        let inj = detect_injection(prompt, self.config.injection_threshold);
        if inj.is_injection {
            self.stats.blocked_injections += 1;
            if self.config.inbound_mode == Mode::Block {
                return Err(InjectionBlocked {
                    message: format!("injection risk={} patterns={:?}", inj.risk, inj.matched),
                });
            }
        }

        let response = llm(prompt);

        let result = redact(&response);
        if result.had_pii() {
            for (label, count) in &result.found {
                *self.stats.pii_counts.entry(label.clone()).or_insert(0) += *count;
            }
            if self.config.outbound_mode == Mode::Redact {
                self.stats.redacted_responses += 1;
                return Ok(result.redacted_text);
            }
        }
        Ok(response)
    }
}

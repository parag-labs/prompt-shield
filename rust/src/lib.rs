//! prompt-shield: a firewall for LLM apps.
//!
//! It blocks prompt injection **inbound** and redacts PII/secrets **outbound**,
//! as drop-in middleware between an app and a model. The detectors are
//! regex-based and deterministic by default; swap in a classifier or NER behind
//! the same interface for broader coverage.

pub mod firewall;
pub mod injection;
pub mod pii;

pub use firewall::{InjectionBlocked, Mode, Shield, ShieldConfig, ShieldStats};
pub use injection::{detect_injection, InjectionResult, DEFAULT_THRESHOLD, INJECTION_PATTERNS};
pub use pii::{redact, RedactionResult};

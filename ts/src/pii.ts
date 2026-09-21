// Outbound PII / secret redaction.
//
// `redact` scans model responses for personal data and secrets before they
// reach the user or downstream systems, replacing every match with a labelled
// placeholder. It is regex-based by default (deterministic, no dependencies);
// swap in Presidio/spaCy NER for broader coverage behind the same interface.

import { compilePattern } from "./injection";

/**
 * The redaction rules, listed in the order they are applied. Order matters:
 * earlier patterns redact first, so e.g. an SSN (3-2-4) is caught before the
 * phone pattern (3-3-4) can consider the same span. Note the per-pattern case
 * sensitivity: `aws_key` is case-sensitive (`AKIA...`) while `api_key` carries
 * `(?i)` and is case-insensitive.
 */
export const PII_SPECS: ReadonlyArray<readonly [string, string]> = [
  ["email", String.raw`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`],
  ["ssn", String.raw`\b\d{3}-\d{2}-\d{4}\b`],
  ["credit_card", String.raw`\b(?:\d[ -]*?){13,16}\b`],
  ["phone", String.raw`\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`],
  ["aws_key", String.raw`AKIA[0-9A-Z]{16}`],
  ["api_key", String.raw`(?i)(sk|pk|api|secret)[-_][A-Za-z0-9]{16,}`],
  ["ip", String.raw`\b(?:\d{1,3}\.){3}\d{1,3}\b`],
];

interface PiiRule {
  label: string;
  re: RegExp;
}

const piiRules: readonly PiiRule[] = PII_SPECS.map(([label, pattern]) => ({
  label,
  re: compilePattern(pattern, "g"),
}));

/** The outcome of a single {@link redact} call. */
export interface RedactionResult {
  /** The input with every matched secret replaced by a `[REDACTED_LABEL]` placeholder. */
  redactedText: string;
  /** Each PII label that fired mapped to the number of matches redacted, in application order. */
  found: Record<string, number>;
  /** Whether any PII or secret was found and redacted. */
  hadPii: boolean;
}

/**
 * Replaces known PII and secret shapes in `text` with labelled placeholders.
 *
 * Rules are applied sequentially in declaration order, each operating on the
 * output of the previous one, so overlapping shapes redact deterministically.
 * The placeholders never re-match a rule, so redaction is idempotent.
 */
export function redact(text: string): RedactionResult {
  const found: Record<string, number> = {};
  let out = text;
  for (const rule of piiRules) {
    const matches = out.match(rule.re);
    const count = matches ? matches.length : 0;
    if (count > 0) {
      found[rule.label] = count;
      out = out.replace(rule.re, `[REDACTED_${rule.label.toUpperCase()}]`);
    }
  }
  return { redactedText: out, found, hadPii: Object.keys(found).length > 0 };
}

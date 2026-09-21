// Outbound PII / secret redaction.
//
// Redact scans model responses for personal data and secrets before they reach
// the user or downstream systems, replacing every match with a labelled
// placeholder. It is regex-based by default (deterministic, no dependencies);
// swap in Presidio/spaCy NER for broader coverage behind the same interface.
package promptshield

import (
	"regexp"
	"strings"
)

type piiRule struct {
	label string
	re    *regexp.Regexp
}

// piiSpecs lists the redaction rules in the order they are applied. Order
// matters: earlier patterns redact first, so e.g. an SSN (3-2-4) is caught
// before the phone pattern (3-3-4) can consider the same span. Note the
// per-pattern case sensitivity: aws_key is case-sensitive (AKIA...) while
// api_key is case-insensitive ((?i)...).
var piiSpecs = []struct {
	label   string
	pattern string
}{
	{"email", `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`},
	{"ssn", `\b\d{3}-\d{2}-\d{4}\b`},
	{"credit_card", `\b(?:\d[ -]*?){13,16}\b`},
	{"phone", `\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`},
	{"aws_key", `AKIA[0-9A-Z]{16}`},
	{"api_key", `(?i)(sk|pk|api|secret)[-_][A-Za-z0-9]{16,}`},
	{"ip", `\b(?:\d{1,3}\.){3}\d{1,3}\b`},
}

var piiRules = compilePii(piiSpecs)

func compilePii(specs []struct {
	label   string
	pattern string
}) []piiRule {
	rules := make([]piiRule, len(specs))
	for i, s := range specs {
		rules[i] = piiRule{label: s.label, re: regexp.MustCompile(s.pattern)}
	}
	return rules
}

// RedactionResult is the outcome of a single Redact call.
type RedactionResult struct {
	// RedactedText is the input with every matched secret replaced by a
	// [REDACTED_LABEL] placeholder.
	RedactedText string
	// Found maps each PII label that fired to the number of matches redacted.
	Found map[string]int
}

// HadPII reports whether any PII or secret was found and redacted.
func (r RedactionResult) HadPII() bool {
	return len(r.Found) > 0
}

// Redact replaces known PII and secret shapes in text with labelled
// placeholders. Rules are applied sequentially in declaration order, each
// operating on the output of the previous one, so overlapping shapes redact
// deterministically. The replacement placeholders never re-match a rule, so
// Redact is idempotent.
func Redact(text string) RedactionResult {
	found := map[string]int{}
	out := text
	for _, rule := range piiRules {
		matches := rule.re.FindAllString(out, -1)
		if len(matches) > 0 {
			found[rule.label] = len(matches)
			out = rule.re.ReplaceAllLiteralString(out, "[REDACTED_"+strings.ToUpper(rule.label)+"]")
		}
	}
	return RedactionResult{RedactedText: out, Found: found}
}

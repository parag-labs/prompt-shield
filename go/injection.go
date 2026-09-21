// Package promptshield is a firewall for LLM apps: it blocks prompt injection
// inbound and redacts PII/secrets outbound.
//
// This file implements inbound prompt-injection / jailbreak detection. It is a
// heuristic, pattern-based detector for the most common injection techniques
// (OWASP LLM01). It returns a risk score and the patterns that matched. In
// production, augment it with an embedding-similarity check against a
// known-attack corpus or a small fine-tuned classifier -- the interface stays
// the same.
package promptshield

import (
	"math"
	"regexp"
)

// DefaultThreshold is the injection risk threshold used when a caller does not
// specify one. A prompt is flagged when its risk is greater than or equal to
// this value.
const DefaultThreshold = 0.5

// InjectionPatterns holds the raw, case-insensitive regular-expression strings
// used to spot common injection and jailbreak phrasings. The strings are also
// returned verbatim in InjectionResult.Matched so callers can see exactly which
// signature fired.
var InjectionPatterns = []string{
	`(?i)ignore (all |any |the )?(previous |prior |above )?(instructions|prompts|rules)`,
	`(?i)disregard (the |all |any )?(previous |prior )?(above|instructions|rules)`,
	`(?i)you are now (a|an|in) .{0,40}(mode|dan|developer)`,
	`(?i)(reveal|print|show|leak) (your|the) (system|initial) prompt`,
	`(?i)pretend (to be|you are)`,
	`(?i)(jailbreak|bypass) (the|your) (safety|guardrails|filters)`,
	`(?i)act as .{0,30}(unfiltered|uncensored|no restrictions)`,
	`(?i)repeat (everything|the text) (above|before)`,
	`(?i)new (instructions|system prompt)\s*:`,
}

var injectionRegexps = compileInjection(InjectionPatterns)

var whitespaceRe = regexp.MustCompile(`\s+`)

func compileInjection(patterns []string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}
	return compiled
}

// InjectionResult is the outcome of a single DetectInjection call.
type InjectionResult struct {
	// IsInjection reports whether the risk met or exceeded the threshold.
	IsInjection bool
	// Risk is the computed risk score in [0, 1], rounded to three decimals.
	Risk float64
	// Matched holds the raw pattern strings that fired, in declaration order.
	Matched []string
}

// DetectInjection scores text for prompt-injection risk against the built-in
// signatures. Whitespace runs are collapsed to a single space before matching,
// so "ignore   previous   instructions" cannot slip past a pattern written with
// single spaces. The risk saturates as patterns accumulate (0.5 each) with a
// small bump for very long inputs, and is capped at 1.0. A prompt is flagged
// when its risk is greater than or equal to threshold.
func DetectInjection(text string, threshold float64) InjectionResult {
	normalized := whitespaceRe.ReplaceAllString(text, " ")
	matched := []string{}
	for i, re := range injectionRegexps {
		if re.MatchString(normalized) {
			matched = append(matched, InjectionPatterns[i])
		}
	}
	risk := 0.5 * float64(len(matched))
	if len(text) > 2000 {
		risk += 0.2
	}
	if risk > 1.0 {
		risk = 1.0
	}
	isInjection := risk >= threshold
	risk = math.Round(risk*1000) / 1000
	return InjectionResult{IsInjection: isInjection, Risk: risk, Matched: matched}
}

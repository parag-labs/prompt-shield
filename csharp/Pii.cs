// Outbound PII / secret redaction.
//
// Scans model responses for personal data and secrets before they reach the user or
// downstream systems, redacting matches. Regex-based by default (deterministic, no
// deps); swap in Presidio/spaCy NER for broader coverage.

using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace PromptShield;

public sealed class RedactionResult
{
    public string RedactedText { get; }
    public Dictionary<string, int> Found { get; }

    public RedactionResult(string redactedText, Dictionary<string, int> found)
    {
        RedactedText = redactedText;
        Found = found;
    }

    public bool HadPii => Found.Count > 0;
}

public static class Pii
{
    // Order matters: earlier patterns redact first, so e.g. an SSN (3-2-4) is caught
    // before the phone pattern (3-3-4) can consider the same span.
    public static readonly (string Label, string Pattern)[] Patterns =
    {
        ("email", @"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        ("ssn", @"\b\d{3}-\d{2}-\d{4}\b"),
        ("credit_card", @"\b(?:\d[ -]*?){13,16}\b"),
        ("phone", @"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        ("aws_key", @"AKIA[0-9A-Z]{16}"),
        ("api_key", @"(?i)(sk|pk|api|secret)[-_][A-Za-z0-9]{16,}"),
        ("ip", @"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    };

    public static RedactionResult Redact(string text)
    {
        var found = new Dictionary<string, int>();
        var outText = text;
        foreach (var (label, pattern) in Patterns)
        {
            var matches = Regex.Matches(outText, pattern);
            if (matches.Count > 0)
            {
                found[label] = matches.Count;
                outText = Regex.Replace(outText, pattern, $"[REDACTED_{label.ToUpperInvariant()}]");
            }
        }
        return new RedactionResult(outText, found);
    }
}

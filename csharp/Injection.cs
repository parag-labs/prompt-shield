// Inbound prompt-injection / jailbreak detection.
//
// Heuristic + pattern-based detector for the most common injection techniques
// (OWASP LLM01). Returns a risk score and the patterns that matched. In production,
// augment with an embedding-similarity check against a known-attack corpus or a
// small fine-tuned classifier -- the interface stays the same.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace PromptShield;

public sealed record InjectionResult(bool IsInjection, double Risk, List<string> Matched);

public static class Injection
{
    public static readonly string[] Patterns =
    {
        @"(?i)ignore (all |any |the )?(previous |prior |above )?(instructions|prompts|rules)",
        @"(?i)disregard (the |all |any )?(previous |prior )?(above|instructions|rules)",
        @"(?i)you are now (a|an|in) .{0,40}(mode|dan|developer)",
        @"(?i)(reveal|print|show|leak) (your|the) (system|initial) prompt",
        @"(?i)pretend (to be|you are)",
        @"(?i)(jailbreak|bypass) (the|your) (safety|guardrails|filters)",
        @"(?i)act as .{0,30}(unfiltered|uncensored|no restrictions)",
        @"(?i)repeat (everything|the text) (above|before)",
        @"(?i)new (instructions|system prompt)\s*:",
    };

    public static InjectionResult Detect(string text, double threshold = 0.5)
    {
        // Collapse runs of whitespace so "ignore   previous   instructions" can't slip
        // past patterns written with single spaces. Heavier obfuscation (letter-
        // spacing, homoglyphs) is out of scope and belongs to a classifier augmentation.
        var normalized = Regex.Replace(text, @"\s+", " ");
        var matched = Patterns.Where(p => Regex.IsMatch(normalized, p)).ToList();
        // Simple risk: saturate quickly as patterns accumulate.
        var risk = Math.Min(1.0, 0.5 * matched.Count + (text.Length > 2000 ? 0.2 : 0.0));
        risk = Math.Round(risk, 3);
        return new InjectionResult(risk >= threshold, risk, matched);
    }
}

// Inbound prompt-injection / jailbreak detection.
//
// Heuristic + pattern-based detector for the most common injection techniques
// (OWASP LLM01). Returns a risk score and the patterns that matched. In production,
// augment with an embedding-similarity check against a known-attack corpus or a
// small fine-tuned classifier -- the interface stays the same.

package com.promptshield;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public final class Injection {

    private Injection() {}

    public static final List<Pattern> PATTERNS = List.of(
        Pattern.compile("(?i)ignore (all |any |the )?(previous |prior |above )?(instructions|prompts|rules)"),
        Pattern.compile("(?i)disregard (the |all |any )?(previous |prior )?(above|instructions|rules)"),
        Pattern.compile("(?i)you are now (a|an|in) .{0,40}(mode|dan|developer)"),
        Pattern.compile("(?i)(reveal|print|show|leak) (your|the) (system|initial) prompt"),
        Pattern.compile("(?i)pretend (to be|you are)"),
        Pattern.compile("(?i)(jailbreak|bypass) (the|your) (safety|guardrails|filters)"),
        Pattern.compile("(?i)act as .{0,30}(unfiltered|uncensored|no restrictions)"),
        Pattern.compile("(?i)repeat (everything|the text) (above|before)"),
        Pattern.compile("(?i)new (instructions|system prompt)\\s*:")
    );

    public record Result(boolean isInjection, double risk, List<String> matched) {}

    public static Result detect(String text) {
        return detect(text, 0.5);
    }

    public static Result detect(String text, double threshold) {
        // Collapse runs of whitespace so "ignore   previous   instructions" can't slip
        // past patterns written with single spaces. Heavier obfuscation (letter-
        // spacing, homoglyphs) is out of scope and belongs to a classifier augmentation.
        String normalized = text.replaceAll("\\s+", " ");
        List<String> matched = new ArrayList<>();
        for (Pattern p : PATTERNS) {
            if (p.matcher(normalized).find()) matched.add(p.pattern());
        }
        // Simple risk: saturate quickly as patterns accumulate.
        double risk = Math.min(1.0, 0.5 * matched.size() + (text.length() > 2000 ? 0.2 : 0.0));
        risk = Math.round(risk * 1000.0) / 1000.0;
        return new Result(risk >= threshold, risk, matched);
    }
}

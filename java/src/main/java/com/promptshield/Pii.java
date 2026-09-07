// Outbound PII / secret redaction.
//
// Scans model responses for personal data and secrets before they reach the user or
// downstream systems, redacting matches. Regex-based by default (deterministic, no
// deps); swap in Presidio/spaCy NER for broader coverage.

package com.promptshield;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class Pii {

    private Pii() {}

    private record Rule(String label, Pattern pattern) {}

    // Order matters: earlier patterns redact first, so e.g. an SSN (3-2-4) is caught
    // before the phone pattern (3-3-4) can consider the same span.
    private static final Rule[] RULES = {
        new Rule("email", Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")),
        new Rule("ssn", Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b")),
        new Rule("credit_card", Pattern.compile("\\b(?:\\d[ -]*?){13,16}\\b")),
        new Rule("phone", Pattern.compile("\\b(?:\\+?1[-.\\s]?)?\\(?\\d{3}\\)?[-.\\s]?\\d{3}[-.\\s]?\\d{4}\\b")),
        new Rule("aws_key", Pattern.compile("AKIA[0-9A-Z]{16}")),
        new Rule("api_key", Pattern.compile("(?i)(sk|pk|api|secret)[-_][A-Za-z0-9]{16,}")),
        new Rule("ip", Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")),
    };

    public static final class Result {
        public final String redactedText;
        public final Map<String, Integer> found;

        Result(String redactedText, Map<String, Integer> found) {
            this.redactedText = redactedText;
            this.found = found;
        }

        public boolean hadPii() {
            return !found.isEmpty();
        }
    }

    public static Result redact(String text) {
        Map<String, Integer> found = new LinkedHashMap<>();
        String out = text;
        for (Rule rule : RULES) {
            Matcher m = rule.pattern().matcher(out);
            int count = 0;
            while (m.find()) count++;
            if (count > 0) {
                found.put(rule.label(), count);
                out = rule.pattern().matcher(out)
                    .replaceAll("[REDACTED_" + rule.label().toUpperCase() + "]");
            }
        }
        return new Result(out, found);
    }
}

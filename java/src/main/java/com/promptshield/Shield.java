// PromptShield firewall: middleware wrapping an LLM call.
//
// Inbound: block prompt-injection attempts. Outbound: redact PII/secrets.
// Modes: BLOCK (raise), REDACT (sanitize), or WARN (annotate only).

package com.promptshield;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public final class Shield {

    public enum Mode { BLOCK, REDACT, WARN }

    public static final class InjectionBlocked extends RuntimeException {
        public InjectionBlocked(String message) { super(message); }
    }

    public static final class Config {
        public final Mode inboundMode;
        public final Mode outboundMode;
        public final double injectionThreshold;

        public Config() {
            this(Mode.BLOCK, Mode.REDACT, 0.5);
        }

        public Config(Mode inboundMode, Mode outboundMode, double injectionThreshold) {
            this.inboundMode = inboundMode;
            this.outboundMode = outboundMode;
            this.injectionThreshold = injectionThreshold;
        }
    }

    public static final class Stats {
        public int blockedInjections = 0;
        public int redactedResponses = 0;
        public final Map<String, Integer> piiCounts = new HashMap<>();
    }

    public final Config config;
    public final Stats stats = new Stats();

    public Shield() {
        this(new Config());
    }

    public Shield(Config config) {
        this.config = config;
    }

    public String guard(String prompt, Function<String, String> llm) {
        // --- INBOUND ---
        Injection.Result inj = Injection.detect(prompt, config.injectionThreshold);
        if (inj.isInjection()) {
            stats.blockedInjections++;
            if (config.inboundMode == Mode.BLOCK) {
                throw new InjectionBlocked("injection risk=" + inj.risk() + " patterns=" + inj.matched());
            }
        }

        String response = llm.apply(prompt);

        // --- OUTBOUND ---
        Pii.Result result = Pii.redact(response);
        if (result.hadPii()) {
            for (Map.Entry<String, Integer> e : result.found.entrySet()) {
                stats.piiCounts.merge(e.getKey(), e.getValue(), Integer::sum);
            }
            if (config.outboundMode == Mode.REDACT) {
                stats.redactedResponses++;
                return result.redactedText;
            }
        }
        return response;
    }
}

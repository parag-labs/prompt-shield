// PromptShield firewall: middleware wrapping an LLM call.
//
// Inbound: block prompt-injection attempts. Outbound: redact PII/secrets.
// Modes: "block" (throw), "redact" (sanitize), or "warn" (annotate only).

import { DEFAULT_THRESHOLD, detectInjection } from "./injection";
import { redact } from "./pii";

/** How the shield reacts on a given direction. */
export type Mode = "block" | "redact" | "warn";

/**
 * Thrown by {@link Shield.guard} when an inbound prompt is flagged as an
 * injection attempt and the inbound mode is `"block"`.
 */
export class InjectionBlocked extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InjectionBlocked";
  }
}

/** Controls the shield's inbound/outbound behaviour. */
export interface ShieldConfig {
  /** How injection attempts are handled. */
  inboundMode: Mode;
  /** How PII in responses is handled. */
  outboundMode: Mode;
  /** The risk score at or above which a prompt is treated as an injection. */
  injectionThreshold: number;
}

/** The default configuration: block inbound, redact outbound, default threshold. */
export function defaultConfig(): ShieldConfig {
  return {
    inboundMode: "block",
    outboundMode: "redact",
    injectionThreshold: DEFAULT_THRESHOLD,
  };
}

/** Records what the shield has done over its lifetime. */
export interface ShieldStats {
  /** Prompts flagged as injection (counted in every mode). */
  blockedInjections: number;
  /** Responses redacted (redact outbound mode only). */
  redactedResponses: number;
  /** Per-label counts of redacted PII, accumulated across calls. */
  piiCounts: Record<string, number>;
}

/** A synchronous model call: takes a prompt, returns a response. */
export type Llm = (prompt: string) => string;

/**
 * Drop-in middleware between an app and a model: it blocks injection inbound and
 * redacts PII/secrets outbound while tracking {@link ShieldStats}.
 */
export class Shield {
  readonly config: ShieldConfig;
  readonly stats: ShieldStats;

  constructor(config: Partial<ShieldConfig> = {}) {
    this.config = { ...defaultConfig(), ...config };
    this.stats = {
      blockedInjections: 0,
      redactedResponses: 0,
      piiCounts: {},
    };
  }

  /**
   * Runs `prompt` through inbound injection detection, invokes `llm`, then runs
   * the response through outbound PII redaction, honouring the configured modes.
   *
   * Inbound: when the prompt is flagged, `blockedInjections` is incremented in
   * every mode; when the inbound mode is `"block"` an {@link InjectionBlocked}
   * error is thrown before `llm` is ever called. Outbound: when PII is found,
   * `piiCounts` is always accumulated; when the outbound mode is `"redact"` the
   * redacted text is returned and `redactedResponses` is incremented, otherwise
   * the original response is returned unchanged.
   */
  guard(prompt: string, llm: Llm): string {
    const inj = detectInjection(prompt, this.config.injectionThreshold);
    if (inj.isInjection) {
      this.stats.blockedInjections += 1;
      if (this.config.inboundMode === "block") {
        throw new InjectionBlocked(
          `injection risk=${inj.risk} patterns=${JSON.stringify(inj.matched)}`,
        );
      }
    }

    const response = llm(prompt);

    const result = redact(response);
    if (result.hadPii) {
      for (const [label, count] of Object.entries(result.found)) {
        this.stats.piiCounts[label] = (this.stats.piiCounts[label] ?? 0) + count;
      }
      if (this.config.outboundMode === "redact") {
        this.stats.redactedResponses += 1;
        return result.redactedText;
      }
    }
    return response;
  }
}

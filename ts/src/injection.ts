// Inbound prompt-injection / jailbreak detection.
//
// A heuristic, pattern-based detector for the most common injection techniques
// (OWASP LLM01). It returns a risk score and the patterns that matched. In
// production, augment it with an embedding-similarity check against a
// known-attack corpus or a small fine-tuned classifier -- the interface stays
// the same.

/**
 * The injection risk threshold used when a caller does not specify one. A prompt
 * is flagged when its risk is greater than or equal to this value.
 */
export const DEFAULT_THRESHOLD = 0.5;

/**
 * The raw, case-insensitive pattern strings used to spot common injection and
 * jailbreak phrasings. They are returned verbatim in {@link InjectionResult.matched}
 * so callers can see which signature fired.
 *
 * The strings carry a leading `(?i)` for parity with the Python/C#/Java ports;
 * JavaScript's `RegExp` cannot parse an inline flag, so {@link compilePattern}
 * strips it and applies the `i` flag instead. The reported strings stay
 * byte-identical across all six languages.
 */
export const INJECTION_PATTERNS: readonly string[] = [
  String.raw`(?i)ignore (all |any |the )?(previous |prior |above )?(instructions|prompts|rules)`,
  String.raw`(?i)disregard (the |all |any )?(previous |prior )?(above|instructions|rules)`,
  String.raw`(?i)you are now (a|an|in) .{0,40}(mode|dan|developer)`,
  String.raw`(?i)(reveal|print|show|leak) (your|the) (system|initial) prompt`,
  String.raw`(?i)pretend (to be|you are)`,
  String.raw`(?i)(jailbreak|bypass) (the|your) (safety|guardrails|filters)`,
  String.raw`(?i)act as .{0,30}(unfiltered|uncensored|no restrictions)`,
  String.raw`(?i)repeat (everything|the text) (above|before)`,
  String.raw`(?i)new (instructions|system prompt)\s*:`,
];

/**
 * Compiles a Python-style pattern into a JavaScript `RegExp`. A leading `(?i)`
 * inline flag (unsupported by `RegExp`) is stripped and translated into the `i`
 * flag; `baseFlags` are always applied. This keeps per-pattern case sensitivity
 * identical to the reference implementation.
 */
export function compilePattern(pattern: string, baseFlags: string): RegExp {
  let body = pattern;
  let flags = baseFlags;
  if (body.startsWith("(?i)")) {
    body = body.slice(4);
    if (!flags.includes("i")) {
      flags += "i";
    }
  }
  return new RegExp(body, flags);
}

const injectionRegexps: readonly RegExp[] = INJECTION_PATTERNS.map((p) =>
  compilePattern(p, ""),
);

const whitespaceRe = /\s+/g;

/** The outcome of a single {@link detectInjection} call. */
export interface InjectionResult {
  /** Whether the risk met or exceeded the threshold. */
  isInjection: boolean;
  /** The computed risk score in `[0, 1]`, rounded to three decimals. */
  risk: number;
  /** The raw pattern strings that fired, in declaration order. */
  matched: string[];
}

/**
 * Scores `text` for prompt-injection risk against the built-in signatures.
 *
 * Whitespace runs are collapsed to a single space before matching, so
 * `"ignore   previous   instructions"` cannot slip past a pattern written with
 * single spaces. The risk saturates as patterns accumulate (0.5 each) with a
 * small bump for very long inputs, and is capped at 1.0. A prompt is flagged
 * when its risk is greater than or equal to `threshold`.
 */
export function detectInjection(
  text: string,
  threshold: number = DEFAULT_THRESHOLD,
): InjectionResult {
  const normalized = text.replace(whitespaceRe, " ");
  const matched: string[] = [];
  injectionRegexps.forEach((re, i) => {
    if (re.test(normalized)) {
      matched.push(INJECTION_PATTERNS[i]);
    }
  });
  let risk = 0.5 * matched.length;
  if (text.length > 2000) {
    risk += 0.2;
  }
  if (risk > 1.0) {
    risk = 1.0;
  }
  const isInjection = risk >= threshold;
  risk = Math.round(risk * 1000) / 1000;
  return { isInjection, risk, matched };
}

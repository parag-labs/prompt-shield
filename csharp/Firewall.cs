// PromptShield firewall: middleware wrapping an LLM call.
//
// Inbound: block prompt-injection attempts. Outbound: redact PII/secrets.
// Modes: Block (raise), Redact (sanitize), or Warn (annotate only).

using System;
using System.Collections.Generic;

namespace PromptShield;

public enum Mode { Block, Redact, Warn }

public sealed class InjectionBlocked : Exception
{
    public InjectionBlocked(string message) : base(message) { }
}

public sealed class ShieldConfig
{
    public Mode InboundMode { get; init; } = Mode.Block;
    public Mode OutboundMode { get; init; } = Mode.Redact;
    public double InjectionThreshold { get; init; } = 0.5;
}

public sealed class ShieldStats
{
    public int BlockedInjections { get; set; }
    public int RedactedResponses { get; set; }
    public Dictionary<string, int> PiiCounts { get; } = new();
}

public sealed class Shield
{
    public ShieldConfig Config { get; }
    public ShieldStats Stats { get; } = new();

    public Shield(ShieldConfig? config = null) => Config = config ?? new ShieldConfig();

    public string Guard(string prompt, Func<string, string> llm)
    {
        // --- INBOUND ---
        var inj = Injection.Detect(prompt, Config.InjectionThreshold);
        if (inj.IsInjection)
        {
            Stats.BlockedInjections++;
            if (Config.InboundMode == Mode.Block)
                throw new InjectionBlocked($"injection risk={inj.Risk} patterns=[{string.Join(", ", inj.Matched)}]");
        }

        var response = llm(prompt);

        // --- OUTBOUND ---
        var result = Pii.Redact(response);
        if (result.HadPii)
        {
            foreach (var (k, v) in result.Found)
                Stats.PiiCounts[k] = Stats.PiiCounts.GetValueOrDefault(k) + v;
            if (Config.OutboundMode == Mode.Redact)
            {
                Stats.RedactedResponses++;
                return result.RedactedText;
            }
        }
        return response;
    }
}

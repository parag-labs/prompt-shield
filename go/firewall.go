// PromptShield firewall: middleware wrapping an LLM call.
//
// Inbound: block prompt-injection attempts. Outbound: redact PII/secrets.
// Modes: block (raise), redact (sanitize), or warn (annotate only).
package promptshield

import "fmt"

// Mode selects how the shield reacts on a given direction.
type Mode string

const (
	// ModeBlock raises an InjectionBlocked error on inbound injection.
	ModeBlock Mode = "block"
	// ModeRedact sanitizes outbound responses (and, inbound, only counts).
	ModeRedact Mode = "redact"
	// ModeWarn annotates/counts without blocking or redacting.
	ModeWarn Mode = "warn"
)

// InjectionBlocked is returned by Guard when an inbound prompt is flagged as an
// injection attempt and the inbound mode is ModeBlock.
type InjectionBlocked struct {
	// Message describes the risk score and matched patterns.
	Message string
}

// Error implements the error interface.
func (e *InjectionBlocked) Error() string {
	return e.Message
}

// ShieldConfig controls the shield's inbound/outbound behaviour.
type ShieldConfig struct {
	// InboundMode selects how injection attempts are handled.
	InboundMode Mode
	// OutboundMode selects how PII in responses is handled.
	OutboundMode Mode
	// InjectionThreshold is the risk score at or above which a prompt is
	// treated as an injection attempt.
	InjectionThreshold float64
}

// DefaultConfig returns the default configuration: block inbound, redact
// outbound, and the default injection threshold.
func DefaultConfig() ShieldConfig {
	return ShieldConfig{
		InboundMode:        ModeBlock,
		OutboundMode:       ModeRedact,
		InjectionThreshold: DefaultThreshold,
	}
}

// ShieldStats records what the shield has done over its lifetime.
type ShieldStats struct {
	// BlockedInjections counts prompts flagged as injection (in every mode).
	BlockedInjections int
	// RedactedResponses counts responses redacted (redact outbound mode only).
	RedactedResponses int
	// PIICounts accumulates per-label counts of redacted PII.
	PIICounts map[string]int
}

// Shield is drop-in middleware between an app and a model: it blocks injection
// inbound and redacts PII/secrets outbound while tracking stats.
type Shield struct {
	// Config is the active configuration.
	Config ShieldConfig
	// Stats holds the running counters.
	Stats *ShieldStats
}

// NewShield builds a Shield. Pass a ShieldConfig to override the defaults;
// call it with no arguments to use DefaultConfig.
func NewShield(config ...ShieldConfig) *Shield {
	cfg := DefaultConfig()
	if len(config) > 0 {
		cfg = config[0]
	}
	return &Shield{
		Config: cfg,
		Stats:  &ShieldStats{PIICounts: map[string]int{}},
	}
}

// Guard runs prompt through inbound injection detection, invokes llm, then runs
// the response through outbound PII redaction, honouring the configured modes.
//
// Inbound: when the prompt is flagged, BlockedInjections is incremented in every
// mode; when the inbound mode is ModeBlock, an *InjectionBlocked error is
// returned before llm is ever called. Outbound: when PII is found, PIICounts is
// always accumulated; when the outbound mode is ModeRedact, the redacted text is
// returned and RedactedResponses is incremented, otherwise the original response
// is returned unchanged.
func (s *Shield) Guard(prompt string, llm func(string) string) (string, error) {
	inj := DetectInjection(prompt, s.Config.InjectionThreshold)
	if inj.IsInjection {
		s.Stats.BlockedInjections++
		if s.Config.InboundMode == ModeBlock {
			return "", &InjectionBlocked{
				Message: fmt.Sprintf("injection risk=%v patterns=%v", inj.Risk, inj.Matched),
			}
		}
	}

	response := llm(prompt)

	result := Redact(response)
	if result.HadPII() {
		for k, v := range result.Found {
			s.Stats.PIICounts[k] += v
		}
		if s.Config.OutboundMode == ModeRedact {
			s.Stats.RedactedResponses++
			return result.RedactedText, nil
		}
	}
	return response, nil
}

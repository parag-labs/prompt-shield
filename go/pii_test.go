package promptshield

import (
	"strings"
	"testing"
)

func TestRedactsEmail(t *testing.T) {
	r := Redact("Contact me at john.doe@example.com please")
	if !r.HadPII() {
		t.Fatal("expected PII to be found")
	}
	if strings.Contains(r.RedactedText, "john.doe@example.com") {
		t.Fatal("email should have been redacted")
	}
	if !strings.Contains(r.RedactedText, "[REDACTED_EMAIL]") {
		t.Fatalf("expected placeholder, got %q", r.RedactedText)
	}
	if r.Found["email"] != 1 {
		t.Fatalf("expected email count 1, got %d", r.Found["email"])
	}
}

func TestRedactsMixedPii(t *testing.T) {
	r := Redact("Contact me at john.doe@example.com or 555-123-4567, SSN 123-45-6789")
	if !r.HadPII() {
		t.Fatal("expected PII to be found")
	}
	if strings.Contains(r.RedactedText, "john.doe@example.com") {
		t.Fatal("email should have been redacted")
	}
	if _, ok := r.Found["ssn"]; !ok {
		t.Fatalf("expected ssn in found, got %v", r.Found)
	}
	if _, ok := r.Found["phone"]; !ok {
		t.Fatalf("expected phone in found, got %v", r.Found)
	}
}

func TestRedactsSSN(t *testing.T) {
	r := Redact("my ssn is 123-45-6789 ok")
	if r.Found["ssn"] != 1 || strings.Contains(r.RedactedText, "123-45-6789") {
		t.Fatalf("ssn not redacted: %+v", r)
	}
}

func TestRedactsCreditCard(t *testing.T) {
	r := Redact("card 4111 1111 1111 1111 charged")
	if r.Found["credit_card"] != 1 || strings.Contains(r.RedactedText, "4111 1111 1111 1111") {
		t.Fatalf("credit card not redacted: %+v", r)
	}
}

func TestRedactsPhone(t *testing.T) {
	r := Redact("call 415-555-1212 now")
	if r.Found["phone"] != 1 || strings.Contains(r.RedactedText, "415-555-1212") {
		t.Fatalf("phone not redacted: %+v", r)
	}
}

func TestRedactsAwsKey(t *testing.T) {
	r := Redact("key AKIAABCDEFGHIJKLMNOP end")
	if r.Found["aws_key"] != 1 || strings.Contains(r.RedactedText, "AKIAABCDEFGHIJKLMNOP") {
		t.Fatalf("aws key not redacted: %+v", r)
	}
}

func TestAwsKeyIsCaseSensitive(t *testing.T) {
	// aws_key has no (?i) flag, so a lowercase "akia..." must NOT be redacted.
	r := Redact("key akiaabcdefghijklmnop end")
	if r.HadPII() {
		t.Fatalf("lowercase akia should not match aws_key, got %v", r.Found)
	}
}

func TestRedactsApiKey(t *testing.T) {
	r := Redact("token sk-abcdef0123456789abcdef01 here")
	if r.Found["api_key"] != 1 || strings.Contains(r.RedactedText, "sk-abcdef0123456789abcdef01") {
		t.Fatalf("api key not redacted: %+v", r)
	}
}

func TestApiKeyIsCaseInsensitive(t *testing.T) {
	// api_key has (?i), so an uppercase "SK-..." prefix must still be redacted.
	r := Redact("token SK-ABCDEF0123456789ABCDEF01 here")
	if r.Found["api_key"] != 1 {
		t.Fatalf("uppercase SK- api key should be redacted, got %v", r.Found)
	}
}

func TestRedactsIP(t *testing.T) {
	r := Redact("host at 192.168.1.100 responded")
	if r.Found["ip"] != 1 || strings.Contains(r.RedactedText, "192.168.1.100") {
		t.Fatalf("ip not redacted: %+v", r)
	}
}

func TestMultipleSecretsInOneMessageAreAllRedacted(t *testing.T) {
	text := "mail me at a@b.com or call 415-555-1212, card 4111 1111 1111 1111"
	r := Redact(text)
	for _, secret := range []string{"a@b.com", "415-555-1212", "4111 1111 1111 1111"} {
		if strings.Contains(r.RedactedText, secret) {
			t.Errorf("secret survived redaction: %q", secret)
		}
	}
	for _, label := range []string{"email", "phone", "credit_card"} {
		if _, ok := r.Found[label]; !ok {
			t.Errorf("expected %q in found, got %v", label, r.Found)
		}
	}
}

func TestCleanTextIsLeftUntouched(t *testing.T) {
	text := "This is a perfectly ordinary sentence with no secrets in it."
	r := Redact(text)
	if r.RedactedText != text {
		t.Fatalf("clean text was modified: %q", r.RedactedText)
	}
	if r.HadPII() {
		t.Fatalf("clean text reported PII: %v", r.Found)
	}
}

func TestRedactionIsIdempotent(t *testing.T) {
	once := Redact("reach me at a@b.com").RedactedText
	twice := Redact(once).RedactedText
	if once != twice {
		t.Fatalf("redaction not idempotent: %q vs %q", once, twice)
	}
}

func TestEmptyInputHasNoPii(t *testing.T) {
	r := Redact("")
	if r.HadPII() || r.RedactedText != "" {
		t.Fatalf("empty input should have no PII, got %+v", r)
	}
}

func TestSecretsAreAlwaysRedactedEvenBuriedInNoise(t *testing.T) {
	filler := strings.Repeat("the quick brown fox jumps over the lazy dog ", 5)
	secrets := []struct{ label, secret string }{
		{"email", "attacker@evil.com"},
		{"ssn", "123-45-6789"},
		{"aws_key", "AKIAABCDEFGHIJKLMNOP"},
		{"api_key", "sk-abcdef0123456789abcdef01"},
	}
	for i := 0; i < 1000; i++ {
		sec := secrets[i%len(secrets)]
		cut := (i * 7) % (len(filler) + 1)
		text := filler[:cut] + " " + sec.secret + " " + filler[cut:]
		r := Redact(text)
		if strings.Contains(r.RedactedText, sec.secret) {
			t.Fatalf("iteration %d: %s secret survived: %q", i, sec.label, sec.secret)
		}
		if !r.HadPII() {
			t.Fatalf("iteration %d: %s not flagged", i, sec.label)
		}
	}
}

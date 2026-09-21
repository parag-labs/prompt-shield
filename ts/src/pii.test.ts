import { describe, expect, it } from "vitest";

import { redact } from "./pii";

describe("redact", () => {
  it("redacts an email", () => {
    const r = redact("Contact me at john.doe@example.com please");
    expect(r.hadPii).toBe(true);
    expect(r.redactedText).not.toContain("john.doe@example.com");
    expect(r.redactedText).toContain("[REDACTED_EMAIL]");
    expect(r.found.email).toBe(1);
  });

  it("redacts mixed PII and records the labels", () => {
    const r = redact(
      "Contact me at john.doe@example.com or 555-123-4567, SSN 123-45-6789",
    );
    expect(r.hadPii).toBe(true);
    expect(r.redactedText).not.toContain("john.doe@example.com");
    expect(r.found).toHaveProperty("ssn");
    expect(r.found).toHaveProperty("phone");
  });

  it("redacts an SSN", () => {
    const r = redact("my ssn is 123-45-6789 ok");
    expect(r.found.ssn).toBe(1);
    expect(r.redactedText).not.toContain("123-45-6789");
  });

  it("redacts a credit card", () => {
    const r = redact("card 4111 1111 1111 1111 charged");
    expect(r.found.credit_card).toBe(1);
    expect(r.redactedText).not.toContain("4111 1111 1111 1111");
  });

  it("redacts a phone number", () => {
    const r = redact("call 415-555-1212 now");
    expect(r.found.phone).toBe(1);
    expect(r.redactedText).not.toContain("415-555-1212");
  });

  it("redacts an AWS key", () => {
    const r = redact("key AKIAABCDEFGHIJKLMNOP end");
    expect(r.found.aws_key).toBe(1);
    expect(r.redactedText).not.toContain("AKIAABCDEFGHIJKLMNOP");
  });

  it("treats aws_key as case-sensitive (lowercase is not redacted)", () => {
    // aws_key has no (?i) flag, so a lowercase "akia..." must NOT be redacted.
    const r = redact("key akiaabcdefghijklmnop end");
    expect(r.hadPii).toBe(false);
  });

  it("redacts an API key", () => {
    const r = redact("token sk-abcdef0123456789abcdef01 here");
    expect(r.found.api_key).toBe(1);
    expect(r.redactedText).not.toContain("sk-abcdef0123456789abcdef01");
  });

  it("treats api_key as case-insensitive (uppercase SK- is redacted)", () => {
    // api_key has (?i), so an uppercase "SK-..." prefix must still be redacted.
    const r = redact("token SK-ABCDEF0123456789ABCDEF01 here");
    expect(r.found.api_key).toBe(1);
  });

  it("redacts an IP address", () => {
    const r = redact("host at 192.168.1.100 responded");
    expect(r.found.ip).toBe(1);
    expect(r.redactedText).not.toContain("192.168.1.100");
  });

  it("redacts every secret in a multi-secret message", () => {
    const text = "mail me at a@b.com or call 415-555-1212, card 4111 1111 1111 1111";
    const r = redact(text);
    for (const secret of ["a@b.com", "415-555-1212", "4111 1111 1111 1111"]) {
      expect(r.redactedText, `secret survived: ${secret}`).not.toContain(secret);
    }
    for (const label of ["email", "phone", "credit_card"]) {
      expect(r.found).toHaveProperty(label);
    }
  });

  it("leaves clean text untouched", () => {
    const text = "This is a perfectly ordinary sentence with no secrets in it.";
    const r = redact(text);
    expect(r.redactedText).toBe(text);
    expect(r.hadPii).toBe(false);
  });

  it("is idempotent", () => {
    const once = redact("reach me at a@b.com").redactedText;
    const twice = redact(once).redactedText;
    expect(twice).toBe(once);
  });

  it("finds no PII in empty input", () => {
    const r = redact("");
    expect(r.hadPii).toBe(false);
    expect(r.redactedText).toBe("");
  });

  it("always redacts secrets even buried in noise", () => {
    const filler = "the quick brown fox jumps over the lazy dog ".repeat(5);
    const secrets: ReadonlyArray<readonly [string, string]> = [
      ["email", "attacker@evil.com"],
      ["ssn", "123-45-6789"],
      ["aws_key", "AKIAABCDEFGHIJKLMNOP"],
      ["api_key", "sk-abcdef0123456789abcdef01"],
    ];
    for (let i = 0; i < 1000; i++) {
      const [label, secret] = secrets[i % secrets.length];
      const cut = (i * 7) % (filler.length + 1);
      const text = `${filler.slice(0, cut)} ${secret} ${filler.slice(cut)}`;
      const r = redact(text);
      expect(r.redactedText, `iteration ${i}: ${label} survived`).not.toContain(
        secret,
      );
      expect(r.hadPii, `iteration ${i}: ${label} not flagged`).toBe(true);
    }
  });
});

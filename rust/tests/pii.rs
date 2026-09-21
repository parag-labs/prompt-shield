use prompt_shield::redact;

#[test]
fn redacts_email() {
    let r = redact("Contact me at john.doe@example.com please");
    assert!(r.had_pii());
    assert!(!r.redacted_text.contains("john.doe@example.com"));
    assert!(r.redacted_text.contains("[REDACTED_EMAIL]"));
    assert_eq!(r.count("email"), 1);
}

#[test]
fn redacts_mixed_pii() {
    let r = redact("Contact me at john.doe@example.com or 555-123-4567, SSN 123-45-6789");
    assert!(r.had_pii());
    assert!(!r.redacted_text.contains("john.doe@example.com"));
    assert!(r.labels().contains(&"ssn"));
    assert!(r.labels().contains(&"phone"));
}

#[test]
fn redacts_ssn() {
    let r = redact("my ssn is 123-45-6789 ok");
    assert_eq!(r.count("ssn"), 1);
    assert!(!r.redacted_text.contains("123-45-6789"));
}

#[test]
fn redacts_credit_card() {
    let r = redact("card 4111 1111 1111 1111 charged");
    assert_eq!(r.count("credit_card"), 1);
    assert!(!r.redacted_text.contains("4111 1111 1111 1111"));
}

#[test]
fn redacts_phone() {
    let r = redact("call 415-555-1212 now");
    assert_eq!(r.count("phone"), 1);
    assert!(!r.redacted_text.contains("415-555-1212"));
}

#[test]
fn redacts_aws_key() {
    let r = redact("key AKIAABCDEFGHIJKLMNOP end");
    assert_eq!(r.count("aws_key"), 1);
    assert!(!r.redacted_text.contains("AKIAABCDEFGHIJKLMNOP"));
}

#[test]
fn aws_key_is_case_sensitive() {
    // aws_key has no (?i) flag, so a lowercase "akia..." must NOT be redacted.
    let r = redact("key akiaabcdefghijklmnop end");
    assert!(!r.had_pii());
}

#[test]
fn redacts_api_key() {
    let r = redact("token sk-abcdef0123456789abcdef01 here");
    assert_eq!(r.count("api_key"), 1);
    assert!(!r.redacted_text.contains("sk-abcdef0123456789abcdef01"));
}

#[test]
fn api_key_is_case_insensitive() {
    // api_key has (?i), so an uppercase "SK-..." prefix must still be redacted.
    let r = redact("token SK-ABCDEF0123456789ABCDEF01 here");
    assert_eq!(r.count("api_key"), 1);
}

#[test]
fn redacts_ip() {
    let r = redact("host at 192.168.1.100 responded");
    assert_eq!(r.count("ip"), 1);
    assert!(!r.redacted_text.contains("192.168.1.100"));
}

#[test]
fn multiple_secrets_in_one_message_are_all_redacted() {
    let text = "mail me at a@b.com or call 415-555-1212, card 4111 1111 1111 1111";
    let r = redact(text);
    for secret in ["a@b.com", "415-555-1212", "4111 1111 1111 1111"] {
        assert!(
            !r.redacted_text.contains(secret),
            "secret survived: {secret}"
        );
    }
    for label in ["email", "phone", "credit_card"] {
        assert!(r.labels().contains(&label), "expected {label} in found");
    }
}

#[test]
fn clean_text_is_left_untouched() {
    let text = "This is a perfectly ordinary sentence with no secrets in it.";
    let r = redact(text);
    assert_eq!(r.redacted_text, text);
    assert!(!r.had_pii());
}

#[test]
fn redaction_is_idempotent() {
    let once = redact("reach me at a@b.com").redacted_text;
    let twice = redact(&once).redacted_text;
    assert_eq!(once, twice);
}

#[test]
fn empty_input_has_no_pii() {
    let r = redact("");
    assert!(!r.had_pii());
    assert_eq!(r.redacted_text, "");
}

#[test]
fn secrets_are_always_redacted_even_buried_in_noise() {
    let filler = "the quick brown fox jumps over the lazy dog ".repeat(5);
    let secrets = [
        ("email", "attacker@evil.com"),
        ("ssn", "123-45-6789"),
        ("aws_key", "AKIAABCDEFGHIJKLMNOP"),
        ("api_key", "sk-abcdef0123456789abcdef01"),
    ];
    for i in 0..1000usize {
        let (label, secret) = secrets[i % secrets.len()];
        let cut = (i * 7) % (filler.len() + 1);
        let text = format!("{} {} {}", &filler[..cut], secret, &filler[cut..]);
        let r = redact(&text);
        assert!(
            !r.redacted_text.contains(secret),
            "iteration {i}: {label} secret survived"
        );
        assert!(r.had_pii(), "iteration {i}: {label} not flagged");
    }
}

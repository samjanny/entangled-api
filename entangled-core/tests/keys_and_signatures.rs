use entangled_core::types::keys::{PublisherPubkey, Signature};

const VALID_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43 chars
const VALID_SIG: &str =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 86 chars

#[test]
fn valid_pubkey_roundtrips() {
    let k = PublisherPubkey::try_from(VALID_KEY).unwrap();
    let v = serde_json::to_value(k).unwrap();
    assert_eq!(v, serde_json::Value::String(VALID_KEY.to_owned()));
    let back: PublisherPubkey = serde_json::from_value(v).unwrap();
    assert_eq!(k, back);
}

#[test]
fn pubkey_rejects_short_string() {
    let too_short = "A".repeat(42);
    let parsed = PublisherPubkey::try_from(too_short.as_str());
    assert!(parsed.is_err());
}

#[test]
fn pubkey_rejects_long_string() {
    let too_long = "A".repeat(44);
    let parsed = PublisherPubkey::try_from(too_long.as_str());
    assert!(parsed.is_err());
}

#[test]
fn pubkey_rejects_padding() {
    // 44 chars including '=' — should be rejected on length first.
    let with_padding = format!("{}=", "A".repeat(43));
    let parsed = PublisherPubkey::try_from(with_padding.as_str());
    assert!(parsed.is_err());
}

#[test]
fn pubkey_rejects_non_base64url_chars() {
    // 43 chars but with '+' (standard base64, not url-safe).
    let bad_plus = format!("{}+", "A".repeat(42));
    let parsed = PublisherPubkey::try_from(bad_plus.as_str());
    assert!(parsed.is_err());
    // 43 chars but with '/' (also standard base64, not url-safe).
    let bad_slash = format!("{}/", "A".repeat(42));
    let parsed2 = PublisherPubkey::try_from(bad_slash.as_str());
    assert!(parsed2.is_err());
}

#[test]
fn signature_valid_roundtrips() {
    let s = Signature::try_from(VALID_SIG).unwrap();
    let v = serde_json::to_value(s).unwrap();
    assert_eq!(v, serde_json::Value::String(VALID_SIG.to_owned()));
    let back: Signature = serde_json::from_value(v).unwrap();
    assert_eq!(s, back);
}

#[test]
fn signature_rejects_short_string() {
    let too_short = "A".repeat(85);
    assert!(Signature::try_from(too_short.as_str()).is_err());
}

#[test]
fn signature_rejects_long_string() {
    let too_long = "A".repeat(87);
    assert!(Signature::try_from(too_long.as_str()).is_err());
}

#[test]
fn signature_rejects_padding() {
    let padded = format!("{}=", "A".repeat(86));
    assert!(Signature::try_from(padded.as_str()).is_err());
}

#[test]
fn signature_rejects_non_base64url_chars() {
    let bad_plus = format!("{}+", "A".repeat(85));
    assert!(Signature::try_from(bad_plus.as_str()).is_err());
    let bad_slash = format!("{}/", "A".repeat(85));
    assert!(Signature::try_from(bad_slash.as_str()).is_err());
}

// -- §04 strict base64url (v1.0-rc.5) ----------------------------------------

#[test]
fn pubkey_rejects_embedded_whitespace() {
    // §04 v1.0-rc.5: decoders MUST reject any character outside the URL-safe
    // alphabet, including whitespace and line breaks.
    let with_space = format!("{} {}", "A".repeat(21), "A".repeat(21));
    assert!(PublisherPubkey::try_from(with_space.as_str()).is_err());
    let with_lf = format!("{}\n{}", "A".repeat(21), "A".repeat(21));
    assert!(PublisherPubkey::try_from(with_lf.as_str()).is_err());
}

#[test]
fn pubkey_rejects_non_canonical_trailing_bits() {
    // §04 v1.0-rc.5: the unused bits in the final encoded character MUST be
    // zero. For a 32-byte / 43-char base64url value the last char encodes
    // only the top 4 bits; the bottom 2 bits MUST be zero.
    //
    // "A" decodes to 0b000000 — canonical.
    // "B" decodes to 0b000001 — last two bits = 0b01, non-canonical for the
    // trailing position.
    let non_canonical = format!("{}{}", "A".repeat(42), "B");
    assert!(
        PublisherPubkey::try_from(non_canonical.as_str()).is_err(),
        "non-canonical trailing-bit encoding must be rejected"
    );
}

#[test]
fn signature_rejects_non_canonical_trailing_bits() {
    // For a 64-byte / 86-char signature the last char encodes only the top
    // 2 bits; the bottom 4 bits MUST be zero. "B" (0b000001) has a non-zero
    // low bit and must be rejected at the lexical layer.
    let non_canonical = format!("{}{}", "A".repeat(85), "B");
    assert!(
        Signature::try_from(non_canonical.as_str()).is_err(),
        "non-canonical trailing-bit signature must be rejected"
    );
}

#[test]
fn pubkey_rejects_non_ascii_byte() {
    // Embed a non-ASCII byte sequence (a multi-byte UTF-8 character) inside
    // an otherwise-43-char string; even if the *char* count happens to look
    // right, the decoder MUST reject anything outside `[A-Za-z0-9_-]`.
    let mut s = "A".repeat(42);
    s.push('é'); // U+00E9 — outside the base64url alphabet
    assert!(PublisherPubkey::try_from(s.as_str()).is_err());
}

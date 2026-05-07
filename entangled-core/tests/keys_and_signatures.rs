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

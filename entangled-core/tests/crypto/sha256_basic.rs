//! SHA-256 wrapper sanity using FIPS 180-4 test vectors.

use entangled_core::crypto::{sha256, sha256_base64url};

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn sha256_empty_input_matches_fips_vector() {
    let expected = hex_to_bytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(sha256(b"").to_vec(), expected);
}

#[test]
fn sha256_abc_matches_fips_vector() {
    let expected = hex_to_bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(sha256(b"abc").to_vec(), expected);
}

#[test]
fn sha256_base64url_round_trip_for_empty_input() {
    let s = sha256_base64url(b"");
    assert_eq!(
        s.len(),
        43,
        "unpadded base64url of 32 bytes is exactly 43 chars"
    );
    assert!(s.is_ascii());
    let decoded = data_encoding::BASE64URL_NOPAD
        .decode(s.as_bytes())
        .expect("valid base64url");
    let expected = hex_to_bytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(decoded, expected);
}

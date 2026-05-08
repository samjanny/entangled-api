//! PIP (24-word BIP-39 representation) round-trip and rejection tests.

use entangled_core::crypto::{derive_pip, pip_to_pubkey, PipError, PublisherSigningKey};

// Pull in the same wordlist file used by the implementation, via a path
// relative to this test file. This lets the test cross-check the wordlist's
// structural invariants directly, rather than indirectly through PIPs.
const WORDLIST_RAW: &str = include_str!("../../src/crypto/wordlist_english.txt");

#[test]
fn wordlist_sanity_2048_words_first_abandon_last_zoo() {
    let words: Vec<&str> = WORDLIST_RAW.lines().collect();
    assert_eq!(
        words.len(),
        2048,
        "BIP-39 English wordlist has 2048 entries"
    );
    assert_eq!(words[0], "abandon");
    assert_eq!(words[2047], "zoo");

    for w in &words {
        assert!(w.is_ascii(), "all wordlist entries are ASCII");
        assert_eq!(*w, w.to_lowercase(), "all entries are lowercase");
        assert!(w.len() <= 8, "BIP-39 words are <= 8 chars");
        assert!(!w.is_empty());
    }

    // Confirm the wordlist is sorted (binary search relies on this).
    for pair in words.windows(2) {
        assert!(pair[0] < pair[1], "wordlist must be sorted ascending");
    }
}

#[test]
fn pip_round_trip_from_known_seed() {
    let signing = PublisherSigningKey::from_seed(&[0x42; 32]);
    let pk = signing.verifying_key();
    let pip = derive_pip(&pk);

    let words: Vec<&str> = pip.split(' ').collect();
    assert_eq!(words.len(), 24, "PIP must contain exactly 24 words");

    let recovered = pip_to_pubkey(&pip).expect("valid PIP");
    assert_eq!(recovered.as_bytes(), pk.as_bytes());
}

#[test]
fn pip_is_deterministic() {
    let signing = PublisherSigningKey::from_seed(&[0x42; 32]);
    let pk = signing.verifying_key();
    let a = derive_pip(&pk);
    let b = derive_pip(&pk);
    assert_eq!(a, b, "derive_pip must be deterministic");
}

#[test]
fn pip_rejects_wrong_word_count_short() {
    let words: Vec<&str> = std::iter::repeat_n("abandon", 23).collect();
    let pip = words.join(" ");
    assert_eq!(pip_to_pubkey(&pip), Err(PipError::WrongWordCount(23)));
}

#[test]
fn pip_rejects_wrong_word_count_long() {
    let words: Vec<&str> = std::iter::repeat_n("abandon", 25).collect();
    let pip = words.join(" ");
    assert_eq!(pip_to_pubkey(&pip), Err(PipError::WrongWordCount(25)));
}

#[test]
fn pip_rejects_unknown_word() {
    let signing = PublisherSigningKey::from_seed(&[0x42; 32]);
    let pip = derive_pip(&signing.verifying_key());
    let mut words: Vec<&str> = pip.split(' ').collect();
    words[5] = "qwerty";
    let mutated = words.join(" ");
    match pip_to_pubkey(&mutated) {
        Err(PipError::UnknownWord(w)) => assert_eq!(w, "qwerty"),
        other => panic!("expected UnknownWord, got {other:?}"),
    }
}

#[test]
fn pip_rejects_invalid_checksum_when_last_word_changed() {
    let signing = PublisherSigningKey::from_seed(&[0x42; 32]);
    let pip = derive_pip(&signing.verifying_key());
    let words: Vec<String> = pip.split(' ').map(|s| s.to_string()).collect();
    let last = &words[23];
    // Pick a different word from the wordlist that is not the original.
    let replacement = if last == "abandon" { "zoo" } else { "abandon" };
    let mut mutated_words = words.clone();
    mutated_words[23] = replacement.to_string();
    let mutated = mutated_words.join(" ");
    assert_eq!(pip_to_pubkey(&mutated), Err(PipError::InvalidChecksum));
}

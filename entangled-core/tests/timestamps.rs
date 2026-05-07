use entangled_core::types::timestamp::EntangledTimestamp;

#[test]
fn accepts_canonical_form() {
    let t = EntangledTimestamp::try_from("2026-05-07T00:00:00Z").unwrap();
    assert_eq!(t.to_string(), "2026-05-07T00:00:00Z");
}

#[test]
fn rejects_fractional_seconds() {
    assert!(EntangledTimestamp::try_from("2026-05-07T00:00:00.123Z").is_err());
}

#[test]
fn rejects_numeric_offset() {
    assert!(EntangledTimestamp::try_from("2026-05-07T00:00:00+00:00").is_err());
}

#[test]
fn rejects_leap_second() {
    assert!(EntangledTimestamp::try_from("2026-12-31T23:59:60Z").is_err());
}

#[test]
fn rejects_invalid_month() {
    assert!(EntangledTimestamp::try_from("2026-13-01T00:00:00Z").is_err());
}

#[test]
fn rejects_feb_29_in_non_leap_year() {
    // 2026 is not a leap year.
    assert!(EntangledTimestamp::try_from("2026-02-29T00:00:00Z").is_err());
}

#[test]
fn accepts_feb_29_in_leap_year() {
    assert!(EntangledTimestamp::try_from("2024-02-29T00:00:00Z").is_ok());
}

#[test]
fn serde_roundtrip() {
    let s = "2026-05-07T12:34:56Z";
    let t = EntangledTimestamp::try_from(s).unwrap();
    let v = serde_json::to_value(t).unwrap();
    assert_eq!(v, serde_json::Value::String(s.to_owned()));
    let back: EntangledTimestamp = serde_json::from_value(v).unwrap();
    assert_eq!(t, back);
}

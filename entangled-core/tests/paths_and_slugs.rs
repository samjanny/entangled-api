use entangled_core::types::{path::EntangledPath, slug::Slug};

#[test]
fn valid_paths_accepted() {
    for p in ["/", "/foo", "/articles/first-post", "/a-b_c.d~e/x.png"] {
        assert!(
            EntangledPath::try_from(p).is_ok(),
            "expected `{p}` to be a valid path"
        );
    }
}

#[test]
fn invalid_paths_rejected() {
    let too_long = format!("/{}", "a".repeat(256)); // 257 chars total
    let cases = [
        "foo",         // missing leading '/'
        "/foo//bar",   // consecutive slash
        "/./",         // dot segment
        "/../x",       // double-dot segment
        "/foo?q=1",    // query string
        "/foo#bar",    // fragment
        "https://x/y", // scheme
        too_long.as_str(),
    ];
    for p in cases {
        assert!(
            EntangledPath::try_from(p).is_err(),
            "expected `{p}` to be rejected"
        );
    }
}

#[test]
fn valid_slugs_accepted() {
    for s in ["a", "abc", "a-b_c", "0123", "a0_-z"] {
        assert!(Slug::try_from(s).is_ok(), "expected `{s}` to be valid slug");
    }
    let max = "a".repeat(64);
    assert!(Slug::try_from(max.as_str()).is_ok());
}

#[test]
fn invalid_slugs_rejected() {
    let too_long = "a".repeat(65);
    let cases = [
        "",     // empty
        "_a",   // doesn't start with [a-z0-9]
        "-a",   // doesn't start with [a-z0-9]
        "A",    // uppercase
        "abc!", // bad char
        too_long.as_str(),
    ];
    for s in cases {
        assert!(Slug::try_from(s).is_err(), "expected `{s}` to be rejected");
    }
}

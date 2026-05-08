use entangled_core::types::{
    path::{EntangledPath, PathError},
    slug::Slug,
};

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
fn reserved_manifest_path_rejected() {
    // §02 v1.0-rc.6: /manifest.json is reserved at the protocol level for the
    // carrier-level manifest fetch and MUST NOT appear as a content path,
    // transaction in_response_to, image src, submit endpoint, or link target.
    assert_eq!(
        EntangledPath::try_from("/manifest.json").unwrap_err(),
        PathError::ReservedManifestPath
    );
}

#[test]
fn paths_resembling_manifest_but_distinct_accepted() {
    // The reservation is byte-exact `/manifest.json`, not a prefix or
    // case-insensitive match.
    for p in [
        "/manifest.json/",
        "/Manifest.json",
        "/manifest.JSON",
        "/manifest_json",
        "/manifest.json.bak",
        "/api/manifest.json",
        "/manifest",
    ] {
        assert!(
            EntangledPath::try_from(p).is_ok(),
            "expected `{p}` to remain valid"
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

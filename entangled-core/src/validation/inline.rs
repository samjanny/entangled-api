//! Stage 5 — inline content validators. §03.

use std::collections::HashSet;

use crate::types::inline::{InlineContent, InlineElement};
use crate::types::link::LinkTarget;
use crate::types::manifest::{Carrier, OnionAddress};

use super::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};
use super::limits::{
    CITATION_URL_MAX_BYTES, INLINE_ARRAY_MAX_ELEMENTS, INLINE_VALUE_MAX_BYTES,
    LINK_TARGET_MAX_BYTES,
};
use super::strings::no_control_chars;

/// Validates an inline content array against the inline grammar (§03) and
/// the per-block aggregate byte cap declared by the containing block.
///
/// `total_byte_cap` is the limit on the sum of UTF-8 bytes across all `value`
/// strings in the array (§03 inline content limits).
///
/// `allow_links` selects whether inline `link` elements are permitted; for
/// `link.label` and `submit_form.label` this is `false` (§03 forbids nested
/// links).
pub fn validate_inline(
    content: &InlineContent,
    total_byte_cap: usize,
    allow_links: bool,
) -> Result<(), Diagnostic> {
    if content.is_empty() {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaRequiredField,
            DocumentKindLabel::None,
            "inline content must contain at least one element",
        ));
    }
    if content.len() > INLINE_ARRAY_MAX_ELEMENTS {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::None,
            format!(
                "inline content has {} elements, max is {INLINE_ARRAY_MAX_ELEMENTS}",
                content.len()
            ),
        ));
    }

    let mut total_bytes: usize = 0;
    for el in content {
        match el {
            InlineElement::Text { value, marks } => {
                check_value(value)?;
                check_marks_unique(marks)?;
                total_bytes = total_bytes.saturating_add(value.len());
            }
            InlineElement::Link {
                value,
                marks,
                target,
            } => {
                if !allow_links {
                    return Err(Diagnostic::new(
                        DiagnosticCode::ESchemaBlockNotPermitted,
                        DocumentKindLabel::None,
                        "nested link not permitted in this inline content",
                    ));
                }
                check_value(value)?;
                check_marks_unique(marks)?;
                validate_link_target(target)?;
                total_bytes = total_bytes.saturating_add(value.len());
            }
        }
    }

    if total_bytes > total_byte_cap {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::None,
            format!("inline content total bytes {total_bytes} exceeds cap of {total_byte_cap}"),
        ));
    }
    Ok(())
}

fn check_value(value: &str) -> Result<(), Diagnostic> {
    if value.len() > INLINE_VALUE_MAX_BYTES {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::None,
            format!(
                "inline value of {} bytes exceeds per-element cap of {INLINE_VALUE_MAX_BYTES}",
                value.len()
            ),
        ));
    }
    if !no_control_chars(value, false) {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldSyntax,
            DocumentKindLabel::None,
            "inline value contains control characters (U+0000..=U+001F or U+007F)",
        ));
    }
    Ok(())
}

fn check_marks_unique<T: std::hash::Hash + Eq>(marks: &[T]) -> Result<(), Diagnostic> {
    let mut seen = HashSet::with_capacity(marks.len());
    for m in marks {
        if !seen.insert(m) {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaDuplicateEntry,
                DocumentKindLabel::None,
                "duplicate text mark",
            )
            .with_details(serde_json::json!({
                "field_path": "inline[].marks",
            })));
        }
    }
    Ok(())
}

/// §03 link-target schema validation, including the serialized 1 KiB cap.
pub fn validate_link_target(target: &LinkTarget) -> Result<(), Diagnostic> {
    let serialized = serde_json::to_string(target).map_err(|e| {
        Diagnostic::new(
            DiagnosticCode::ESchemaFieldType,
            DocumentKindLabel::None,
            format!("link target failed to serialize: {e}"),
        )
    })?;
    if serialized.len() > LINK_TARGET_MAX_BYTES {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::None,
            format!(
                "serialized link target of {} bytes exceeds cap of {LINK_TARGET_MAX_BYTES}",
                serialized.len()
            ),
        ));
    }

    match target {
        LinkTarget::Citation { url } => validate_citation_url(url),
        LinkTarget::Carrier { carrier, url } => validate_carrier_url(*carrier, url),
        // SameSite and Entangled are validated structurally by the inner newtypes.
        _ => Ok(()),
    }
}

fn validate_citation_url(url: &str) -> Result<(), Diagnostic> {
    validate_url_common("citation", url, "https://")
}

/// Validate a `kind: "carrier"` link target URL (§03).
///
/// Same byte-cap, control-char, and RFC 3986 rules as citation, but the
/// scheme MUST be `http://` (the carrier provides confidentiality at the
/// rendezvous layer; cf. §09 on plain HTTP over Tor v3) and the host MUST
/// be a valid carrier address for the declared `carrier` — for `tor-v3`,
/// the 56-character lowercase base32 onion body followed by `.onion`.
fn validate_carrier_url(carrier: Carrier, url: &str) -> Result<(), Diagnostic> {
    validate_url_common("carrier", url, "http://")?;
    let after_scheme = &url["http://".len()..];
    let host = extract_authority_host(after_scheme).ok_or_else(|| {
        Diagnostic::new(
            DiagnosticCode::ESchemaFieldSyntax,
            DocumentKindLabel::None,
            "carrier url has no host component",
        )
    })?;
    match carrier {
        Carrier::TorV3 => {
            OnionAddress::try_from(host).map_err(|e| {
                Diagnostic::new(
                    DiagnosticCode::ESchemaFieldSyntax,
                    DocumentKindLabel::None,
                    format!("carrier url host {host:?} is not a valid tor-v3 .onion address: {e}"),
                )
            })?;
        }
    }
    Ok(())
}

/// Shared URL syntax check for `citation` and `carrier` link target URLs:
/// 1 KiB byte cap, mandatory `required_scheme` prefix, no control chars,
/// RFC 3986 unreserved/reserved characters with valid `%HH` triplets.
fn validate_url_common(
    kind_label: &'static str,
    url: &str,
    required_scheme: &'static str,
) -> Result<(), Diagnostic> {
    if url.len() > CITATION_URL_MAX_BYTES {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::None,
            format!(
                "{kind_label} url of {} bytes exceeds cap of {CITATION_URL_MAX_BYTES}",
                url.len()
            ),
        ));
    }
    if !url.starts_with(required_scheme) {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldSyntax,
            DocumentKindLabel::None,
            format!("{kind_label} url must begin with {required_scheme}"),
        ));
    }
    if !no_control_chars(url, false) {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldSyntax,
            DocumentKindLabel::None,
            format!("{kind_label} url contains control characters"),
        ));
    }
    // RFC 3986: only unreserved / gen-delims / sub-delims / pct-encoded are
    // valid. Anything else (including printable ASCII like < > " \\ ^ ` { | }
    // and any non-ASCII byte) is rejected. `%` MUST introduce a complete
    // pct-encoded triplet `%HH` where each H is HEXDIG.
    let bytes = url.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            let h1 = bytes.get(i + 1).copied();
            let h2 = bytes.get(i + 2).copied();
            match (h1, h2) {
                (Some(a), Some(c)) if a.is_ascii_hexdigit() && c.is_ascii_hexdigit() => {
                    i += 3;
                    continue;
                }
                _ => {
                    return Err(Diagnostic::new(
                        DiagnosticCode::ESchemaFieldSyntax,
                        DocumentKindLabel::None,
                        format!("{kind_label} url contains malformed percent-encoded triplet"),
                    ));
                }
            }
        }
        if !is_rfc3986_unencoded_byte(b) {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldSyntax,
                DocumentKindLabel::None,
                format!(
                    "{kind_label} url contains characters outside RFC 3986 unreserved/reserved set"
                ),
            ));
        }
        i += 1;
    }
    Ok(())
}

/// Extract the host component from the authority part of a URI.
///
/// Given the URL slice **after** the `scheme://` prefix, finds the end of
/// the authority (first `/`, `?`, or `#`), strips optional userinfo
/// (anything before `@`), and strips an optional port (anything after the
/// last `:`). Returns `None` if the result is empty.
fn extract_authority_host(after_scheme: &str) -> Option<&str> {
    let end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..end];
    let host_port = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    let host = match host_port.rfind(':') {
        Some(colon) => &host_port[..colon],
        None => host_port,
    };
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Returns true if `b` is an unreserved/reserved URI byte per RFC 3986
/// §2.2 / §2.3 — i.e. anything that may legally appear *unencoded* in a
/// URI. Percent-encoded triplets `%HH` are validated separately by the
/// caller and are not handled here.
fn is_rfc3986_unencoded_byte(b: u8) -> bool {
    matches!(b,
        // unreserved: ALPHA / DIGIT / "-" / "." / "_" / "~"
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
        // gen-delims
        | b':' | b'/' | b'?' | b'#' | b'[' | b']' | b'@'
        // sub-delims
        | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    )
}

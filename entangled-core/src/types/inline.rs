//! Inline content elements: `Text` and `Link` runs with `TextMark` styling
//! (§03).

use serde::{Deserialize, Serialize};

use super::link::LinkTarget;

/// Inline text styling marks applicable to a `Text` or `Link` run (§03).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TextMark {
    /// Bold text.
    Bold,
    /// Italic text.
    Italic,
    /// Inline code styling.
    Code,
    /// Strikethrough text.
    Strikethrough,
}

/// One element of inline content (§03).
///
/// The wire form is a JSON object tagged by `kind`. Unknown `kind` values or
/// sibling fields are rejected at parse time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InlineElement {
    /// A run of styled text.
    Text {
        /// Plain Unicode text content.
        value: String,
        /// Styling marks applied to `value`.
        marks: Vec<TextMark>,
    },
    /// An inline link (text plus a target).
    Link {
        /// Text shown for the link.
        value: String,
        /// Styling marks applied to `value`.
        marks: Vec<TextMark>,
        /// Where the link points.
        target: LinkTarget,
    },
}

/// Ordered sequence of inline elements (§03).
pub type InlineContent = Vec<InlineElement>;

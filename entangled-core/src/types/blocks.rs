//! The 11 block kinds (§03) plus their helper enums and the `HeadingLevel`
//! newtype.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use super::form::FormField;
use super::inline::InlineContent;
use super::keys::ImageSha256;
use super::link::LinkTarget;
use super::path::EntangledPath;
use super::slug::Slug;

/// Visual variant of a `Feedback` block (§03).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FeedbackVariant {
    /// Successful operation.
    Success,
    /// Informational feedback.
    Info,
    /// Non-fatal warning.
    Warning,
    /// Failure or error condition.
    Error,
}

/// Visual variant of a `Note` block (§03).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NoteVariant {
    /// Informational aside.
    Info,
    /// Cautionary note.
    Warning,
    /// Severe / dangerous condition.
    Danger,
    /// Affirmation or success note.
    Success,
}

/// Allowed media types for an `Image` block (§03).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ImageMediaType {
    /// `image/png`.
    #[serde(rename = "image/png")]
    Png,
    /// `image/jpeg`.
    #[serde(rename = "image/jpeg")]
    Jpeg,
    /// `image/webp`.
    #[serde(rename = "image/webp")]
    Webp,
}

/// HTML-style heading level constrained to `1..=6` (§03).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HeadingLevel(u8);

/// Error produced when constructing a [`HeadingLevel`] from an out-of-range
/// integer.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HeadingLevelError {
    /// Value was not in the inclusive range 1..=6.
    #[error("heading level must be in 1..=6")]
    OutOfRange,
}

impl HeadingLevel {
    /// Return the underlying level as a `u8` in 1..=6.
    pub fn get(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for HeadingLevel {
    type Error = HeadingLevelError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if (1..=6).contains(&value) {
            Ok(Self(value))
        } else {
            Err(HeadingLevelError::OutOfRange)
        }
    }
}

impl fmt::Debug for HeadingLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HeadingLevel({})", self.0)
    }
}

impl Serialize for HeadingLevel {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.0)
    }
}

impl<'de> Deserialize<'de> for HeadingLevel {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = u8::deserialize(deserializer)?;
        Self::try_from(raw).map_err(serde::de::Error::custom)
    }
}

/// Closed enumeration of the 11 block kinds defined by the protocol (§03).
///
/// The wire form is a JSON object tagged by `kind` (snake_case). Unknown
/// `kind` values, or unknown sibling fields, are rejected at parse time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Block {
    /// A paragraph of inline content.
    Paragraph {
        /// Inline content of the paragraph.
        content: InlineContent,
    },
    /// A heading at level 1..=6.
    Heading {
        /// Heading level (1..=6).
        level: HeadingLevel,
        /// Inline content of the heading.
        content: InlineContent,
    },
    /// A pre-formatted code block tagged with a language slug.
    CodeBlock {
        /// Language tag (slug syntax).
        language: Slug,
        /// Raw verbatim code content.
        content: String,
    },
    /// A block quotation with optional attribution.
    Quote {
        /// Inline content of the quote.
        content: InlineContent,
        /// Optional inline attribution string.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        attribution: Option<InlineContent>,
    },
    /// An ordered or unordered list.
    List {
        /// `true` for ordered list, `false` for unordered.
        ordered: bool,
        /// List items, each holding inline content.
        items: Vec<InlineContent>,
    },
    /// A visual horizontal divider with no content.
    Divider,
    /// An image asset referenced by same-site path with content-hash binding.
    Image {
        /// Same-site path of the image asset.
        src: EntangledPath,
        /// SHA-256 of the image bytes; the client must verify after fetch.
        sha256: ImageSha256,
        /// Declared media type.
        media_type: ImageMediaType,
        /// Intrinsic width in pixels.
        width: u32,
        /// Intrinsic height in pixels.
        height: u32,
        /// Alt-text for accessibility.
        alt: String,
        /// Optional caption.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        caption: Option<String>,
    },
    /// A standalone link block (label + target).
    Link {
        /// Inline label rendered as the link.
        label: InlineContent,
        /// Where the link points.
        target: LinkTarget,
    },
    /// A submit form bound to a path with typed fields.
    SubmitForm {
        /// Inline label/header above the form.
        label: InlineContent,
        /// Path the form posts to (a transaction is returned).
        submit_to: EntangledPath,
        /// Closed list of typed fields.
        fields: Vec<FormField>,
        /// Display label for the submit button.
        submit_label: String,
    },
    /// A feedback strip (transient operation result).
    Feedback {
        /// Visual variant.
        variant: FeedbackVariant,
        /// Inline content.
        content: InlineContent,
    },
    /// A boxed note/callout with optional title.
    Note {
        /// Visual variant.
        variant: NoteVariant,
        /// Optional plain-text title rendered above the body.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        title: Option<String>,
        /// Inline content of the note body.
        content: InlineContent,
    },
}

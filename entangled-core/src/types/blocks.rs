use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use super::form::FormField;
use super::inline::InlineContent;
use super::keys::ImageSha256;
use super::link::LinkTarget;
use super::path::EntangledPath;
use super::slug::Slug;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FeedbackVariant {
    Success,
    Info,
    Warning,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NoteVariant {
    Info,
    Warning,
    Danger,
    Success,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ImageMediaType {
    #[serde(rename = "image/png")]
    Png,
    #[serde(rename = "image/jpeg")]
    Jpeg,
    #[serde(rename = "image/webp")]
    Webp,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HeadingLevel(u8);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HeadingLevelError {
    #[error("heading level must be in 1..=6")]
    OutOfRange,
}

impl HeadingLevel {
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Block {
    Paragraph {
        content: InlineContent,
    },
    Heading {
        level: HeadingLevel,
        content: InlineContent,
    },
    CodeBlock {
        language: Slug,
        content: String,
    },
    Quote {
        content: InlineContent,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        attribution: Option<InlineContent>,
    },
    List {
        ordered: bool,
        items: Vec<InlineContent>,
    },
    Divider,
    Image {
        src: EntangledPath,
        sha256: ImageSha256,
        media_type: ImageMediaType,
        width: u32,
        height: u32,
        alt: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        caption: Option<String>,
    },
    Link {
        label: InlineContent,
        target: LinkTarget,
    },
    SubmitForm {
        label: InlineContent,
        submit_to: EntangledPath,
        fields: Vec<FormField>,
        submit_label: String,
    },
    Feedback {
        variant: FeedbackVariant,
        content: InlineContent,
    },
    Note {
        variant: NoteVariant,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        title: Option<String>,
        content: InlineContent,
    },
}

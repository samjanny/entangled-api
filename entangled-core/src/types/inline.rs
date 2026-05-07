use serde::{Deserialize, Serialize};

use super::link::LinkTarget;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TextMark {
    Bold,
    Italic,
    Code,
    Strikethrough,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InlineElement {
    Text {
        value: String,
        marks: Vec<TextMark>,
    },
    Link {
        value: String,
        marks: Vec<TextMark>,
        target: LinkTarget,
    },
}

pub type InlineContent = Vec<InlineElement>;

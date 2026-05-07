use serde::{Deserialize, Serialize};

use super::slug::Slug;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectOption {
    pub value: Slug,
    pub label: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FormField {
    Text {
        name: Slug,
        label: String,
        required: bool,
        max_length: u32,
    },
    Textarea {
        name: Slug,
        label: String,
        required: bool,
        max_length: u32,
    },
    Select {
        name: Slug,
        label: String,
        required: bool,
        options: Vec<SelectOption>,
    },
    Checkbox {
        name: Slug,
        label: String,
        required: bool,
    },
}

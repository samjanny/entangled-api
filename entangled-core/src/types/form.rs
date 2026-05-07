//! Form field schema for `submit_form` blocks: text, textarea, select,
//! checkbox (§03).

use serde::{Deserialize, Serialize};

use super::slug::Slug;

/// One option in a `Select` form field (§03).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectOption {
    /// Machine value submitted when this option is chosen.
    pub value: Slug,
    /// Human-readable label rendered to the user.
    pub label: String,
}

/// Closed enumeration of form field kinds (§03 submit_form).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FormField {
    /// Single-line free-text field.
    Text {
        /// Field name (slug); must be unique within a form.
        name: Slug,
        /// Display label.
        label: String,
        /// Whether the user must supply a value.
        required: bool,
        /// Maximum byte length of the submitted value.
        max_length: u32,
    },
    /// Multi-line free-text field.
    Textarea {
        /// Field name (slug).
        name: Slug,
        /// Display label.
        label: String,
        /// Whether the user must supply a value.
        required: bool,
        /// Maximum byte length of the submitted value.
        max_length: u32,
    },
    /// Discrete choice from a closed list of options.
    Select {
        /// Field name (slug).
        name: Slug,
        /// Display label.
        label: String,
        /// Whether the user must choose an option.
        required: bool,
        /// Closed list of permitted options.
        options: Vec<SelectOption>,
    },
    /// Boolean checkbox.
    Checkbox {
        /// Field name (slug).
        name: Slug,
        /// Display label.
        label: String,
        /// Whether the user must check the box (e.g., to consent).
        required: bool,
    },
}

//! Stage 5 — block validators. §03.

use std::collections::HashSet;

use crate::types::blocks::Block;
use crate::types::form::{FormField, SelectOption};

use super::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};
use super::inline::validate_inline;
use super::kind::DocumentKind;
use super::limits::{
    CODE_BLOCK_CONTENT_MAX_BYTES, FEEDBACK_CONTENT_MAX_BYTES, FORM_FIELDS_MAX,
    FORM_FIELD_LABEL_MAX_BYTES, FORM_FIELD_MAX_LENGTH_RANGE, HEADING_CONTENT_MAX_BYTES,
    IMAGE_ALT_MAX_BYTES, IMAGE_CAPTION_MAX_BYTES, IMAGE_DIMENSION_RANGE, LINK_LABEL_MAX_BYTES,
    LIST_ITEMS_MAX, LIST_TOTAL_MAX_BYTES, MAX_IMAGE_BLOCKS_PER_DOC, NOTE_CONTENT_MAX_BYTES,
    NOTE_TITLE_MAX_BYTES, PARAGRAPH_CONTENT_MAX_BYTES, QUOTE_ATTRIBUTION_MAX_BYTES,
    QUOTE_CONTENT_MAX_BYTES, SELECT_OPTIONS_MAX, SUBMIT_LABEL_MAX_BYTES,
};
use super::strings::no_control_chars;

fn doc_kind_label(doc_kind: DocumentKind) -> DocumentKindLabel {
    match doc_kind {
        DocumentKind::Manifest => DocumentKindLabel::Manifest,
        DocumentKind::Content => DocumentKindLabel::Content,
        DocumentKind::Transaction => DocumentKindLabel::Transaction,
    }
}

fn fix_kind(diag: Diagnostic, doc_kind: DocumentKind) -> Diagnostic {
    Diagnostic {
        document_kind: doc_kind_label(doc_kind),
        ..diag
    }
}

/// Validates a block array within a document of the given kind. Performs the
/// per-document image-block count cap, then per-block validation.
pub fn validate_blocks(blocks: &[Block], doc_kind: DocumentKind) -> Result<(), Diagnostic> {
    let mut image_count: usize = 0;
    for b in blocks {
        if matches!(b, Block::Image { .. }) {
            image_count += 1;
        }
    }
    if image_count > MAX_IMAGE_BLOCKS_PER_DOC {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            doc_kind_label(doc_kind),
            format!("document has {image_count} image blocks, max is {MAX_IMAGE_BLOCKS_PER_DOC}"),
        ));
    }
    for b in blocks {
        validate_block(b, doc_kind)?;
    }
    Ok(())
}

/// Validate a single block under the containing document kind.
///
/// # Errors
///
/// Returns the first applicable Stage 5 diagnostic
/// (`E_SCHEMA_BLOCK_NOT_PERMITTED`, `E_SCHEMA_FIELD_LENGTH`,
/// `E_SCHEMA_FIELD_RANGE`, `E_SCHEMA_FIELD_SYNTAX`).
pub fn validate_block(block: &Block, doc_kind: DocumentKind) -> Result<(), Diagnostic> {
    // Permission gate per §03.
    if matches!(block, Block::SubmitForm { .. }) && doc_kind == DocumentKind::Transaction {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaBlockNotPermitted,
            DocumentKindLabel::Transaction,
            "submit_form block is not permitted in transaction documents",
        ));
    }

    let inner = match block {
        Block::Paragraph { content } => validate_inline(content, PARAGRAPH_CONTENT_MAX_BYTES, true),
        Block::Heading { level: _, content } => {
            validate_inline(content, HEADING_CONTENT_MAX_BYTES, true)
        }
        Block::CodeBlock {
            language: _,
            content,
        } => validate_code_block_content(content),
        Block::Quote {
            content,
            attribution,
        } => {
            validate_inline(content, QUOTE_CONTENT_MAX_BYTES, true)?;
            if let Some(attr) = attribution {
                validate_inline(attr, QUOTE_ATTRIBUTION_MAX_BYTES, false)?;
            }
            Ok(())
        }
        Block::List { ordered: _, items } => validate_list_items(items),
        Block::Divider => Ok(()),
        Block::Image {
            src: _,
            sha256: _,
            media_type: _,
            width,
            height,
            alt,
            caption,
        } => validate_image_fields(*width, *height, alt, caption.as_deref()),
        Block::Link { label, target } => validate_link_block(label, target),
        Block::SubmitForm {
            label,
            submit_to: _,
            fields,
            submit_label,
        } => validate_submit_form(label, fields, submit_label),
        Block::Feedback {
            variant: _,
            content,
        } => validate_inline(content, FEEDBACK_CONTENT_MAX_BYTES, true),
        Block::Note {
            variant: _,
            title,
            content,
        } => {
            if let Some(t) = title {
                validate_note_title(t)?;
            }
            validate_inline(content, NOTE_CONTENT_MAX_BYTES, true)
        }
    };
    inner.map_err(|d| fix_kind(d, doc_kind))
}

fn validate_code_block_content(content: &str) -> Result<(), Diagnostic> {
    if content.len() > CODE_BLOCK_CONTENT_MAX_BYTES {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::None,
            format!(
                "code_block content of {} bytes exceeds cap of {CODE_BLOCK_CONTENT_MAX_BYTES}",
                content.len()
            ),
        ));
    }
    if !no_control_chars(content, true) {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldSyntax,
            DocumentKindLabel::None,
            "code_block content contains control characters other than line feed",
        ));
    }
    Ok(())
}

fn validate_list_items(items: &[crate::types::inline::InlineContent]) -> Result<(), Diagnostic> {
    if items.is_empty() {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaRequiredField,
            DocumentKindLabel::None,
            "list must contain at least one item",
        ));
    }
    if items.len() > LIST_ITEMS_MAX {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::None,
            format!("list has {} items, max is {LIST_ITEMS_MAX}", items.len()),
        ));
    }
    let mut total_bytes: usize = 0;
    for item in items {
        // Per-item validation, with a generous per-item cap; the aggregate
        // gate below is the spec's normative limit.
        validate_inline(item, LIST_TOTAL_MAX_BYTES, true)?;
        for el in item {
            let value = match el {
                crate::types::inline::InlineElement::Text { value, .. }
                | crate::types::inline::InlineElement::Link { value, .. } => value,
            };
            total_bytes = total_bytes.saturating_add(value.len());
        }
    }
    if total_bytes > LIST_TOTAL_MAX_BYTES {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::None,
            format!(
                "list aggregate value bytes {total_bytes} exceeds cap of {LIST_TOTAL_MAX_BYTES}"
            ),
        ));
    }
    Ok(())
}

fn validate_image_fields(
    width: u32,
    height: u32,
    alt: &str,
    caption: Option<&str>,
) -> Result<(), Diagnostic> {
    if !IMAGE_DIMENSION_RANGE.contains(&width) {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldRange,
            DocumentKindLabel::None,
            format!(
                "image.width {width} out of range {}..={}",
                IMAGE_DIMENSION_RANGE.start(),
                IMAGE_DIMENSION_RANGE.end()
            ),
        ));
    }
    if !IMAGE_DIMENSION_RANGE.contains(&height) {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldRange,
            DocumentKindLabel::None,
            format!(
                "image.height {height} out of range {}..={}",
                IMAGE_DIMENSION_RANGE.start(),
                IMAGE_DIMENSION_RANGE.end()
            ),
        ));
    }
    if alt.len() > IMAGE_ALT_MAX_BYTES {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::None,
            format!(
                "image.alt of {} bytes exceeds cap of {IMAGE_ALT_MAX_BYTES}",
                alt.len()
            ),
        ));
    }
    if !no_control_chars(alt, false) {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldSyntax,
            DocumentKindLabel::None,
            "image.alt contains control characters",
        ));
    }
    if let Some(c) = caption {
        if c.is_empty() {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldSyntax,
                DocumentKindLabel::None,
                "image.caption, when present, must not be empty",
            ));
        }
        if c.len() > IMAGE_CAPTION_MAX_BYTES {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldLength,
                DocumentKindLabel::None,
                format!(
                    "image.caption of {} bytes exceeds cap of {IMAGE_CAPTION_MAX_BYTES}",
                    c.len()
                ),
            ));
        }
        if !no_control_chars(c, false) {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldSyntax,
                DocumentKindLabel::None,
                "image.caption contains control characters",
            ));
        }
    }
    Ok(())
}

fn validate_link_block(
    label: &crate::types::inline::InlineContent,
    target: &crate::types::link::LinkTarget,
) -> Result<(), Diagnostic> {
    validate_inline(label, LINK_LABEL_MAX_BYTES, false)?;
    super::inline::validate_link_target(target)
}

fn validate_submit_form(
    label: &crate::types::inline::InlineContent,
    fields: &[FormField],
    submit_label: &str,
) -> Result<(), Diagnostic> {
    // The spec does not declare a block-level aggregate byte cap for
    // submit_form.label. The per-element (2 KiB) and per-array (256) inline
    // limits still apply. Pass `usize::MAX` so the per-element gates are the
    // only constraint.
    validate_inline(label, usize::MAX, false)?;
    if fields.is_empty() {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaRequiredField,
            DocumentKindLabel::None,
            "submit_form must contain at least one field",
        ));
    }
    if fields.len() > FORM_FIELDS_MAX {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::None,
            format!(
                "submit_form has {} fields, max is {FORM_FIELDS_MAX}",
                fields.len()
            ),
        ));
    }
    if submit_label.len() > SUBMIT_LABEL_MAX_BYTES {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::None,
            format!(
                "submit_label of {} bytes exceeds cap of {SUBMIT_LABEL_MAX_BYTES}",
                submit_label.len()
            ),
        ));
    }
    if !no_control_chars(submit_label, false) {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldSyntax,
            DocumentKindLabel::None,
            "submit_label contains control characters",
        ));
    }
    validate_form_fields(fields)
}

/// Validate the `fields` array of a `submit_form` block: per-field syntax
/// plus uniqueness of `name`.
///
/// # Errors
///
/// Returns the first applicable Stage 5 diagnostic.
pub fn validate_form_fields(fields: &[FormField]) -> Result<(), Diagnostic> {
    let mut seen_names: HashSet<&crate::types::slug::Slug> = HashSet::with_capacity(fields.len());
    for f in fields {
        let name = match f {
            FormField::Text { name, .. }
            | FormField::Textarea { name, .. }
            | FormField::Select { name, .. }
            | FormField::Checkbox { name, .. } => name,
        };
        if !seen_names.insert(name) {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldSyntax,
                DocumentKindLabel::None,
                format!("duplicate field name {:?}", name.as_str()),
            ));
        }

        let label = match f {
            FormField::Text { label, .. }
            | FormField::Textarea { label, .. }
            | FormField::Select { label, .. }
            | FormField::Checkbox { label, .. } => label,
        };
        if label.len() > FORM_FIELD_LABEL_MAX_BYTES {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldLength,
                DocumentKindLabel::None,
                format!(
                    "form field label of {} bytes exceeds cap of {FORM_FIELD_LABEL_MAX_BYTES}",
                    label.len()
                ),
            ));
        }
        if !no_control_chars(label, false) {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldSyntax,
                DocumentKindLabel::None,
                "form field label contains control characters",
            ));
        }

        match f {
            FormField::Text { max_length, .. } | FormField::Textarea { max_length, .. } => {
                if !FORM_FIELD_MAX_LENGTH_RANGE.contains(max_length) {
                    return Err(Diagnostic::new(
                        DiagnosticCode::ESchemaFieldRange,
                        DocumentKindLabel::None,
                        format!(
                            "form field max_length {max_length} out of range {}..={}",
                            FORM_FIELD_MAX_LENGTH_RANGE.start(),
                            FORM_FIELD_MAX_LENGTH_RANGE.end()
                        ),
                    ));
                }
            }
            FormField::Select { options, .. } => validate_select_options(options)?,
            FormField::Checkbox { .. } => {}
        }
    }
    Ok(())
}

fn validate_select_options(options: &[SelectOption]) -> Result<(), Diagnostic> {
    if options.is_empty() {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaRequiredField,
            DocumentKindLabel::None,
            "select field must contain at least one option",
        ));
    }
    if options.len() > SELECT_OPTIONS_MAX {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::None,
            format!(
                "select field has {} options, max is {SELECT_OPTIONS_MAX}",
                options.len()
            ),
        ));
    }
    let mut seen_values: HashSet<&crate::types::slug::Slug> = HashSet::with_capacity(options.len());
    for opt in options {
        if !seen_values.insert(&opt.value) {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldSyntax,
                DocumentKindLabel::None,
                format!("duplicate select option value {:?}", opt.value.as_str()),
            ));
        }
        if opt.label.len() > FORM_FIELD_LABEL_MAX_BYTES {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldLength,
                DocumentKindLabel::None,
                format!(
                    "select option label of {} bytes exceeds cap of {FORM_FIELD_LABEL_MAX_BYTES}",
                    opt.label.len()
                ),
            ));
        }
        if !no_control_chars(&opt.label, false) {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldSyntax,
                DocumentKindLabel::None,
                "select option label contains control characters",
            ));
        }
    }
    Ok(())
}

fn validate_note_title(title: &str) -> Result<(), Diagnostic> {
    if title.is_empty() {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldSyntax,
            DocumentKindLabel::None,
            "note.title, when present, must not be empty",
        ));
    }
    if title.len() > NOTE_TITLE_MAX_BYTES {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::None,
            format!(
                "note.title of {} bytes exceeds cap of {NOTE_TITLE_MAX_BYTES}",
                title.len()
            ),
        ));
    }
    if !no_control_chars(title, false) {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldSyntax,
            DocumentKindLabel::None,
            "note.title contains control characters",
        ));
    }
    Ok(())
}

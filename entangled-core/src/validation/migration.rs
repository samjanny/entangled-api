//! Stage 9 origin-migration handling (§10 v1.0-rc.13).
//!
//! When an announcing manifest carries a `migration_pointer`, a client
//! supporting publisher profiles fetches the successor manifest from
//! `successor_origin.address` and runs the full Stages 1-9 pipeline on
//! it. The publisher-identity continuity check belongs at Stage 9: the
//! successor manifest's `publisher_pubkey` MUST byte-equal the
//! announcing manifest's `publisher_pubkey`. A mismatch is reported as
//! `E_MIGRATION_MISMATCH` and the announcement is rejected.
//!
//! Structural well-formedness of the announcing manifest's
//! `migration_pointer` (self-pointing address, carrier mismatch,
//! `announced_at` after `updated`) is a Stage 5 schema concern handled by
//! [`crate::validation::schema::validate_migration_pointer`] and reported
//! as `E_MIGRATION_INVALID` instead.

use crate::types::manifest::Manifest;
use crate::validation::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};

/// Verify a migration announcement: the successor manifest's
/// `publisher_pubkey` MUST equal the announcing manifest's
/// `publisher_pubkey`.
///
/// Returns `E_MIGRATION_MISMATCH` (§11 rc.13) on divergence, with
/// `details` carrying the announced successor address and the two
/// pubkeys compared. Both manifests are expected to have already cleared
/// their own Stages 1-9 pipelines; this helper performs only the
/// publisher-identity continuity check.
///
/// # Errors
///
/// `E_MIGRATION_MISMATCH` when the successor's `publisher_pubkey` does
/// not byte-equal the announcing manifest's `publisher_pubkey`.
pub fn verify_migration_announcement(
    announcing: &Manifest,
    successor: &Manifest,
) -> Result<(), Diagnostic> {
    if announcing.publisher_pubkey != successor.publisher_pubkey {
        return Err(Diagnostic::new(
            DiagnosticCode::EMigrationMismatch,
            DocumentKindLabel::Manifest,
            "successor manifest publisher_pubkey does not match announcing publisher_pubkey",
        )
        .with_details(serde_json::json!({
            "field_path": "successor.publisher_pubkey",
            "reason": "publisher_identity_mismatch",
            "announcing_pubkey": announcing.publisher_pubkey.to_string(),
            "successor_pubkey": successor.publisher_pubkey.to_string(),
            "announced_successor_address": successor.origin.address.as_str(),
        })));
    }
    Ok(())
}

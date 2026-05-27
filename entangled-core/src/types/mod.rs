//! Wire-format types of the Entangled v1.0 protocol.
//!
//! Every type in this module corresponds to a JSON object or value defined in
//! the protocol specification. Newtype wrappers carry validation invariants
//! enforced at parse time; structural enums use serde's internally-tagged
//! representation to preserve the wire's `kind` (or `op`) discriminator.
//!
//! See [§02](https://github.com/samjanny/entangled/blob/main/specs/02-document-schema.md)
//! and [§03](https://github.com/samjanny/entangled/blob/main/specs/03-block-types.md).

pub mod blocks;
pub mod canary;
pub mod document;
pub mod form;
pub mod inline;
pub mod keys;
pub mod link;
pub mod manifest;
pub mod meta;
pub mod path;
pub mod slug;
pub mod state;
pub mod timestamp;

pub use blocks::{Block, FeedbackVariant, HeadingLevel, ImageMediaType, NoteVariant};
pub use canary::Canary;
pub use document::{ContentDocument, Document, TransactionDocument};
pub use form::{FormField, SelectOption};
pub use inline::{InlineContent, InlineElement, TextMark};
pub use keys::{
    ContentHash, ContentRoot, ImageSha256, KeyDecodeError, OriginPubkey, PublisherPubkey,
    RequestHash, RequestId, RequestIdDecodeError, RuntimePubkey, Sha256HashDecodeError, Signature,
    SignatureDecodeError, SpecVersion, SpecVersionError,
};
pub use link::LinkTarget;
pub use manifest::{Carrier, Manifest, NavEntry, OnionAddress, OnionAddressError, Origin};
pub use meta::Meta;
pub use path::{EntangledPath, PathError};
pub use slug::{Slug, SlugError};
pub use state::{StateMode, StatePolicyEntry, StateUpdateOp};
pub use timestamp::{EntangledTimestamp, TimestampError};

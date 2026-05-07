use serde::{Deserialize, Serialize};

use super::blocks::Block;
use super::keys::{Signature, SpecVersion};
use super::manifest::Manifest;
use super::meta::Meta;
use super::path::EntangledPath;
use super::state::StateUpdateOp;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentDocument {
    pub spec_version: SpecVersion,
    pub path: EntangledPath,
    pub meta: Meta,
    pub blocks: Vec<Block>,
    pub sig: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionDocument {
    pub spec_version: SpecVersion,
    pub in_response_to: EntangledPath,
    pub state_updates: Vec<StateUpdateOp>,
    pub blocks: Vec<Block>,
    pub sig: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Document {
    Manifest(Manifest),
    Content(ContentDocument),
    Transaction(TransactionDocument),
}

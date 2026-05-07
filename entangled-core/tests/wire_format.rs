mod common;

use entangled_core::types::{
    blocks::{Block, ImageMediaType},
    inline::TextMark,
    link::LinkTarget,
    manifest::Carrier,
    slug::Slug,
    state::{StateMode, StateUpdateOp},
};

use crate::common::path;

#[test]
fn divider_block_serializes_with_only_kind() {
    let b = Block::Divider;
    let v: serde_json::Value = serde_json::to_value(&b).unwrap();
    assert_eq!(v, serde_json::json!({ "kind": "divider" }));
}

#[test]
fn text_mark_bold_serializes_as_lowercase() {
    let v = serde_json::to_value(TextMark::Bold).unwrap();
    assert_eq!(v, serde_json::Value::String("bold".to_owned()));
}

#[test]
fn state_mode_client_only_serializes_snake_case() {
    let v = serde_json::to_value(StateMode::ClientOnly).unwrap();
    assert_eq!(v, serde_json::Value::String("client_only".to_owned()));
}

#[test]
fn carrier_tor_v3_serializes_as_kebab_case_string() {
    let v = serde_json::to_value(Carrier::TorV3).unwrap();
    assert_eq!(v, serde_json::Value::String("tor-v3".to_owned()));
}

#[test]
fn image_media_type_png_serializes_with_slash() {
    let v = serde_json::to_value(ImageMediaType::Png).unwrap();
    assert_eq!(v, serde_json::Value::String("image/png".to_owned()));
}

#[test]
fn link_target_same_site_uses_kind_field() {
    let lt = LinkTarget::SameSite { path: path("/x") };
    let v = serde_json::to_value(&lt).unwrap();
    assert_eq!(
        v,
        serde_json::json!({
            "kind": "same_site",
            "path": "/x"
        })
    );
}

#[test]
fn state_update_op_uses_op_discriminator_not_kind() {
    let op = StateUpdateOp::Set {
        namespace: Slug::try_from("session").unwrap(),
        key: Slug::try_from("auth").unwrap(),
        value: "token".to_owned(),
        ttl: 3600,
    };
    let v = serde_json::to_value(&op).unwrap();
    let obj = v.as_object().expect("must be object");
    assert!(
        obj.contains_key("op"),
        "expected discriminator field 'op', got {obj:?}"
    );
    assert!(
        !obj.contains_key("kind"),
        "must NOT use 'kind' as discriminator on state update ops, got {obj:?}"
    );
    assert_eq!(obj.get("op"), Some(&serde_json::json!("set")));
}

#[test]
fn state_update_op_delete_uses_op_discriminator() {
    let op = StateUpdateOp::Delete {
        namespace: Slug::try_from("session").unwrap(),
        key: Slug::try_from("auth").unwrap(),
    };
    let v = serde_json::to_value(&op).unwrap();
    assert_eq!(
        v,
        serde_json::json!({
            "op": "delete",
            "namespace": "session",
            "key": "auth"
        })
    );
}

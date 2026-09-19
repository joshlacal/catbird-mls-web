//! Synchronous JS entry points capture session authority before creating a
//! Promise. Internal Rust functions return an already-fenced future, so neither
//! direct package calls nor queued Worker calls can adopt a replacement session.
use crate::browser_subscription;
use js_sys::Array;
use wasm_bindgen::prelude::*;

macro_rules! export_session {
    ($name:ident($($arg:ident: $ty:ty),* $(,)?) -> () = $path:path) => {
        #[wasm_bindgen]
        pub fn $name($($arg: $ty),*) -> js_sys::Promise {
            let operation = $path($($arg),*);
            wasm_bindgen_futures::future_to_promise(async move {
                operation.await.map(|()| JsValue::UNDEFINED)
            })
        }
    };
    ($name:ident($($arg:ident: $ty:ty),* $(,)?) -> $result:ty = $path:path) => {
        #[wasm_bindgen]
        pub fn $name($($arg: $ty),*) -> js_sys::Promise {
            let operation = $path($($arg),*);
            wasm_bindgen_futures::future_to_promise(async move {
                operation.await.map(JsValue::from)
            })
        }
    };
}

export_session!(catbird_mls_init(config: JsValue) -> () = crate::catbird_mls_init);
export_session!(catbird_mls_setup() -> JsValue = crate::catbird_mls_setup);
export_session!(catbird_mls_replenish_key_packages() -> JsValue = crate::catbird_mls_replenish_key_packages);
export_session!(catbird_mls_join_group(convo_id: String) -> JsValue = crate::catbird_mls_join_group);
export_session!(catbird_mls_list_conversations() -> JsValue = crate::catbird_mls_list_conversations);
export_session!(catbird_mls_create_conversation(
    name: String,
    member_dids: Array,
) -> JsValue = crate::catbird_mls_create_conversation);
export_session!(catbird_mls_subscribe(
    convo_id: String,
    on_message: js_sys::Function,
    on_event: js_sys::Function,
    on_status: js_sys::Function,
) -> browser_subscription::CanonicalSubscription = crate::catbird_mls_subscribe);
export_session!(catbird_mls_unsubscribe(_convo_id: String) -> () = crate::catbird_mls_unsubscribe);
export_session!(catbird_mls_send_message(
    convo_id: String,
    content: String,
) -> JsValue = crate::catbird_mls_send_message);
export_session!(catbird_mls_send_image(
    convo_id: String,
    content: String,
    data: Vec<u8>,
    content_type: String,
    width: u32,
    height: u32,
    alt_text: Option<String>,
) -> JsValue = crate::catbird_mls_send_image);
export_session!(catbird_mls_get_image_attachment(
    convo_id: String,
    blob_id: String,
    key_b64: String,
    iv_b64: String,
    sha256: String,
    content_type: String,
) -> String = crate::catbird_mls_get_image_attachment);
export_session!(catbird_mls_messages(
    convo_id: String,
    before: Option<String>,
) -> JsValue = crate::catbird_mls_messages);
export_session!(catbird_mls_fetch_new_messages(convo_id: String) -> JsValue = crate::catbird_mls_fetch_new_messages);
export_session!(catbird_mls_send_reaction(
    conversation_id: String,
    message_id: String,
    emoji: String,
    action: String,
) -> () = crate::catbird_mls_send_reaction);
export_session!(catbird_mls_update_cursor(
    _conversation_id: String,
    _cursor: String,
) -> () = crate::catbird_mls_update_cursor);
export_session!(catbird_mls_get_members(conversation_id: String) -> JsValue = crate::catbird_mls_get_members);
export_session!(catbird_mls_add_group_members(
    conversation_id: String,
    member_dids: Array,
) -> () = crate::catbird_mls_add_group_members);
export_session!(catbird_mls_add_participants(
    conversation_id: String,
    target_did: String,
) -> () = crate::catbird_mls_add_participants);
export_session!(catbird_mls_demote_member(
    _conversation_id: String,
    _target_did: String,
) -> () = crate::catbird_mls_demote_member);
export_session!(catbird_mls_remove_participants(
    conversation_id: String,
    target_did: String,
) -> () = crate::catbird_mls_remove_participants);
export_session!(catbird_mls_leave_conversation(conversation_id: String) -> () = crate::catbird_mls_leave_conversation);
export_session!(catbird_mls_send_typing(
    _conversation_id: String,
    _is_typing: bool,
) -> () = crate::catbird_mls_send_typing);
export_session!(catbird_mls_promote_member(
    _conversation_id: String,
    _target_did: String,
) -> () = crate::catbird_mls_promote_member);
export_session!(catbird_mls_update_group_metadata(
    conversation_id: String,
    title: Option<String>,
    description: Option<String>,
    avatar_blob_locator: Option<String>,
    avatar_content_type: Option<String>,
    avatar_bytes: Option<Vec<u8>>,
) -> JsValue = crate::catbird_mls_update_group_metadata);
export_session!(wasm_bootstrap_group_metadata(group_id_hex: String) -> JsValue = crate::wasm_bootstrap_group_metadata);
export_session!(wasm_republish_metadata_after_reset(
    new_group_id_hex: String,
    reset_generation: Option<u64>,
) -> JsValue = crate::wasm_republish_metadata_after_reset);
export_session!(catbird_mls_get_profiles(dids: Array) -> JsValue = crate::catbird_mls_get_profiles);
export_session!(catbird_mls_search_users(query: String) -> JsValue = crate::catbird_mls_search_users);
export_session!(catbird_mls_check_opt_in_status(dids: Array) -> JsValue = crate::catbird_mls_check_opt_in_status);
export_session!(catbird_mls_run_deferred_recovery() -> JsValue = crate::catbird_mls_run_deferred_recovery);
export_session!(catbird_mls_start_direct_request(input: JsValue) -> JsValue = crate::request_runtime::catbird_mls_start_direct_request);
export_session!(catbird_mls_resume_direct_request(draft_id: String) -> JsValue = crate::request_runtime::catbird_mls_resume_direct_request);
export_session!(catbird_mls_cancel_direct_request(draft_id: String) -> JsValue = crate::request_runtime::catbird_mls_cancel_direct_request);
export_session!(catbird_mls_refresh_request_preview(cid: String) -> JsValue = crate::request_runtime::catbird_mls_refresh_request_preview);
export_session!(catbird_mls_list_direct_request_views() -> JsValue = crate::request_runtime::catbird_mls_list_direct_request_views);
export_session!(catbird_mls_get_direct_request_delivery_enabled() -> JsValue = crate::request_runtime::catbird_mls_get_direct_request_delivery_enabled);
export_session!(catbird_mls_set_direct_request_delivery_enabled(enabled: bool) -> () = crate::request_runtime::catbird_mls_set_direct_request_delivery_enabled);
export_session!(catbird_mls_close_direct_request(cid: String) -> JsValue = crate::request_runtime::catbird_mls_close_direct_request);
export_session!(catbird_mls_accept_direct_request(cid: String) -> JsValue = crate::request_runtime::catbird_mls_accept_direct_request);
export_session!(catbird_mls_get_group_invitation_reference(
    cid: String,
    recipient: String,
) -> JsValue = crate::request_runtime::catbird_mls_get_group_invitation_reference);
export_session!(catbird_mls_request_command(
    command: String,
    args: JsValue,
) -> JsValue = crate::request_runtime::catbird_mls_request_command);
export_session!(catbird_mls_prepare_signed_request(
    operation: String,
    request_json: String,
) -> JsValue = crate::browser_transport::catbird_mls_prepare_signed_request);

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    async fn exported_promises_capture_session_before_first_poll() {
        let request = catbird_mls_request_command("save_request_draft".into(), JsValue::NULL);
        let send = catbird_mls_send_message("unresolved".into(), "must not send".into());
        crate::browser_session::advance();
        for promise in [request, send] {
            let error = wasm_bindgen_futures::JsFuture::from(promise)
                .await
                .unwrap_err();
            assert!(error
                .as_string()
                .unwrap()
                .contains("Browser session changed"));
        }
    }
}

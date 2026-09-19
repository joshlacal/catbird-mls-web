//! Browser UI adapter around the shared request engine. Drafts are protected
//! local input; the shared intent/projection journals remain protocol authority.
use crate::*;
use catbird_mls::orchestrator::mls_provider::MlsCryptoContext;
use catbird_mls::orchestrator::{
    DirectRequestInput, DirectRequestOutcome, MLSOrchestrator, RequestConsent,
};

pub(crate) type BrowserOrchestrator =
    MLSOrchestrator<WasmStorageBackend, WasmApiClient, SqliteCredentialStore, WasmMLSContext>;
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RequestDraft {
    input: DirectRequestInput,
    recipient_label: String,
    phase: String,
    outcome: Option<DirectRequestOutcome>,
    archived: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note_delivery: Option<NoteDelivery>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NoteDelivery {
    conversation_id: String,
    message_id: Option<String>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Workspace {
    owner_did: String,
    delivery_enabled: Option<bool>,
    drafts: Vec<RequestDraft>,
    requests: Vec<catbird_mls::DirectRequestView>,
    discovery_error: Option<String>,
}
fn err(error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}
fn engine(owner: &str) -> Result<Arc<BrowserOrchestrator>, JsValue> {
    with_state(|s| {
        if s.user_did.as_deref() != Some(owner) || !s.request_ready {
            return Err(err(
                "Authenticated request runtime is not ready for this account",
            ));
        }
        s.request_engine
            .clone()
            .ok_or_else(|| err("Request runtime unavailable"))
    })
}
pub(crate) fn current(owner: &str, engine: &Arc<BrowserOrchestrator>) -> Result<(), JsValue> {
    with_state(|s| {
        if s.user_did.as_deref() == Some(owner)
            && s.request_engine
                .as_ref()
                .is_some_and(|e| Arc::ptr_eq(e, engine))
        {
            Ok(())
        } else {
            Err(err(
                "Account changed; request outcome remains protected for reconciliation",
            ))
        }
    })
}
fn owner() -> Result<String, JsValue> {
    with_state(|s| s.user_did.clone().ok_or_else(|| err("Not authenticated")))
}
pub(crate) fn current_engine() -> Result<(String, Arc<BrowserOrchestrator>), JsValue> {
    let did = owner()?;
    let runtime = engine(&did)?;
    Ok((did, runtime))
}
pub(crate) async fn require_ordinary_access(cid: &str) -> Result<(), JsValue> {
    let (did, runtime) = current_engine()?;
    let readiness = runtime.ensure_conversation_ready(cid).await.map_err(err)?;
    current(&did, &runtime)?;
    if !readiness.send_allowed {
        return Err(err(
            "Conversation consent or device readiness does not allow this action",
        ));
    }
    Ok(())
}
pub(crate) async fn synchronize(
    did: &str,
    runtime: &Arc<BrowserOrchestrator>,
    fresh: bool,
) -> Result<(), JsValue> {
    let api = with_state(|s| Ok(s.api_client.clone()))?;
    let actor = runtime
        .credentials()
        .get_device_uuid(did)
        .await
        .map_err(err)?
        .ok_or_else(|| err("Enrolled actor missing"))?;
    crate::browser_inventory::synchronize_inventory(runtime.clone(), api, did, &actor, fresh)
        .await
        .map_err(err)?;
    current(did, runtime)
}
pub(crate) async fn replenish() -> Result<JsValue, JsValue> {
    let (did, runtime) = current_engine()?;
    runtime.replenish_if_needed().await.map_err(err)?;
    runtime
        .replenish_direct_request_keys_if_needed()
        .await
        .map_err(err)?;
    current(&did, &runtime)?;
    to_js(&serde_json::json!({"status":"reconciled"}))
}
fn draft(ctx: &WasmMLSContext, id: &str) -> Result<(Vec<u8>, RequestDraft), JsValue> {
    let raw = ctx
        .request_value("uiDraft", id)
        .map_err(err)?
        .ok_or_else(|| err("Draft not found"))?;
    let value = serde_json::from_slice(&raw).map_err(err)?;
    Ok((raw, value))
}
fn save(
    ctx: &WasmMLSContext,
    value: &RequestDraft,
    expected: Option<&[u8]>,
) -> Result<(), JsValue> {
    let raw = serde_json::to_vec(value).map_err(err)?;
    if !ctx
        .request_value_cas("uiDraft", &value.input.draft_id, expected, &raw)
        .map_err(err)?
    {
        return Err(err(
            "Draft changed while processing; reload its saved state",
        ));
    }
    Ok(())
}

pub(crate) async fn setup() -> Result<JsValue, JsValue> {
    let (did, engine, ctx, creds, api) = with_state(|s| {
        Ok((
            s.user_did.clone().ok_or_else(|| err("Not authenticated"))?,
            s.request_engine
                .clone()
                .ok_or_else(|| err("Request engine unavailable"))?,
            s.mls_context
                .clone()
                .ok_or_else(|| err("Crypto unavailable"))?,
            s.credentials.clone(),
            s.api_client.clone(),
        ))
    })?;
    engine.initialize(&did).await.map_err(err)?;
    let mls_did = if let Some(journal) = creds
        .enrollment(&did)
        .map_err(err)?
        .filter(|j| j.auth_generation.is_some())
    {
        journal.validate_local(&did, &ctx).map_err(err)?;
        journal.mls_did
    } else {
        crate::browser_enrollment::initialize_enrollment(ctx, creds.clone(), api.clone(), &did)
            .await
            .map_err(err)?
    };
    current(&did, &engine)?;
    let device = creds
        .get_device_uuid(&did)
        .await
        .map_err(err)?
        .ok_or_else(|| err("Enrolled actor missing"))?;
    api.bind_actor(&did, &device).map_err(err)?;
    current(&did, &engine)?;
    with_state_mut(|s| {
        s.request_ready = true;
        Ok(())
    })?;
    // Local custody is ready offline. Pool maintenance errors remain visible to
    // the explicit delivery preference command and do not block existing chats.
    wasm_bindgen_futures::spawn_local(async move {
        if current(&did, &engine).is_ok() {
            if let Err(error) = engine.replenish_direct_request_keys_if_needed().await {
                tracing::warn!(%error,"Request key maintenance remains pending");
            }
        }
    });
    to_js(
        &serde_json::json!({"status":"registered","mlsDid":mls_did,"requestKeyMaintenancePending":true}),
    )
}

#[wasm_bindgen]
pub async fn catbird_mls_start_direct_request(input: JsValue) -> Result<JsValue, JsValue> {
    let input: DirectRequestInput = serde_wasm_bindgen::from_value(input).map_err(err)?;
    let did = owner()?;
    let runtime = engine(&did)?;
    let out = runtime.start_direct_request(input).await.map_err(err)?;
    current(&did, &runtime)?;
    to_js(&out)
}
#[wasm_bindgen]
pub async fn catbird_mls_resume_direct_request(draft_id: String) -> Result<JsValue, JsValue> {
    let did = owner()?;
    let runtime = engine(&did)?;
    let out = runtime
        .resume_direct_request(&draft_id)
        .await
        .map_err(err)?;
    current(&did, &runtime)?;
    to_js(&out)
}
#[wasm_bindgen]
pub async fn catbird_mls_cancel_direct_request(draft_id: String) -> Result<JsValue, JsValue> {
    let did = owner()?;
    let runtime = engine(&did)?;
    let out = runtime
        .cancel_direct_request(&draft_id)
        .await
        .map_err(err)?;
    current(&did, &runtime)?;
    to_js(&out)
}
#[wasm_bindgen]
pub async fn catbird_mls_refresh_request_preview(cid: String) -> Result<JsValue, JsValue> {
    let did = owner()?;
    let runtime = engine(&did)?;
    let out = runtime.refresh_request_preview(&cid).await.map_err(err)?;
    current(&did, &runtime)?;
    to_js(&out)
}
#[wasm_bindgen]
pub async fn catbird_mls_list_direct_request_views() -> Result<JsValue, JsValue> {
    let did = owner()?;
    let runtime = engine(&did)?;
    let out = runtime.list_direct_request_views().await.map_err(err)?;
    current(&did, &runtime)?;
    to_js(&out)
}
#[wasm_bindgen]
pub async fn catbird_mls_get_direct_request_delivery_enabled() -> Result<JsValue, JsValue> {
    let did = owner()?;
    let runtime = engine(&did)?;
    let out = runtime
        .get_direct_request_delivery_enabled()
        .await
        .map_err(err)?;
    current(&did, &runtime)?;
    to_js(&out)
}
#[wasm_bindgen]
pub async fn catbird_mls_set_direct_request_delivery_enabled(enabled: bool) -> Result<(), JsValue> {
    let did = owner()?;
    let runtime = engine(&did)?;
    runtime
        .set_direct_request_delivery_enabled(enabled)
        .await
        .map_err(err)?;
    current(&did, &runtime)
}
#[wasm_bindgen]
pub async fn catbird_mls_close_direct_request(cid: String) -> Result<JsValue, JsValue> {
    let did = owner()?;
    let runtime = engine(&did)?;
    let out = runtime.close_direct_request(&cid).await.map_err(err)?;
    current(&did, &runtime)?;
    to_js(&out)
}
#[wasm_bindgen]
pub async fn catbird_mls_accept_direct_request(cid: String) -> Result<JsValue, JsValue> {
    let did = owner()?;
    let runtime = engine(&did)?;
    let views = runtime.list_direct_request_views().await.map_err(err)?;
    if !views.iter().any(|v| {
        v.conversation_id == cid
            && v.consent == RequestConsent::IncomingPending
            && v.capabilities.can_accept
    }) {
        return Err(err("No verified incoming request available for acceptance"));
    }
    runtime.accept_conversation(&cid).await.map_err(err)?;
    current(&did, &runtime)?;
    let out = runtime.refresh_request_preview(&cid).await.map_err(err)?;
    current(&did, &runtime)?;
    to_js(&out)
}

#[wasm_bindgen]
pub async fn catbird_mls_get_group_invitation_reference(
    cid: String,
    recipient: String,
) -> Result<JsValue, JsValue> {
    let (did, runtime) = current_engine()?;
    let result = runtime
        .get_group_invitation_reference(&cid, &recipient)
        .await
        .map_err(err)?;
    current(&did, &runtime)?;
    to_js(&result)
}

/// Host presentation commands share the exact draft shape with native Catmos.
#[wasm_bindgen]
pub async fn catbird_mls_request_command(
    command: String,
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let args: serde_json::Value = serde_wasm_bindgen::from_value(args).map_err(err)?;
    let did = args["ownerDid"]
        .as_str()
        .ok_or_else(|| err("Missing request account"))?;
    let runtime = engine(did)?;
    let ctx = runtime.mls_context();
    match command.as_str() {
        "get_request_workspace" => {
            let discovery_error = synchronize(did, &runtime, true).await.err().map(|_| {
                "New requests could not be checked. Saved requests remain available.".to_owned()
            });
            let requests = runtime.list_direct_request_views().await.map_err(err)?;
            let delivery_enabled = runtime
                .get_direct_request_delivery_enabled()
                .await
                .map_err(err)?;
            let drafts = ctx
                .request_values("uiDraft")
                .map_err(err)?
                .into_iter()
                .map(|r| serde_json::from_slice(&r).map_err(err))
                .collect::<Result<Vec<_>, _>>()?;
            current(did, &runtime)?;
            to_js(&Workspace {
                owner_did: did.to_owned(),
                delivery_enabled,
                drafts,
                requests,
                discovery_error,
            })
        }
        "save_request_draft" => {
            let input: DirectRequestInput =
                serde_json::from_value(args["input"].clone()).map_err(err)?;
            let label = args["recipientLabel"]
                .as_str()
                .ok_or_else(|| err("Invalid recipient label"))?;
            catbird_mls::chat_v2::ids::CanonicalUuid::parse(&input.draft_id).map_err(err)?;
            catbird_mls::chat_v2::ids::BareDid::parse(&input.recipient_did).map_err(err)?;
            if input.recipient_did == did || input.text.len() > 16384 || label.len() > 256 {
                return Err(err("Invalid request draft"));
            }
            let old = ctx.request_value("uiDraft", &input.draft_id).map_err(err)?;
            if let Some(raw) = &old {
                let old: RequestDraft = serde_json::from_slice(raw).map_err(err)?;
                if old.phase != "draft" {
                    if old.input == input {
                        return to_js(&old);
                    }
                    return Err(err("Attempted request input is immutable"));
                }
            }
            let value = RequestDraft {
                input,
                recipient_label: label.into(),
                phase: "draft".into(),
                outcome: None,
                archived: false,
                note_delivery: None,
            };
            save(ctx, &value, old.as_deref())?;
            to_js(&value)
        }
        "submit_request_draft" | "resume_request_draft" | "cancel_request_draft" => {
            let id = args["draftId"]
                .as_str()
                .ok_or_else(|| err("Missing draft ID"))?;
            let (old, mut value) = draft(ctx, id)?;
            if value.archived {
                return Err(err("Draft is archived"));
            }
            if command == "cancel_request_draft" && value.phase == "draft" {
                value.archived = true;
                save(ctx, &value, Some(&old))?;
                return to_js(&value);
            }
            value.phase = "attempted".into();
            save(ctx, &value, Some(&old))?;
            let attempted = serde_json::to_vec(&value).map_err(err)?;
            let result = match command.as_str() {
                "submit_request_draft" => runtime.start_direct_request(value.input.clone()).await,
                "resume_request_draft" => runtime.resume_direct_request(id).await,
                _ => runtime.cancel_direct_request(id).await,
            };
            current(did, &runtime)?;
            let outcome=result.map_err(|_|err("Delivery is not confirmed. The exact request is retained; check delivery before creating another."))?;
            value.phase = if matches!(outcome, DirectRequestOutcome::OutcomeUnknown { .. }) {
                "checking"
            } else {
                "resolved"
            }
            .into();
            value.outcome = Some(outcome);
            save(ctx, &value, Some(&attempted))?;
            to_js(&value)
        }
        "send_existing_invitation_note" => {
            let id = args["draftId"]
                .as_str()
                .ok_or_else(|| err("Missing draft ID"))?;
            let (old, mut value) = draft(ctx, id)?;
            if value.archived || value.note_delivery.is_some() {
                return Err(err(
                    "This note was already attempted. Open the conversation to check delivery.",
                ));
            }
            let cid = match &value.outcome {
                Some(DirectRequestOutcome::ExistingDirect {
                    conversation_id,
                    requires_acceptance: false,
                }) => conversation_id.clone(),
                _ => {
                    return Err(err(
                        "An accepted direct conversation is required; no note was sent",
                    ))
                }
            };
            let reference = value
                .input
                .invitation
                .clone()
                .ok_or_else(|| err("Draft has no group invitation"))?;
            if reference.recipient_did != value.input.recipient_did {
                return Err(err("Invitation recipient changed"));
            }
            require_ordinary_access(&cid).await?;
            current(did, &runtime)?;
            let embed = catbird_mls::orchestrator::MLSEmbedData::group_invitation(reference)
                .map_err(err)?;
            // The shared send repeats fresh invitation/destination validation.
            // Retain a durable attempt first; ordinary sends are never retried
            // with a new message ID after an uncertain delivery.
            value.note_delivery = Some(NoteDelivery {
                conversation_id: cid.clone(),
                message_id: None,
            });
            save(ctx, &value, Some(&old))?;
            let attempted = serde_json::to_vec(&value).map_err(err)?;
            let sent = runtime
                .send_message_with_embed(&cid, &value.input.text, embed)
                .await;
            current(did, &runtime)?;
            let message=sent.map_err(|_|err("Invitation note delivery is not confirmed. Your text is retained; open the conversation before composing another note."))?;
            value.note_delivery.as_mut().unwrap().message_id = Some(message.id);
            value.archived = true;
            save(ctx, &value, Some(&attempted))?;
            to_js(&value)
        }
        "get_group_invitation_reference" => {
            let cid = args["conversationId"]
                .as_str()
                .ok_or_else(|| err("Missing conversation"))?;
            let recipient = args["recipientDid"]
                .as_str()
                .ok_or_else(|| err("Missing recipient"))?;
            let reference = runtime
                .get_group_invitation_reference(cid, recipient)
                .await
                .map_err(err)?;
            current(did, &runtime)?;
            to_js(&reference)
        }
        "refresh_direct_request" => {
            catbird_mls_refresh_request_preview(
                args["conversationId"]
                    .as_str()
                    .ok_or_else(|| err("Missing conversation"))?
                    .into(),
            )
            .await
        }
        "accept_direct_request" => {
            catbird_mls_accept_direct_request(
                args["conversationId"]
                    .as_str()
                    .ok_or_else(|| err("Missing conversation"))?
                    .into(),
            )
            .await
        }
        "close_direct_request" => {
            catbird_mls_close_direct_request(
                args["conversationId"]
                    .as_str()
                    .ok_or_else(|| err("Missing conversation"))?
                    .into(),
            )
            .await
        }
        "set_request_delivery_enabled" => {
            catbird_mls_set_direct_request_delivery_enabled(
                args["enabled"]
                    .as_bool()
                    .ok_or_else(|| err("Invalid preference"))?,
            )
            .await?;
            Ok(JsValue::UNDEFINED)
        }
        "request_sender" => {
            let cid = args["conversationId"]
                .as_str()
                .ok_or_else(|| err("Missing conversation"))?;
            let views = runtime.list_direct_request_views().await.map_err(err)?;
            current(did, &runtime)?;
            let view = views
                .into_iter()
                .find(|v| v.conversation_id == cid && v.consent == RequestConsent::IncomingPending)
                .ok_or_else(|| err("Verified incoming request unavailable"))?;
            to_js(
                &view
                    .introduction
                    .ok_or_else(|| err("Sender proof unavailable"))?
                    .sender_did,
            )
        }
        _ => Err(err("Unknown request command")),
    }
}

#[cfg(all(test, feature = "inventory-worker-tests"))]
pub(crate) mod tests {
    use super::*;
    use wasm_bindgen_test::*;
    #[wasm_bindgen(inline_js = r#"
 let previousFetch;let preparation=[];let cancellation=[];let queued=new Map();let latest=new Map();let history=[];let allowSend=false;let sentEntry;
 export function installRequestFacadeFixture(doc){
  previousFetch=globalThis.fetch;preparation=[];cancellation=[];queued=new Map();latest=new Map();history=[];allowSend=false;sentEntry=undefined;
  globalThis.fetch=async(input,options)=>{
   const url=typeof input==='string'?input:input.url;
   const response=(body,status=200)=>{history.push([new URL(url).pathname.split('.').pop(),status]);const r=new Response(JSON.stringify(body),{status,headers:{'content-type':'application/json'}});Object.defineProperty(r,'url',{value:url});return r;};
   const endpoint=new URL(url).pathname.split('.').pop();
   if(typeof input!=='string'){latest.set(endpoint,await input.clone().text());}
   const pending=queued.get(endpoint);if(pending?.length){const [body,status]=pending.shift();return response(JSON.parse(body),status);}
   if(endpoint==='sendMessage'&&allowSend){const signedRequest=JSON.parse(await input.clone().text()).signedRequest;sentEntry={entryId:crypto.randomUUID(),conversationId:signedRequest.body.prior.conversationId,seq:3,signedRequest,receivedAt:new Date().toISOString()};return response({entry:sentEntry});}
   if(url==='https://chat.catbird.blue/.well-known/did.json')return response(JSON.parse(doc));
   if(url.includes('.enrollDevice')){const b=JSON.parse(await input.clone().text()).signedRequest.body;return response({device:{deviceId:b.deviceId,keyId:b.keyId,signaturePublicKey:{$bytes:b.signaturePublicKey},authGeneration:7,status:'active',availablePackageCount:1,reservedPackageCount:0,createdAt:'2026-09-19T12:00:00.000Z',updatedAt:'2026-09-19T12:00:00.000Z'}});}
   if(url.includes('.getConversations'))return response({items:[],hasMore:false,inventorySessionId:'s'.repeat(32),snapshotEventCursor:'cursor',snapshotExpiresAt:'2099-01-01T00:00:00.000Z',inventoryScope:{supportedProtocolVersions:['1','2'],scopeDigest:btoa(String.fromCharCode(...new Array(32).fill(7)))}});
   if(url.includes('.prepareDirectRequest')){preparation.push(await input.clone().text());throw new Error('injected uncertain preparation');}
   if(url.includes('.cancelDirectRequestPreparation')){cancellation.push(await input.clone().text());throw new Error('injected uncertain cancellation');}
   return response({error:'FixtureOffline'},503);
  };
 }
 export function enqueueFacade(endpoint,body,status){if(!queued.has(endpoint))queued.set(endpoint,[]);queued.get(endpoint).push([body,status]);}
 export function lastFacade(endpoint){return latest.get(endpoint)||'';}
 export function enableFacadeSend(){allowSend=true;}
 export function sentFacadeEntry(){return JSON.stringify(sentEntry);}
 export function facadeHistory(){return JSON.stringify(history.slice(-15));}
 export function preparationCount(){return preparation.length;}
 export function cancellationCount(){return cancellation.length;}
 export function exactPreparations(){return preparation.length>=2&&preparation.every(x=>x===preparation[0]);}
 export function exactCancellations(){return cancellation.length>=2&&cancellation.every(x=>x===cancellation[0]);}
 export function restoreRequestFacadeFixture(){globalThis.fetch=previousFetch;}
 "#)]
    extern "C" {
        pub(crate) fn installRequestFacadeFixture(doc: &str);
        fn enqueueFacade(endpoint: &str, body: &str, status: u16);
        fn lastFacade(endpoint: &str) -> String;
        fn facadeHistory() -> String;
        fn enableFacadeSend();
        fn sentFacadeEntry() -> String;
        fn preparationCount() -> u32;
        fn cancellationCount() -> u32;
        fn exactPreparations() -> bool;
        fn exactCancellations() -> bool;
        fn restoreRequestFacadeFixture();
    }
    pub(crate) struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            restoreRequestFacadeFixture();
            STATE.with(|s| *s.borrow_mut() = None);
        }
    }
    pub(crate) async fn initialize(prefix: &str, owner: &str) {
        crate::catbird_mls_init(js_sys::JSON::parse(&serde_json::json!({"baseUrl":"https://facade.invalid","dbPrefix":prefix,"mlsDbKey":"bd".repeat(32)}).to_string()).unwrap()).await.unwrap();
        crate::catbird_mls_set_auth(owner.into(), "fixture-session".into()).unwrap();
        crate::catbird_mls_set_content_root_key(vec![91; 32]).unwrap();
        setup().await.unwrap();
    }
    #[wasm_bindgen_test]
    async fn shared_facade_retains_uncertain_prepare_and_cancel_through_restart() {
        use base64::engine::general_purpose::STANDARD_NO_PAD;
        let key = p256::ecdsa::SigningKey::from_slice(&[41; 32]).unwrap();
        let point = key.verifying_key().to_encoded_point(true);
        let id = catbird_mls::chat_v2::transcript::direct_request::direct_request_receipt_key_id(
            point.as_bytes(),
        )
        .unwrap();
        let mut multikey = vec![0x80, 0x24];
        multikey.extend(point.as_bytes());
        let doc = serde_json::json!({"id":"did:web:chat.catbird.blue","verificationMethod":[{"id":id,"controller":"did:web:chat.catbird.blue","type":"Multikey","publicKeyMultibase":format!("m{}",STANDARD_NO_PAD.encode(multikey))}]});
        installRequestFacadeFixture(&doc.to_string());
        let _restore = Restore;
        let owner = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
        let prefix = format!("facade-{}", uuid::Uuid::new_v4());
        initialize(&prefix, owner).await;
        let input = DirectRequestInput {
            draft_id: uuid::Uuid::new_v4().to_string(),
            recipient_did: "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".into(),
            text: "Protected draft content".into(),
            invitation: None,
        };
        let outcome = catbird_mls_start_direct_request(to_js(&input).unwrap())
            .await
            .unwrap();
        let outcome: DirectRequestOutcome = serde_wasm_bindgen::from_value(outcome).unwrap();
        assert!(matches!(
            outcome,
            DirectRequestOutcome::OutcomeUnknown { .. }
        ));
        assert_eq!(preparationCount(), 1);
        let raw = with_state(|s| {
            Ok(s.mls_context
                .as_ref()
                .unwrap()
                .read_direct_request_intent(&input.draft_id)
                .unwrap()
                .unwrap())
        })
        .unwrap();
        STATE.with(|s| *s.borrow_mut() = None);
        initialize(&prefix, owner).await;
        let outcome = catbird_mls_resume_direct_request(input.draft_id.clone())
            .await
            .unwrap();
        let outcome: DirectRequestOutcome = serde_wasm_bindgen::from_value(outcome).unwrap();
        assert!(matches!(
            outcome,
            DirectRequestOutcome::OutcomeUnknown { .. }
        ));
        assert!(exactPreparations());
        assert_eq!(
            with_state(|s| Ok(s
                .mls_context
                .as_ref()
                .unwrap()
                .read_direct_request_intent(&input.draft_id)
                .unwrap()
                .unwrap()))
            .unwrap(),
            raw
        );
        let mut changed = input.clone();
        changed.text = "Different content".into();
        assert!(catbird_mls_start_direct_request(to_js(&changed).unwrap())
            .await
            .is_err());
        assert_eq!(preparationCount(), 2);
        catbird_mls_cancel_direct_request(input.draft_id.clone())
            .await
            .unwrap();
        assert_eq!(cancellationCount(), 1);
        STATE.with(|s| *s.borrow_mut() = None);
        initialize(&prefix, owner).await;
        catbird_mls_resume_direct_request(input.draft_id.clone())
            .await
            .unwrap();
        assert!(exactCancellations());
        assert_eq!(preparationCount(), 2);
        assert!(
            with_state(|s| Ok(s
                .mls_context
                .as_ref()
                .unwrap()
                .list_direct_request_journal()
                .unwrap()
                .is_empty()))
            .unwrap(),
            "No private group before verified preparation"
        );
        crate::catbird_mls_clear_auth().unwrap();
        assert!(catbird_mls_resume_direct_request(input.draft_id)
            .await
            .is_err());
    }
    pub(crate) fn enqueue(endpoint: &str, body: serde_json::Value) {
        enqueueFacade(endpoint, &body.to_string(), 200);
    }
    fn last(endpoint: &str) -> serde_json::Value {
        serde_json::from_str(&lastFacade(endpoint)).unwrap()
    }
    fn utc(seconds: i64) -> String {
        (chrono::Utc::now() + chrono::Duration::seconds(seconds))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }
    fn sign_receipt(key: &p256::ecdsa::SigningKey, bytes: &[u8]) -> String {
        use p256::ecdsa::signature::Signer;
        let signature: p256::ecdsa::Signature = key.sign(bytes);
        B64.encode(signature.normalize_s().unwrap_or(signature).to_bytes())
    }
    #[wasm_bindgen_test]
    async fn shared_sender_publication_and_recipient_preview_survive_browser_restart() {
        published_request_scenario(false).await;
    }
    #[wasm_bindgen_test]
    async fn shared_unaddressed_device_closes_request_without_native_group() {
        published_request_scenario(true).await;
    }
    async fn published_request_scenario(unaddressed: bool) {
        use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
        use catbird_mls::chat_v2::transcript::direct_request as protocol;
        use serde_json::json;
        use sha2::{Digest, Sha256};
        let authority = p256::ecdsa::SigningKey::from_slice(&[41; 32]).unwrap();
        let point = authority.verifying_key().to_encoded_point(true);
        let method = protocol::direct_request_receipt_key_id(point.as_bytes()).unwrap();
        let mut multikey = vec![0x80, 0x24];
        multikey.extend(point.as_bytes());
        let doc = json!({"id":"did:web:chat.catbird.blue","verificationMethod":[{"id":method,"controller":"did:web:chat.catbird.blue","type":"Multikey","publicKeyMultibase":format!("m{}",STANDARD_NO_PAD.encode(multikey))}]});
        installRequestFacadeFixture(&doc.to_string());
        let _restore = Restore;
        let alice = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
        let bob = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
        let apath = format!("facade-a-{}", uuid::Uuid::new_v4());
        let bpath = format!("facade-b-{}", uuid::Uuid::new_v4());
        initialize(&bpath, bob).await;
        let (_, bob_runtime) = current_engine().unwrap();
        let bob_device = bob_runtime
            .credentials()
            .get_device_uuid(bob)
            .await
            .unwrap()
            .unwrap();
        let bid = format!("{bob}#{bob_device}").into_bytes();
        let package = bob_runtime
            .mls_context()
            .create_key_package(bid.clone())
            .unwrap();
        let bob_public = package.signature_public_key.clone();
        STATE.with(|s| *s.borrow_mut() = None);
        initialize(&apath, alice).await;
        let input = DirectRequestInput {
            draft_id: uuid::Uuid::new_v4().to_string(),
            recipient_did: bob.into(),
            text: "Browser first message before consent".into(),
            invitation: None,
        };
        catbird_mls_start_direct_request(to_js(&input).unwrap())
            .await
            .unwrap();
        let original = last("prepareDirectRequest");
        let prepare = &original["signedRequest"]["body"];
        let (_, alice_runtime) = current_engine().unwrap();
        let device = alice_runtime
            .credentials()
            .get_device_uuid(alice)
            .await
            .unwrap()
            .unwrap();
        let public = alice_runtime
            .mls_context()
            .identity_public_key(format!("{alice}#{device}").into_bytes())
            .unwrap();
        let verified = protocol::verify_signed_request(
            protocol::DirectRequestKind::Prepare,
            &serde_json::to_vec(&original["signedRequest"]).unwrap(),
            &public,
        )
        .unwrap();
        let grant_id = uuid::Uuid::new_v4().to_string();
        let grant = json!({"$type":"blue.catbird.chat.defs#directRequestGrantBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-GRANT\0","protocolVersion":"2","actorDid":bob,"actorDeviceId":bob_device,"keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public)),"authGeneration":7,"grantId":grant_id,"grantRevision":1,"purpose":"direct-request-bootstrap","profile":"encryptedIntroduction1","keyPackageRef":B64.encode(&package.hash_ref),"keyPackageSha256":B64.encode(Sha256::digest(&package.key_package_data)),"expiresAt":utc(20*86400),"idempotencyKey":grant_id,"signedAt":utc(0)});
        let signature = bob_runtime
            .mls_context()
            .sign_with_identity_key(
                bid,
                protocol::direct_request_signing_bytes(
                    protocol::DirectRequestKind::Grant,
                    &serde_json::to_vec(&grant).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let selected = json!({"actorDid":bob,"actorDeviceId":bob_device,"keyId":grant["keyId"],"authGeneration":7,"keyPackage":{"framing":"mlsMessage","contentType":"keyPackage","bytes":B64.encode(&package.key_package_data),"sha256":B64.encode(Sha256::digest(&package.key_package_data)),"keyPackageRef":B64.encode(&package.hash_ref)},"grant":{"body":grant,"signature":B64.encode(signature)}});
        let mut preparation = json!({"protocolVersion":"2","requestId":prepare["requestId"],"firstMessageId":prepare["firstMessageId"],"conversationId":prepare["conversationId"],"recipientDid":bob,"origin":prepare["origin"],"profile":prepare["profile"],"creator":{"actorDid":prepare["actorDid"],"actorDeviceId":device,"keyId":prepare["keyId"],"authGeneration":7},"selectedDevices":[selected],"preparedAt":utc(0),"leaseExpiresAt":utc(300),"minimumImportUntil":utc(7*86400+300-5),"preparationRequestDigest":B64.encode(verified.request_digest()),"authorityDid":"did:web:chat.catbird.blue","receiptKeyId":method});
        let signing = protocol::direct_request_preparation_signing_bytes(
            &serde_json::to_vec(&preparation).unwrap(),
        )
        .unwrap();
        preparation["preparationDigest"] = json!(B64.encode(Sha256::digest(&signing)));
        preparation["preparationSignature"] = json!(sign_receipt(&authority, &signing));
        enqueue(
            "prepareDirectRequest",
            json!({"outcome":{"$type":"blue.catbird.chat.defs#directRequestPreparedOutcome","preparation":preparation}}),
        );
        catbird_mls_resume_direct_request(input.draft_id.clone())
            .await
            .unwrap();
        let publication = last("publishDirectRequest");
        let p = &publication["signedRequest"]["body"];
        let signed = protocol::verify_signed_request(
            protocol::DirectRequestKind::Publish,
            &serde_json::to_vec(&publication["signedRequest"]).unwrap(),
            &public,
        )
        .unwrap();
        let body = json!({"$type":"blue.catbird.chat.defs#directRequestReceiptBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-OUTCOME\0","protocolVersion":"2","authorityDid":"did:web:chat.catbird.blue","keyId":method,"receipt":{"$type":"blue.catbird.chat.defs#directRequestPublishedReceipt","requestId":p["requestId"],"requestKind":"publish","requestDigest":B64.encode(signed.request_digest()),"preparationRequestDigest":B64.encode(verified.request_digest()),"actorDid":alice,"actorDeviceId":device,"actorKeyId":p["keyId"],"authGeneration":7,"conversationId":p["conversationId"],"firstMessageId":p["firstMessageId"],"coordinates":p["next"],"recordedAt":utc(0)}});
        let receipt = json!({"$type":"blue.catbird.chat.defs#signedDirectRequestReceipt","signature":sign_receipt(&authority,&protocol::direct_request_signing_bytes(protocol::DirectRequestKind::Outcome,&serde_json::to_vec(&body).unwrap()).unwrap()),"body":body});
        enqueue("publishDirectRequest", json!({"outcome":receipt}));
        let sent: DirectRequestOutcome = serde_wasm_bindgen::from_value(
            catbird_mls_resume_direct_request(input.draft_id.clone())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(sent, DirectRequestOutcome::RequestSent { .. }));
        assert_eq!(publication, last("publishDirectRequest"));
        let cid = p["conversationId"].as_str().unwrap();
        let entry = json!({"$type":"blue.catbird.chat.defs#directRequestEntry","entryId":uuid::Uuid::new_v4().to_string(),"conversationId":cid,"seq":1,"signedRequest":publication["signedRequest"],"receivedAt":receipt["body"]["receipt"]["recordedAt"]});
        drop(bob_runtime);
        drop(alice_runtime);
        STATE.with(|s| *s.borrow_mut() = None);
        let bpath = if unaddressed {
            format!("facade-unaddressed-{}", uuid::Uuid::new_v4())
        } else {
            bpath
        };
        initialize(&bpath, bob).await;
        enqueue(
            "getEntries",
            json!({"entries":[entry],"hasMore":false,"nextAfterSeq":1}),
        );
        enqueue("getDirectRequestOutcome", json!({"outcome":receipt}));
        let view: catbird_mls::DirectRequestView = serde_wasm_bindgen::from_value(
            catbird_mls_refresh_request_preview(cid.into())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(view.consent, RequestConsent::IncomingPending);
        if unaddressed {
            assert_eq!(view.crypto, catbird_mls::RequestCrypto::Unavailable);
            assert_eq!(
                view.preview,
                Some(catbird_mls::RequestPreview::Unavailable {
                    code: "DeviceNotAddressed".into()
                })
            );
            let pending_state = json!({"conversationKind":"direct","coordinates":p["next"],"cipherSuite":"MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519","participants":[{"userDid":p["actorDid"],"role":"admin","status":"active","leafCount":1},{"userDid":p["recipientDid"],"role":"admin","status":"pending","leafCount":1,"invitationProvenance":{"invitationTransitionId":p["requestId"],"invitedByDid":p["actorDid"],"invitedByDeviceId":p["actorDeviceId"]}}],"leaves":[{"userDid":p["actorDid"],"deviceId":p["actorDeviceId"],"leafOrigin":"genesis","keyId":p["keyId"],"deviceStatus":"active"},{"userDid":p["recipientDid"],"deviceId":bob_device,"leafOrigin":"keyPackage","joinKeyPackageRef":B64.encode(&package.hash_ref),"keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public)),"deviceStatus":"active"}],"metadataSnapshot":p["artifacts"]["metadataSnapshot"],"snapshotSeq":1,"directRequest":{"requestId":p["requestId"],"firstMessageId":p["firstMessageId"],"senderDid":p["actorDid"],"recipientDid":p["recipientDid"],"consent":"incomingPending","importUntil":p["importUntil"],"contextHash":p["contextHash"],"preparationDigest":p["preparationDigest"]}});
            let (_, runtime) = current_engine().unwrap();
            assert!(runtime
                .mls_context()
                .get_epoch(B64.decode(p["next"]["groupId"].as_str().unwrap()).unwrap())
                .is_err());
            drop(runtime);
            close_with_restart(&bpath, bob, cid, p, &pending_state, 2).await;
            return;
        }
        let fixture = PublishedFixture {
            apath: &apath,
            bpath: &bpath,
            alice,
            bob,
            cid,
            p,
            bob_device: &bob_device,
            bob_public: &bob_public,
            key_package_ref: &package.hash_ref,
            preview_text: &input.text,
        };
        // Separate boxed stages keep this debug-only test from retaining a giant
        // poll frame above the real runtime. Product stack settings are unchanged.
        let accepted_state =
            Box::pin(accept_published_request(fixture, view, &authority, &method)).await;
        Box::pin(exchange_accepted_reply(fixture, &accepted_state)).await;
        close_with_restart(&bpath, bob, cid, p, &accepted_state, 4).await;
    }
    #[derive(Clone, Copy)]
    struct PublishedFixture<'a> {
        apath: &'a str,
        bpath: &'a str,
        alice: &'a str,
        bob: &'a str,
        cid: &'a str,
        p: &'a serde_json::Value,
        bob_device: &'a str,
        bob_public: &'a [u8],
        key_package_ref: &'a [u8],
        preview_text: &'a str,
    }
    async fn accept_published_request(
        fixture: PublishedFixture<'_>,
        view: catbird_mls::DirectRequestView,
        authority: &p256::ecdsa::SigningKey,
        method: &str,
    ) -> serde_json::Value {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use catbird_mls::chat_v2::transcript::direct_request as protocol;
        use serde_json::json;
        use sha2::{Digest, Sha256};
        let PublishedFixture {
            bpath,
            bob,
            cid,
            p,
            bob_device,
            bob_public,
            key_package_ref,
            preview_text,
            ..
        } = fixture;
        assert_eq!(view.crypto, catbird_mls::RequestCrypto::Ready);
        assert_eq!(
            view.preview,
            Some(catbird_mls::RequestPreview::Ready {
                text: preview_text.to_owned(),
                invitation: None
            })
        );
        assert!(
            !view.capabilities.can_send
                && !view.capabilities.can_emit_receipts
                && !view.capabilities.can_administer
        );
        STATE.with(|s| *s.borrow_mut() = None);
        initialize(bpath, bob).await;
        let views: Vec<catbird_mls::DirectRequestView> =
            serde_wasm_bindgen::from_value(catbird_mls_list_direct_request_views().await.unwrap())
                .unwrap();
        assert_eq!(views[0].preview, view.preview);
        assert_eq!(views[0].consent, RequestConsent::IncomingPending);
        assert!(
            catbird_mls_send_message(cid.into(), "Forbidden before acceptance".into())
                .await
                .is_err()
        );
        assert!(catbird_mls_accept_direct_request(cid.into()).await.is_err());
        let pending_accept = last("acceptConversation");
        let accepted = &pending_accept["directRequest"]["body"];
        let verified_accept = protocol::verify_signed_request(
            protocol::DirectRequestKind::Accept,
            &serde_json::to_vec(&pending_accept["directRequest"]).unwrap(),
            bob_public,
        )
        .unwrap();
        STATE.with(|s| *s.borrow_mut() = None);
        initialize(bpath, bob).await;
        let accept_entry = json!({"entryId":uuid::Uuid::new_v4().to_string(),"conversationId":cid,"seq":2,"signedRequest":pending_accept["directRequest"],"receivedAt":utc(0)});
        let accepted_receipt = json!({"$type":"blue.catbird.chat.defs#directRequestAcceptanceCommitReceiptBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-ACCEPTANCE-COMMIT\0","protocolVersion":"2","authorityDid":"did:web:chat.catbird.blue","keyId":method,"requestId":accepted["requestId"],"acceptanceDigest":B64.encode(verified_accept.request_digest()),"entryHash":B64.encode(protocol::direct_request_acceptance_entry_hash(&serde_json::to_vec(&accept_entry).unwrap()).unwrap()),"prior":accepted["prior"],"next":accepted["next"],"recordedAt":utc(0)});
        let proof = json!({"entry":accept_entry,"receipt":{"body":accepted_receipt,"signature":sign_receipt(authority,&protocol::direct_request_signing_bytes(protocol::DirectRequestKind::AcceptanceCommit,&serde_json::to_vec(&accepted_receipt).unwrap()).unwrap())}});
        enqueue(
            "acceptConversation",
            json!({"coordinates":accepted["next"],"acceptanceProof":proof}),
        );
        let accepted_view: catbird_mls::DirectRequestView = serde_wasm_bindgen::from_value(
            catbird_mls_accept_direct_request(cid.into()).await.unwrap(),
        )
        .unwrap();
        assert_eq!(accepted_view.consent, RequestConsent::Accepted);
        assert!(accepted_view.capabilities.can_send);
        assert_eq!(pending_accept, last("acceptConversation"));
        assert_eq!(accepted["prior"]["epoch"], accepted["next"]["epoch"]);
        STATE.with(|s| *s.borrow_mut() = None);
        initialize(bpath, bob).await;
        let views: Vec<catbird_mls::DirectRequestView> =
            serde_wasm_bindgen::from_value(catbird_mls_list_direct_request_views().await.unwrap())
                .unwrap();
        assert_eq!(views[0].consent, RequestConsent::Accepted);
        let accepted_state = json!({"conversationKind":"direct","coordinates":accepted["next"],"cipherSuite":"MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519","participants":[{"userDid":p["actorDid"],"role":"admin","status":"active","leafCount":1},{"userDid":p["recipientDid"],"role":"admin","status":"active","leafCount":1,"invitationProvenance":{"invitationTransitionId":p["requestId"],"invitedByDid":p["actorDid"],"invitedByDeviceId":p["actorDeviceId"]}}],"leaves":[{"userDid":p["actorDid"],"deviceId":p["actorDeviceId"],"leafOrigin":"genesis","keyId":p["keyId"],"deviceStatus":"active"},{"userDid":p["recipientDid"],"deviceId":bob_device,"leafOrigin":"keyPackage","joinKeyPackageRef":B64.encode(key_package_ref),"keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(bob_public)),"deviceStatus":"active"}],"metadataSnapshot":p["artifacts"]["metadataSnapshot"],"snapshotSeq":2,"directRequest":{"requestId":p["requestId"],"firstMessageId":p["firstMessageId"],"senderDid":p["actorDid"],"recipientDid":p["recipientDid"],"consent":"accepted","importUntil":p["importUntil"],"contextHash":p["contextHash"],"preparationDigest":p["preparationDigest"],"acceptanceProof":proof}});
        accepted_state
    }
    async fn exchange_accepted_reply(
        fixture: PublishedFixture<'_>,
        accepted_state: &serde_json::Value,
    ) {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use serde_json::json;
        use sha2::{Digest, Sha256};
        let PublishedFixture {
            apath,
            bpath,
            alice,
            bob,
            cid,
            p,
            bob_device,
            bob_public,
            ..
        } = fixture;
        enqueue("getConversationState", json!({"state":accepted_state}));
        catbird_mls_refresh_request_preview(cid.into())
            .await
            .unwrap();
        enqueue(
            "getEntries",
            json!({"entries":[],"hasMore":false,"nextAfterSeq":0}),
        );
        enqueue("getConversationState", json!({"state":accepted_state}));
        enableFacadeSend();
        let reply =
            catbird_mls_send_message(cid.into(), "Browser reply after acceptance".into()).await;
        assert!(
            reply.is_ok(),
            "ordinary reply failed: {:?}; history={}",
            reply.as_ref().err(),
            facadeHistory()
        );
        let reply: Message = serde_wasm_bindgen::from_value(reply.unwrap()).unwrap();
        assert_eq!(reply.content, "Browser reply after acceptance");
        let mut application_entry: serde_json::Value =
            serde_json::from_str(&sentFacadeEntry()).unwrap();
        application_entry["$type"] = json!("blue.catbird.chat.defs#applicationEntry");
        let (_, bob_engine) = current_engine().unwrap();
        let own = catbird_mls::orchestrator::IncomingEnvelope::from_canonical_entry(
            &application_entry,
            cid,
        )
        .unwrap()
        .unwrap();
        assert!(bob_engine
            .process_incoming_message(&own)
            .await
            .unwrap()
            .message
            .is_none());
        let gid = B64.decode(p["next"]["groupId"].as_str().unwrap()).unwrap();
        let (echo_epoch, echo_aad, echo_ciphertext) = match bob_engine
            .mls_context()
            .decrypt_message_outcome(gid.clone(), own.ciphertext.clone())
            .unwrap()
        {
            catbird_mls::orchestrator::mls_provider::MlsDecryptOutcome::OwnPrivateMessage {
                epoch,
                aad_sha256,
                ciphertext_sha256,
            } => (epoch, aad_sha256, ciphertext_sha256),
            _ => panic!("Expected typed own application with actual AAD"),
        };
        assert_eq!(
            echo_ciphertext,
            <[u8; 32]>::from(Sha256::digest(&own.ciphertext))
        );
        drop(bob_engine);
        STATE.with(|s| *s.borrow_mut() = None);
        initialize(bpath, bob).await;
        let (_, reopened) = current_engine().unwrap();
        assert!(reopened
            .mls_context()
            .has_own_echo_proof(
                cid,
                &gid,
                own.server_message_id.as_deref().unwrap(),
                echo_epoch,
                &echo_aad,
                &echo_ciphertext
            )
            .unwrap());
        assert!(!reopened
            .mls_context()
            .has_own_echo_proof(
                cid,
                &gid,
                own.server_message_id.as_deref().unwrap(),
                echo_epoch,
                &[0; 32],
                &echo_ciphertext
            )
            .unwrap());
        drop(reopened);
        STATE.with(|s| *s.borrow_mut() = None);
        initialize(apath, alice).await;
        enqueue("getConversationState", json!({"state":accepted_state}));
        enqueue(
            "getDeviceKey",
            json!({"ownerDid":bob,"deviceId":bob_device,"keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(bob_public)),"signaturePublicKey":B64.encode(bob_public)}),
        );
        let sender_view: catbird_mls::DirectRequestView = serde_wasm_bindgen::from_value(
            catbird_mls_refresh_request_preview(cid.into())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(sender_view.consent, RequestConsent::Accepted);
        enqueue(
            "getEntries",
            json!({"entries":[application_entry],"hasMore":false,"nextAfterSeq":3}),
        );
        let (_, alice_engine) = current_engine().unwrap();
        let (delivered, cursor) = alice_engine
            .fetch_messages(cid, Some("2"), 100, None, None, None)
            .await
            .unwrap();
        assert_eq!(cursor.as_deref(), Some("3"));
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].text, reply.content);
        drop(alice_engine);
    }
    async fn close_with_restart(
        bpath: &str,
        bob: &str,
        cid: &str,
        p: &serde_json::Value,
        accepted_state: &serde_json::Value,
        terminal_seq: u64,
    ) {
        use serde_json::json;
        STATE.with(|s| *s.borrow_mut() = None);
        initialize(bpath, bob).await;
        let (_, current) = current_engine().unwrap();
        let no_native = current
            .mls_context()
            .get_epoch(B64.decode(p["next"]["groupId"].as_str().unwrap()).unwrap())
            .is_err();
        drop(current);
        if no_native {
            assert!(catbird_mls_close_direct_request(cid.into()).await.is_err());
            assert!(
                lastFacade("closeConversation").is_empty(),
                "No exit submission before verified host coordinate"
            );
            enqueue("getConversationState", json!({"state":accepted_state}));
        }
        enqueue("getConversationState", json!({"state":accepted_state}));
        let initial_close = catbird_mls_close_direct_request(cid.into()).await;
        assert!(initial_close.is_err());
        assert!(
            !lastFacade("closeConversation").is_empty(),
            "Expected uncertain close transport: {:?}; history={}",
            initial_close.as_ref().err(),
            facadeHistory()
        );
        let close = last("closeConversation");
        let close_body = &close["signedRequest"]["body"];
        let (_, closing_runtime) = current_engine().unwrap();
        let records = closing_runtime.mls_context().list_account_exits().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].request_body,
            lastFacade("closeConversation").as_bytes()
        );
        drop(closing_runtime);
        STATE.with(|s| *s.borrow_mut() = None);
        initialize(bpath, bob).await;
        let tombstone = json!({"$type":"blue.catbird.chat.defs#conversationCloseTombstone","conversationId":cid,"conversationKind":"direct","retired":close_body["retired"],"closedByDid":close_body["actorDid"],"closedByDeviceId":close_body["actorDeviceId"],"terminalSeq":terminal_seq,"closedAt":utc(0)});
        let close_entry = json!({"$type":"blue.catbird.chat.defs#conversationCloseEntry","entryId":uuid::Uuid::new_v4().to_string(),"conversationId":cid,"seq":terminal_seq,"signedRequest":close["signedRequest"],"receivedAt":tombstone["closedAt"],"tombstone":tombstone});
        enqueue(
            "closeConversation",
            json!({"result":{"entry":close_entry,"tombstone":tombstone}}),
        );
        enqueueFacade(
            "getConversationState",
            &json!({"error":"ConversationNotFound"}).to_string(),
            404,
        );
        enqueue("getConversationState", json!({"state":accepted_state}));
        let close_result = catbird_mls_close_direct_request(cid.into()).await;
        assert!(
            close_result.is_ok(),
            "Close failed: {:?}; history={}; records={:?}",
            close_result.as_ref().err(),
            facadeHistory(),
            current_engine()
                .unwrap()
                .1
                .mls_context()
                .list_account_exits()
                .map(|r| r
                    .iter()
                    .map(|r| (r.accepted_response.is_some(), r.local_completion))
                    .collect::<Vec<_>>())
        );
        let closed: catbird_mls::DirectRequestView =
            serde_wasm_bindgen::from_value(close_result.unwrap()).unwrap();
        assert_eq!(closed.consent, RequestConsent::Closed);
        assert!(!closed.capabilities.can_send);
        assert_eq!(close, last("closeConversation"));
        let (_, closed_runtime) = current_engine().unwrap();
        assert!(closed_runtime
            .mls_context()
            .get_epoch(B64.decode(p["next"]["groupId"].as_str().unwrap()).unwrap())
            .is_err());
        assert!(closed_runtime.mls_context().list_account_exits().unwrap()[0].local_completion);
        drop(closed_runtime);
        STATE.with(|s| *s.borrow_mut() = None);
        initialize(bpath, bob).await;
        let closed: catbird_mls::DirectRequestView = serde_wasm_bindgen::from_value(
            catbird_mls_close_direct_request(cid.into()).await.unwrap(),
        )
        .unwrap();
        assert_eq!(closed.consent, RequestConsent::Closed);
    }
}

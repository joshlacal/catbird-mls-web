//! Browser UI adapter around the shared request engine. Drafts are protected
//! local input; the shared intent/projection journals remain protocol authority.
use crate::*;
use catbird_mls::orchestrator::{MLSOrchestrator, DirectRequestInput, DirectRequestOutcome, RequestConsent};
use catbird_mls::orchestrator::mls_provider::MlsCryptoContext;

pub(crate) type BrowserOrchestrator = MLSOrchestrator<WasmStorageBackend,WasmApiClient,SqliteCredentialStore,WasmMLSContext>;
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct RequestDraft {
    input: DirectRequestInput,
    recipient_label: String,
    phase: String,
    outcome: Option<DirectRequestOutcome>,
    archived: bool,
}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
struct Workspace { owner_did:String, delivery_enabled:Option<bool>, drafts:Vec<RequestDraft>, requests:Vec<catbird_mls::DirectRequestView> }
fn err(error:impl std::fmt::Display)->JsValue {JsValue::from_str(&error.to_string())}
fn engine(owner:&str)->Result<Arc<BrowserOrchestrator>,JsValue> {
    with_state(|s| {
        if s.user_did.as_deref()!=Some(owner) || !s.request_ready {return Err(err("Authenticated request runtime is not ready for this account"));}
        s.request_engine.clone().ok_or_else(||err("Request runtime unavailable"))
    })
}
pub(crate) fn current(owner:&str,engine:&Arc<BrowserOrchestrator>)->Result<(),JsValue> {
    with_state(|s|if s.user_did.as_deref()==Some(owner)&&s.request_engine.as_ref().is_some_and(|e|Arc::ptr_eq(e,engine)){Ok(())}else{Err(err("Account changed; request outcome remains protected for reconciliation"))})
}
fn owner()->Result<String,JsValue>{with_state(|s|s.user_did.clone().ok_or_else(||err("Not authenticated")))}
pub(crate) fn current_engine()->Result<(String,Arc<BrowserOrchestrator>),JsValue>{let did=owner()?;let runtime=engine(&did)?;Ok((did,runtime))}
pub(crate) async fn require_ordinary_access(cid:&str)->Result<(),JsValue>{
    let (did,runtime)=current_engine()?;
    let readiness=runtime.ensure_conversation_ready(cid).await.map_err(err)?;
    current(&did,&runtime)?;
    if !readiness.send_allowed{return Err(err("Conversation consent or device readiness does not allow this action"));}Ok(())
}
pub(crate) async fn replenish()->Result<JsValue,JsValue>{
    let (did,runtime)=current_engine()?;
    runtime.replenish_if_needed().await.map_err(err)?;
    runtime.replenish_direct_request_keys_if_needed().await.map_err(err)?;
    current(&did,&runtime)?;to_js(&serde_json::json!({"status":"reconciled"}))
}
fn draft(ctx:&WasmMLSContext,id:&str)->Result<(Vec<u8>,RequestDraft),JsValue>{
    let raw=ctx.request_value("uiDraft",id).map_err(err)?.ok_or_else(||err("Draft not found"))?;
    let value=serde_json::from_slice(&raw).map_err(err)?;
    Ok((raw,value))
}
fn save(ctx:&WasmMLSContext,value:&RequestDraft,expected:Option<&[u8]>)->Result<(),JsValue>{
    let raw=serde_json::to_vec(value).map_err(err)?;
    if !ctx.request_value_cas("uiDraft",&value.input.draft_id,expected,&raw).map_err(err)? {return Err(err("Draft changed while processing; reload its saved state"));}
    Ok(())
}

pub(crate) async fn setup()->Result<JsValue,JsValue>{
    let (did,engine,ctx,creds,api)=with_state(|s|Ok((s.user_did.clone().ok_or_else(||err("Not authenticated"))?,s.request_engine.clone().ok_or_else(||err("Request engine unavailable"))?,s.mls_context.clone().ok_or_else(||err("Crypto unavailable"))?,s.credentials.clone(),s.api_client.clone())))?;
    engine.initialize(&did).await.map_err(err)?;
    let mls_did=crate::browser_enrollment::initialize_enrollment(ctx,creds.clone(),api.clone(),&did).await.map_err(err)?;
    current(&did,&engine)?;
    let device=creds.get_device_uuid(&did).await.map_err(err)?.ok_or_else(||err("Enrolled actor missing"))?;
    api.bind_actor(&did,&device).map_err(err)?;
    engine.replenish_direct_request_keys_if_needed().await.map_err(err)?;
    current(&did,&engine)?;
    with_state_mut(|s|{s.request_ready=true;Ok(())})?;
    to_js(&serde_json::json!({"status":"registered","mlsDid":mls_did}))
}

#[wasm_bindgen]
pub async fn catbird_mls_start_direct_request(input:JsValue)->Result<JsValue,JsValue>{
    let input:DirectRequestInput=serde_wasm_bindgen::from_value(input).map_err(err)?;
    let did=owner()?;let runtime=engine(&did)?;let out=runtime.start_direct_request(input).await.map_err(err)?;current(&did,&runtime)?;to_js(&out)
}
#[wasm_bindgen]
pub async fn catbird_mls_resume_direct_request(draft_id:String)->Result<JsValue,JsValue>{let did=owner()?;let runtime=engine(&did)?;let out=runtime.resume_direct_request(&draft_id).await.map_err(err)?;current(&did,&runtime)?;to_js(&out)}
#[wasm_bindgen]
pub async fn catbird_mls_cancel_direct_request(draft_id:String)->Result<JsValue,JsValue>{let did=owner()?;let runtime=engine(&did)?;let out=runtime.cancel_direct_request(&draft_id).await.map_err(err)?;current(&did,&runtime)?;to_js(&out)}
#[wasm_bindgen]
pub async fn catbird_mls_refresh_request_preview(cid:String)->Result<JsValue,JsValue>{let did=owner()?;let runtime=engine(&did)?;let out=runtime.refresh_request_preview(&cid).await.map_err(err)?;current(&did,&runtime)?;to_js(&out)}
#[wasm_bindgen]
pub async fn catbird_mls_list_direct_request_views()->Result<JsValue,JsValue>{let did=owner()?;let runtime=engine(&did)?;let out=runtime.list_direct_request_views().await.map_err(err)?;current(&did,&runtime)?;to_js(&out)}
#[wasm_bindgen]
pub async fn catbird_mls_get_direct_request_delivery_enabled()->Result<JsValue,JsValue>{let did=owner()?;let runtime=engine(&did)?;let out=runtime.get_direct_request_delivery_enabled().await.map_err(err)?;current(&did,&runtime)?;to_js(&out)}
#[wasm_bindgen]
pub async fn catbird_mls_set_direct_request_delivery_enabled(enabled:bool)->Result<(),JsValue>{let did=owner()?;let runtime=engine(&did)?;runtime.set_direct_request_delivery_enabled(enabled).await.map_err(err)?;current(&did,&runtime)}
#[wasm_bindgen]
pub async fn catbird_mls_close_direct_request(cid:String)->Result<JsValue,JsValue>{let did=owner()?;let runtime=engine(&did)?;let out=runtime.close_direct_request(&cid).await.map_err(err)?;current(&did,&runtime)?;to_js(&out)}
#[wasm_bindgen]
pub async fn catbird_mls_accept_direct_request(cid:String)->Result<JsValue,JsValue>{
    let did=owner()?;let runtime=engine(&did)?;
    let views=runtime.list_direct_request_views().await.map_err(err)?;
    if !views.iter().any(|v|v.conversation_id==cid && v.consent==RequestConsent::IncomingPending && v.capabilities.can_accept){return Err(err("No verified incoming request available for acceptance"));}
    runtime.accept_conversation(&cid).await.map_err(err)?;current(&did,&runtime)?;
    let out=runtime.refresh_request_preview(&cid).await.map_err(err)?;current(&did,&runtime)?;to_js(&out)
}

#[wasm_bindgen]
pub async fn catbird_mls_get_group_invitation_reference(cid:String,recipient:String)->Result<JsValue,JsValue>{let (did,runtime)=current_engine()?;let result=runtime.get_group_invitation_reference(&cid,&recipient).await.map_err(err)?;current(&did,&runtime)?;to_js(&result)}

/// Host presentation commands share the exact draft shape with native Catmos.
#[wasm_bindgen]
pub async fn catbird_mls_request_command(command:String,args:JsValue)->Result<JsValue,JsValue>{
    let args:serde_json::Value=serde_wasm_bindgen::from_value(args).map_err(err)?;
    let did=args["ownerDid"].as_str().ok_or_else(||err("Missing request account"))?;
    let runtime=engine(did)?;let ctx=runtime.mls_context();
    match command.as_str(){
        "get_request_workspace"=>{
            let requests=runtime.list_direct_request_views().await.map_err(err)?;
            let delivery_enabled=runtime.get_direct_request_delivery_enabled().await.map_err(err)?;
            let drafts=ctx.request_values("uiDraft").map_err(err)?.into_iter().map(|r|serde_json::from_slice(&r).map_err(err)).collect::<Result<Vec<_>,_>>()?;
            current(did,&runtime)?;to_js(&Workspace{owner_did:did.to_owned(),delivery_enabled,drafts,requests})
        }
        "save_request_draft"=>{
            let input:DirectRequestInput=serde_json::from_value(args["input"].clone()).map_err(err)?;
            let label=args["recipientLabel"].as_str().ok_or_else(||err("Invalid recipient label"))?;
            catbird_mls::chat_v2::ids::CanonicalUuid::parse(&input.draft_id).map_err(err)?;
            catbird_mls::chat_v2::ids::BareDid::parse(&input.recipient_did).map_err(err)?;
            if input.recipient_did==did||input.text.len()>16384||label.len()>256{return Err(err("Invalid request draft"));}
            let old=ctx.request_value("uiDraft",&input.draft_id).map_err(err)?;
            if let Some(raw)=&old {let old:RequestDraft=serde_json::from_slice(raw).map_err(err)?;if old.phase!="draft" {if old.input==input{return to_js(&old);}return Err(err("Attempted request input is immutable"));}}
            let value=RequestDraft{input,recipient_label:label.into(),phase:"draft".into(),outcome:None,archived:false};save(ctx,&value,old.as_deref())?;to_js(&value)
        }
        "submit_request_draft"|"resume_request_draft"|"cancel_request_draft"=>{
            let id=args["draftId"].as_str().ok_or_else(||err("Missing draft ID"))?;
            let (old,mut value)=draft(ctx,id)?;
            if value.archived{return Err(err("Draft is archived"));}
            if command=="cancel_request_draft"&&value.phase=="draft"{value.archived=true;save(ctx,&value,Some(&old))?;return to_js(&value);}
            value.phase="attempted".into();save(ctx,&value,Some(&old))?;
            let attempted=serde_json::to_vec(&value).map_err(err)?;
            let result=match command.as_str(){"submit_request_draft"=>runtime.start_direct_request(value.input.clone()).await,"resume_request_draft"=>runtime.resume_direct_request(id).await,_=>runtime.cancel_direct_request(id).await};
            current(did,&runtime)?;
            let outcome=result.map_err(|_|err("Delivery is not confirmed. The exact request is retained; check delivery before creating another."))?;
            value.phase=if matches!(outcome,DirectRequestOutcome::OutcomeUnknown{..}){"checking"}else{"resolved"}.into();value.outcome=Some(outcome);save(ctx,&value,Some(&attempted))?;to_js(&value)
        }
        "get_group_invitation_reference"=>{let cid=args["conversationId"].as_str().ok_or_else(||err("Missing conversation"))?;let recipient=args["recipientDid"].as_str().ok_or_else(||err("Missing recipient"))?;let reference=runtime.get_group_invitation_reference(cid,recipient).await.map_err(err)?;current(did,&runtime)?;to_js(&reference)},
        "refresh_direct_request"=>catbird_mls_refresh_request_preview(args["conversationId"].as_str().ok_or_else(||err("Missing conversation"))?.into()).await,
        "accept_direct_request"=>catbird_mls_accept_direct_request(args["conversationId"].as_str().ok_or_else(||err("Missing conversation"))?.into()).await,
        "close_direct_request"=>catbird_mls_close_direct_request(args["conversationId"].as_str().ok_or_else(||err("Missing conversation"))?.into()).await,
        "set_request_delivery_enabled"=>{catbird_mls_set_direct_request_delivery_enabled(args["enabled"].as_bool().ok_or_else(||err("Invalid preference"))?).await?;Ok(JsValue::UNDEFINED)},
        "request_sender"=>{let cid=args["conversationId"].as_str().ok_or_else(||err("Missing conversation"))?;let views=runtime.list_direct_request_views().await.map_err(err)?;current(did,&runtime)?;let view=views.into_iter().find(|v|v.conversation_id==cid&&v.consent==RequestConsent::IncomingPending).ok_or_else(||err("Verified incoming request unavailable"))?;to_js(&view.introduction.ok_or_else(||err("Sender proof unavailable"))?.sender_did)},
        _=>Err(err("Unknown request command"))
    }
}

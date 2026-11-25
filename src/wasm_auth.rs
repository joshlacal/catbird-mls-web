//! Browser direct ATProto OAuth via Petrel's Rust runtime and Client Assertion Backend (CAB).
//!
//! Mirrors `catmos/src-tauri/src/auth.rs` for Web Workers:
//! - Non-extractable WebCrypto P-256 DPoP keys persisted via structured cloning in IndexedDB.
//! - Session/account/flow records persisted via `CallbackSecretStore` in IndexedDB.
//! - `FetchTransport` + `DohResolver::cloudflare` for CORS-clean browser networking and handle lookup.
//! - Direct DPoP-signed PDS XRPC (`XrpcClient::exchange`) and `getServiceAuth` (`aud=<ds>#atproto_mls`).

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Response};
use js_sys::{Array, Function, Object, Promise, Reflect, Uint8Array};
use petrel::crypto::{DpopSigner, EcPublicJwk, WebCryptoDpopSigner};
use petrel::identity::{DohResolver, IdentityOptions, IdentityResolver};
use petrel::net::{FetchTransport, SharedTransport};
use petrel::oauth::{
    ClientAuth, DpopKeyStore, OAuthClient, OAuthConfig, OAuthError, OAuthIdentityAdapter,
    OAuthTarget,
};
use petrel::rt::BoxFuture;
use petrel::service_auth::ServiceRef;
use petrel::storage::{CallbackSecretStore, SessionStore, StoreError};
use petrel::xrpc::{CallOptions, XrpcBody, XrpcClient};
use petrel_core::{AtIdentifier, Did, Nsid};
use serde::Serialize;
use url::Url;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::CryptoKey;

pub(crate) const DEFAULT_CLIENT_ID: &str = "https://catmos.catbird.blue/oauth/client-metadata.json";
pub(crate) const DEFAULT_REDIRECT_URI: &str = "https://catmos.catbird.blue/auth/callback";
pub(crate) const DEFAULT_CAB_URL: &str = "https://api.catbird.blue/cab/catmos";
pub(crate) const STORE_NAMESPACE: &str = "catmos-web";
pub(crate) const DELIVERY_SERVICE_ID: &str = "atproto_mls";

const MAX_PDS_RESPONSE_BYTES: u64 = 128 * 1024 * 1024;
const PDS_TIMEOUT: Duration = Duration::from_secs(60);

const EXTRA_SCOPES: [&str; 2] = [
    "repo:blue.catbird.chat.declaration?action=create&action=update",
    "repo:app.bsky.graph.block?action=create",
];

/// Full scoped OAuth permission set Catmos requests on initial sign-in.
/// Matches `catmos/src-tauri/src/auth.rs` and `catmos/static/oauth/client-metadata.json`.
pub(crate) fn oauth_scope(delivery_service_did: &str) -> String {
    let bare_ds = delivery_service_did
        .trim()
        .split('#')
        .next()
        .unwrap_or(delivery_service_did.trim());
    let mut scopes: Vec<String> = catbird_mls::client::REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .chain(EXTRA_SCOPES.iter())
        .map(|scope| (*scope).to_string())
        .collect();
    scopes.push(format!("rpc:*?aud={bare_ds}%23{DELIVERY_SERVICE_ID}"));
    scopes.join(" ")
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WebSignedIn {
    pub did: String,
    pub handle: String,
    pub pds: String,
    pub granted_scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WebPdsExchangeResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Persists non-extractable WebCrypto `CryptoKey` handles and their public JWK coordinates
/// via an IndexedDB callback owned by the Web Worker.
struct WebCryptoKeyStore {
    dispatch: Function,
}

impl WebCryptoKeyStore {
    fn new(dispatch: Function) -> Self {
        Self { dispatch }
    }

    async fn call(&self, operation: &str, id: &str, value: JsValue) -> Result<JsValue, StoreError> {
        let result = self
            .dispatch
            .call3(
                &JsValue::NULL,
                &JsValue::from_str(operation),
                &JsValue::from_str(id),
                &value,
            )
            .map_err(|_| StoreError::Unavailable("WebCrypto DPoP key store threw".into()))?;
        JsFuture::from(Promise::resolve(&result))
            .await
            .map_err(|_| StoreError::Unavailable("WebCrypto DPoP key store rejected".into()))
    }
}

impl DpopKeyStore for WebCryptoKeyStore {
    fn create<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Result<Arc<dyn DpopSigner>, StoreError>> {
        Box::pin(async move {
            let signer = WebCryptoDpopSigner::generate().await.map_err(|_| {
                StoreError::Unavailable("WebCrypto DPoP key generation failed".into())
            })?;
            let jwk = signer.public_jwk();
            let entry = Object::new();
            Reflect::set(
                entry.as_ref(),
                &JsValue::from_str("key"),
                signer.crypto_key().as_ref(),
            )
            .map_err(|_| StoreError::Unavailable("serialize WebCrypto DPoP key".into()))?;
            Reflect::set(
                entry.as_ref(),
                &JsValue::from_str("x"),
                &JsValue::from_str(&jwk.x),
            )
            .map_err(|_| StoreError::Unavailable("serialize WebCrypto DPoP x".into()))?;
            Reflect::set(
                entry.as_ref(),
                &JsValue::from_str("y"),
                &JsValue::from_str(&jwk.y),
            )
            .map_err(|_| StoreError::Unavailable("serialize WebCrypto DPoP y".into()))?;
            self.call("put", id, entry.into()).await?;
            Ok(Arc::new(signer) as Arc<dyn DpopSigner>)
        })
    }

    fn get<'a>(
        &'a self,
        id: &'a str,
    ) -> BoxFuture<'a, Result<Option<Arc<dyn DpopSigner>>, StoreError>> {
        Box::pin(async move {
            let stored = self.call("get", id, JsValue::NULL).await?;
            if stored.is_null() || stored.is_undefined() {
                return Ok(None);
            }
            let key: CryptoKey = Reflect::get(&stored, &JsValue::from_str("key"))
                .map_err(|_| StoreError::Corrupt("missing WebCrypto DPoP key handle".into()))?
                .dyn_into::<CryptoKey>()
                .map_err(|_| StoreError::Corrupt("invalid WebCrypto DPoP key handle".into()))?;
            let x = Reflect::get(&stored, &JsValue::from_str("x"))
                .map_err(|_| StoreError::Corrupt("missing WebCrypto DPoP x".into()))?
                .as_string()
                .ok_or_else(|| StoreError::Corrupt("invalid WebCrypto DPoP x".into()))?;
            let y = Reflect::get(&stored, &JsValue::from_str("y"))
                .map_err(|_| StoreError::Corrupt("missing WebCrypto DPoP y".into()))?
                .as_string()
                .ok_or_else(|| StoreError::Corrupt("invalid WebCrypto DPoP y".into()))?;
            let signer = WebCryptoDpopSigner::from_key(key, EcPublicJwk { x, y })
                .await
                .map_err(|_| StoreError::Corrupt("WebCrypto DPoP key binding failed".into()))?;
            Ok(Some(Arc::new(signer) as Arc<dyn DpopSigner>))
        })
    }

    fn delete<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            self.call("delete", id, JsValue::NULL).await?;
            Ok(())
        })
    }
}

pub(crate) struct WasmAuthInner {
    transport: SharedTransport,
    client: Arc<OAuthClient>,
    store: SessionStore,
    allow_loopback: bool,
    pds_by_did: RefCell<HashMap<String, Url>>,
}

impl WasmAuthInner {
    async fn resolve_pds(&self, did: &Did) -> Result<Url, String> {
        if let Some(cached) = self.pds_by_did.borrow().get(did.as_str()).cloned() {
            return Ok(cached);
        }
        let account = self
            .store
            .get_account(did)
            .await
            .map_err(|e| format!("Could not read saved OAuth account: {e}"))?
            .ok_or_else(|| "Not authenticated".to_string())?;
        let pds = account
            .pds
            .parse::<Url>()
            .map_err(|_| "Saved OAuth account has an invalid PDS URL".to_string())?;
        self.pds_by_did
            .borrow_mut()
            .insert(did.as_str().to_string(), pds.clone());
        Ok(pds)
    }

    pub(crate) async fn service_token(
        &self,
        did: &str,
        audience: &str,
        method: &str,
    ) -> Result<String, String> {
        let parsed_did = parse_did(did)?;
        let audience_ref = ServiceRef::parse(audience)
            .map_err(|e| format!("invalid service audience `{audience}`: {e}"))?;
        let method_nsid = method
            .parse::<Nsid>()
            .map_err(|_| format!("invalid service method `{method}`"))?;
        let token = self
            .client
            .session_auth(parsed_did)
            .get_service_auth(&audience_ref, Some(&method_nsid), None)
            .await
            .map_err(|e| format!("getServiceAuth `{method}` failed: {e}"))?;
        Ok(token.as_str().to_string())
    }

    pub(crate) async fn pds_exchange(
        &self,
        did: &str,
        method: Method,
        nsid: &str,
        params: Vec<(String, String)>,
        headers: HeaderMap,
        body: Option<(Bytes, String)>,
    ) -> Result<Response<Bytes>, String> {
        let parsed_did = parse_did(did)?;
        let pds = self.resolve_pds(&parsed_did).await?;
        let client = XrpcClient::new(pds, Arc::clone(&self.transport))
            .map_err(|e| e.to_string())?
            .with_auth_provider(Arc::new(self.client.session_auth(parsed_did)));
        let xrpc_body = body
            .map(|(bytes, content_type)| XrpcBody::bytes(bytes, &content_type))
            .transpose()
            .map_err(|e| e.to_string())?;
        let mut options = CallOptions {
            headers,
            ..CallOptions::default()
        };
        options.transport.timeout = Some(PDS_TIMEOUT);
        options.transport.max_response_bytes = Some(MAX_PDS_RESPONSE_BYTES);
        options.transport.allow_loopback = self.allow_loopback;
        client
            .exchange(method, nsid, params, xrpc_body, &options)
            .await
            .map_err(|e| e.to_string())
    }

    async fn signed_in(&self, did: &Did, scope: &str) -> Result<WebSignedIn, String> {
        let account = self
            .store
            .get_account(did)
            .await
            .map_err(|e| format!("The saved sign-in could not be read: {e}"))?
            .ok_or_else(|| "The saved account is incomplete".to_string())?;
        let pds = account
            .pds
            .parse::<Url>()
            .map_err(|_| "The saved account has no valid server".to_string())?;
        self.pds_by_did
            .borrow_mut()
            .insert(did.as_str().to_string(), pds);
        Ok(WebSignedIn {
            did: did.as_str().to_string(),
            handle: account
                .handle
                .map_or_else(|| did.as_str().to_string(), |handle| handle.to_string()),
            pds: account.pds.trim_end_matches('/').to_string(),
            granted_scopes: scope.split_ascii_whitespace().map(str::to_string).collect(),
        })
    }
}

/// Headers managed exclusively by Petrel's XRPC / DPoP pipeline.
pub(crate) fn is_managed_header(name: &str) -> bool {
    [
        "authorization",
        "dpop",
        "content-type",
        "content-length",
        "host",
    ]
    .iter()
    .any(|managed| name.eq_ignore_ascii_case(managed))
}

pub(crate) fn split_xrpc_path(path: &str) -> Result<(String, Vec<(String, String)>), String> {
    let trimmed = path.trim();
    let full = if trimmed.starts_with('/') {
        format!("https://placeholder.invalid{trimmed}")
    } else {
        format!("https://placeholder.invalid/{trimmed}")
    };
    let parsed = Url::parse(&full).map_err(|e| format!("invalid XRPC path `{path}`: {e}"))?;
    let nsid = parsed
        .path()
        .strip_prefix("/xrpc/")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("path `{path}` is not an /xrpc/ path"))?
        .to_string();
    let params = parsed.query_pairs().into_owned().collect();
    Ok((nsid, params))
}

fn parse_did(did: &str) -> Result<Did, String> {
    Did::parse(did).map_err(|e| format!("invalid DID `{did}`: {e}"))
}

fn build_oauth_config(
    client_id: &str,
    redirect_uri: &str,
    cab_url: &str,
    scope: &str,
) -> Result<(OAuthConfig, bool), String> {
    let redirect = Url::parse(redirect_uri)
        .map_err(|e| format!("invalid OAuth redirect URI `{redirect_uri}`: {e}"))?;
    let is_loopback = redirect.scheme() == "http"
        && matches!(
            redirect.host_str(),
            Some("127.0.0.1" | "localhost" | "[::1]")
        );
    if is_loopback {
        let port = redirect.port_or_known_default().unwrap_or(80);
        let config = OAuthConfig::loopback(port, redirect.path(), scope)
            .map_err(|e| format!("Invalid loopback OAuth configuration: {e}"))?;
        return Ok((config, true));
    }
    let backend_url = Url::parse(cab_url)
        .map_err(|e| format!("invalid client assertion backend URL `{cab_url}`: {e}"))?;
    let config = OAuthConfig::new(
        client_id.to_string(),
        redirect,
        scope,
        ClientAuth::Cab {
            backend_url,
            client_id: client_id.to_string(),
        },
    )
    .map_err(|e| format!("Invalid OAuth client configuration: {e}"))?;
    Ok((config, false))
}

/// Browser Petrel OAuth client backed by IndexedDB + non-extractable WebCrypto DPoP keys.
#[wasm_bindgen]
pub struct WasmAuthClient {
    pub(crate) inner: Rc<WasmAuthInner>,
}

#[wasm_bindgen]
impl WasmAuthClient {
    #[wasm_bindgen(constructor)]
    pub fn new(
        client_id: Option<String>,
        redirect_uri: Option<String>,
        cab_url: Option<String>,
        delivery_service_did: Option<String>,
        secret_dispatch: Function,
        dpop_key_dispatch: Function,
    ) -> Result<WasmAuthClient, JsValue> {
        let client_id = client_id
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_CLIENT_ID.to_string());
        let redirect_uri = redirect_uri
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_REDIRECT_URI.to_string());
        let cab_url = cab_url
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_CAB_URL.to_string());
        let delivery_service_did = delivery_service_did
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "did:web:chat.catbird.blue".to_string());

        let scope = oauth_scope(&delivery_service_did);
        let (config, allow_loopback) =
            build_oauth_config(&client_id, &redirect_uri, &cab_url, &scope)
                .map_err(|e| JsValue::from_str(&e))?;

        let secrets = CallbackSecretStore::new(secret_dispatch);
        let store = SessionStore::new(Arc::new(secrets), STORE_NAMESPACE)
            .map_err(|e| JsValue::from_str(&format!("Could not open OAuth session store: {e}")))?;
        let keys = Arc::new(WebCryptoKeyStore::new(dpop_key_dispatch));

        let transport: SharedTransport = Arc::new(FetchTransport);
        let dns = DohResolver::cloudflare(Arc::clone(&transport));
        let resolver =
            IdentityResolver::new(Arc::clone(&transport), dns, IdentityOptions::default());
        let client = OAuthClient::new(
            Arc::clone(&transport),
            Arc::new(OAuthIdentityAdapter::new(resolver)),
            store.clone(),
            config,
        )
        .map_err(|e| JsValue::from_str(&format!("Invalid OAuth client configuration: {e}")))?
        .with_key_store(keys);

        Ok(Self {
            inner: Rc::new(WasmAuthInner {
                transport,
                client: Arc::new(client),
                store,
                allow_loopback,
                pds_by_did: RefCell::new(HashMap::new()),
            }),
        })
    }

    #[wasm_bindgen(js_name = oauthScope)]
    pub fn oauth_scope_js(delivery_service_did: String) -> String {
        oauth_scope(&delivery_service_did)
    }

    #[wasm_bindgen(js_name = startLogin)]
    pub async fn start_login(&self, identifier: String) -> Result<String, JsValue> {
        let trimmed = identifier.trim().trim_start_matches('@');
        let target = if trimmed.starts_with("https://") {
            OAuthTarget::Server(
                trimmed
                    .parse()
                    .map_err(|_| JsValue::from_str("That server address is not valid"))?,
            )
        } else {
            OAuthTarget::Identifier(
                AtIdentifier::parse(trimmed)
                    .map_err(|_| JsValue::from_str("Enter a handle such as name.bsky.social"))?,
            )
        };
        let authorize_url = self
            .inner
            .client
            .start_authorization(target)
            .await
            .map_err(|e| JsValue::from_str(&format!("Could not start sign-in: {e}")))?;
        Ok(authorize_url.to_string())
    }

    #[wasm_bindgen(js_name = completeLogin)]
    pub async fn complete_login(&self, callback_url: String) -> Result<JsValue, JsValue> {
        let parsed = Url::parse(&callback_url)
            .map_err(|e| JsValue::from_str(&format!("Invalid OAuth callback URL: {e}")))?;
        let session = self
            .inner
            .client
            .complete_authorization(&parsed)
            .await
            .map_err(|e| match e {
                OAuthError::Cancelled => JsValue::from_str("Sign-in was cancelled"),
                other => JsValue::from_str(&format!("Sign-in failed: {other}")),
            })?;
        let signed_in = self
            .inner
            .signed_in(&session.did, session.scope())
            .await
            .map_err(|e| JsValue::from_str(&e))?;
        serde_wasm_bindgen::to_value(&signed_in).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen(js_name = restoreSession)]
    pub async fn restore_session(&self) -> Result<JsValue, JsValue> {
        let Some(did) =
            self.inner.store.get_current_did().await.map_err(|e| {
                JsValue::from_str(&format!("The saved sign-in could not be read: {e}"))
            })?
        else {
            return Ok(JsValue::NULL);
        };
        match self.inner.client.session(&did).await {
            Ok(Some(session)) => {
                let signed_in = self
                    .inner
                    .signed_in(&did, session.scope())
                    .await
                    .map_err(|e| JsValue::from_str(&e))?;
                serde_wasm_bindgen::to_value(&signed_in)
                    .map_err(|e| JsValue::from_str(&e.to_string()))
            }
            Ok(None) => Ok(JsValue::NULL),
            Err(error) => Err(JsValue::from_str(&error.to_string())),
        }
    }

    #[wasm_bindgen(js_name = logout)]
    pub async fn logout(&self, did: String) -> Result<(), JsValue> {
        let parsed = parse_did(&did).map_err(|e| JsValue::from_str(&e))?;
        self.inner.pds_by_did.borrow_mut().remove(parsed.as_str());
        self.inner
            .client
            .logout(&parsed)
            .await
            .map(|_| ())
            .map_err(|e| JsValue::from_str(&format!("Could not clear the saved sign-in: {e}")))
    }

    #[wasm_bindgen(js_name = serviceToken)]
    pub async fn service_token(
        &self,
        did: String,
        audience: String,
        method: String,
    ) -> Result<String, JsValue> {
        self.inner
            .service_token(&did, &audience, &method)
            .await
            .map_err(|e| JsValue::from_str(&e))
    }

    #[wasm_bindgen(js_name = pdsExchange)]
    pub async fn pds_exchange(
        &self,
        did: String,
        method: String,
        path: String,
        headers_js: JsValue,
        body: Option<Uint8Array>,
        content_type: Option<String>,
    ) -> Result<JsValue, JsValue> {
        let http_method = Method::from_bytes(method.trim().to_ascii_uppercase().as_bytes())
            .map_err(|e| JsValue::from_str(&format!("invalid HTTP method: {e}")))?;
        let (nsid, params) = split_xrpc_path(&path).map_err(|e| JsValue::from_str(&e))?;

        let mut header_map = HeaderMap::new();
        let mut resolved_ct = content_type.filter(|s| !s.trim().is_empty());
        if !headers_js.is_null() && !headers_js.is_undefined() {
            let pairs: Vec<(String, String)> = serde_wasm_bindgen::from_value(headers_js)
                .map_err(|e| JsValue::from_str(&format!("invalid headers: {e}")))?;
            for (name, value) in pairs {
                if name.eq_ignore_ascii_case("content-type") && resolved_ct.is_none() {
                    resolved_ct = Some(value.clone());
                }
                if is_managed_header(&name) {
                    continue;
                }
                let hn = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| JsValue::from_str(&format!("invalid header name `{name}`")))?;
                let hv = HeaderValue::from_str(&value)
                    .map_err(|_| JsValue::from_str(&format!("invalid header value `{name}`")))?;
                header_map.append(hn, hv);
            }
        }

        let body_pair = body.map(|arr| {
            let bytes = Bytes::from(arr.to_vec());
            let ct = resolved_ct.unwrap_or_else(|| "application/json".to_string());
            (bytes, ct)
        });

        let response = self
            .inner
            .pds_exchange(&did, http_method, &nsid, params, header_map, body_pair)
            .await
            .map_err(|e| JsValue::from_str(&e))?;

        let status = response.status().as_u16();
        let mut resp_ct = None;
        let mut resp_headers = Vec::new();
        for (name, value) in response.headers() {
            if let Ok(val) = value.to_str() {
                if name.as_str().eq_ignore_ascii_case("content-type") {
                    resp_ct = Some(val.to_string());
                }
                resp_headers.push((name.as_str().to_string(), val.to_string()));
            }
        }
        let result = WebPdsExchangeResponse {
            status,
            content_type: resp_ct,
            headers: resp_headers,
            body: response.into_body().to_vec(),
        };
        serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen(js_name = checkOptInStatus)]
    pub async fn check_opt_in_status(
        &self,
        did: String,
        home_ds_did: String,
        home_ds_endpoint: String,
        dids: Array,
    ) -> Result<JsValue, JsValue> {
        let did_list: Vec<String> = dids.iter().filter_map(|v| v.as_string()).collect();
        if did_list.is_empty() {
            return serde_wasm_bindgen::to_value(&Vec::<crate::OptInStatusResult>::new())
                .map_err(|e| JsValue::from_str(&e.to_string()));
        }
        let bare_ds = home_ds_did
            .trim()
            .split('#')
            .next()
            .unwrap_or(home_ds_did.trim());
        let audience = format!("{bare_ds}#{DELIVERY_SERVICE_ID}");
        let jwt = self
            .inner
            .service_token(&did, &audience, "blue.catbird.chat.getDevices")
            .await
            .map_err(|e| JsValue::from_str(&e))?;
        let url = format!(
            "{}/xrpc/blue.catbird.chat.getDevices?dids={}",
            home_ds_endpoint.trim_end_matches('/'),
            did_list.join(",")
        );
        let client = reqwest::Client::new();
        let resp = client
            .get(&url)
            .bearer_auth(&jwt)
            .send()
            .await
            .map_err(|e| JsValue::from_str(&format!("check_opt_in_status failed: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(JsValue::from_str(&format!(
                "check_opt_in_status failed ({status}): {body}"
            )));
        }
        let output: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| JsValue::from_str(&format!("check_opt_in_status parse failed: {e}")))?;
        let mut results = Vec::new();
        if let Some(devices) = output["devices"].as_array() {
            let mut by_did: HashMap<String, bool> = HashMap::new();
            for dev in devices {
                if let Some(dev_did) = dev["did"].as_str() {
                    by_did.insert(dev_did.to_string(), true);
                }
            }
            for target in &did_list {
                results.push(crate::OptInStatusResult {
                    did: target.clone(),
                    opted_in: by_did.contains_key(target),
                });
            }
        } else {
            for target in &did_list {
                results.push(crate::OptInStatusResult {
                    did: target.clone(),
                    opted_in: false,
                });
            }
        }
        serde_wasm_bindgen::to_value(&results).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

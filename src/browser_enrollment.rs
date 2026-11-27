//! Browser enrollment preserves exact signed attempts across response loss.
//! Device keys remain in the Rust provider's protected OPFS database.
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use catbird_mls::orchestrator::{
    api_client::MLSAPIClient,
    canonical_transport::{
        self as transport, CanonicalOperation, CleanChatSigningContext, PreparedRequest,
    },
    error::{OrchestratorError, Result},
    mls_provider::MlsCryptoContext,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    api_client::WasmApiClient, credentials::SqliteCredentialStore, wasm_mls_context::WasmMLSContext,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrollmentJournal {
    pub did: String,
    pub device_id: String,
    pub mls_did: String,
    pub public_key: Vec<u8>,
    pub key_id: String,
    pub request_body: Vec<u8>,
    pub auth_generation: Option<i64>,
}

pub(crate) fn invalid() -> OrchestratorError {
    OrchestratorError::Credential("device identity mismatch; explicit new-device enrollment is required, existing custody was retained".into())
}

impl EnrollmentJournal {
    pub(crate) fn validate_local(&self, did: &str, ctx: &WasmMLSContext) -> Result<()> {
        let uuid = uuid::Uuid::parse_str(&self.device_id).map_err(|_| invalid())?;
        if self.did != did
            || uuid.get_version_num() != 4
            || uuid.get_variant() != uuid::Variant::RFC4122
            || uuid.to_string() != self.device_id
            || self.mls_did != format!("{did}#{}", self.device_id)
            || self.public_key.len() != 32
            || transport::derive_key_id(&self.public_key) != self.key_id
            || self
                .auth_generation
                .is_some_and(|generation| generation <= 0)
            || ctx
                .identity_public_key(self.mls_did.as_bytes().to_vec())
                .map_err(|_| invalid())?
                != self.public_key
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn validate_server(
        &self,
        device: &catbird_mls::atproto::chat::defs::DeviceView,
    ) -> Result<i64> {
        if device.device_id.as_ref() != self.device_id
            || device.key_id.as_ref() != self.key_id
            || device.signature_public_key.as_ref() != self.public_key
            || device.auth_generation <= 0
            || device.status.as_str() != "active"
            || self
                .auth_generation
                .is_some_and(|generation| generation != device.auth_generation)
        {
            return Err(invalid());
        }
        Ok(device.auth_generation)
    }
}

pub async fn initialize_enrollment(
    ctx: Arc<WasmMLSContext>,
    credentials: Arc<SqliteCredentialStore>,
    api: Arc<WasmApiClient>,
    did: &str,
) -> Result<String> {
    let _exclusive = credentials.begin_enrollment()?;
    if !api.is_authenticated_as(did).await {
        return Err(OrchestratorError::NotAuthenticated);
    }
    let mut journal = if let Some(journal) = credentials.enrollment(did)? {
        journal.validate_local(did, &ctx)?;
        journal
    } else {
        if credentials.has_legacy_state(did)? {
            return Err(invalid());
        }
        let device_id = uuid::Uuid::new_v4().to_string();
        let mls_did = format!("{did}#{device_id}");
        let kp = ctx
            .create_key_package(mls_did.as_bytes().to_vec())
            .map_err(|error| {
                OrchestratorError::Credential(format!(
                    "cannot create enrollment KeyPackage: {error}"
                ))
            })?;
        let public_key = ctx
            .identity_public_key(mls_did.as_bytes().to_vec())
            .map_err(|error| {
                OrchestratorError::Credential(format!("cannot read enrollment signer: {error}"))
            })?;
        if kp.signature_public_key != public_key {
            return Err(invalid());
        }
        let key_id = transport::derive_key_id(&public_key);
        let body = serde_json::json!({
            "$type":"blue.catbird.chat.defs#deviceEnrollmentBody",
            "signatureDomain":transport::DEVICE_ENROLL_SIGNATURE_DOMAIN,
            "actorDid":did,"deviceId":device_id,"deviceName":"Catbird Web","keyId":key_id,
            "signaturePublicKey":{"$bytes":B64.encode(&public_key)},"expectedAuthGeneration":0,
            "capability":{
                "protocolVersion":"1","mlsVersion":"1.0",
                "cipherSuite":"MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519","credentialType":"basic",
                "addByValue":"supported","updatePath":"supported","removeByValue":"supported",
                "ratchetTreeGroupInfo":"supported","externalPubGroupInfo":"presentButExternalCommitsForbidden",
                "applicationFrameProfile":"dagCborApplication1","controlProfile":"publicGroup1",
                "attachmentProfile":"aes256GcmBlob1","metadataProfile":"exporterAes256Gcm1","typingProfile":"signedClearEphemeral1"
            },
            "keyPackages":[{"framing":"mlsMessage","contentType":"keyPackage",
                "bytes":{"$bytes":B64.encode(&kp.key_package_data)},"sha256":B64.encode(Sha256::digest(&kp.key_package_data)),
                "keyPackageRef":{"$bytes":B64.encode(&kp.hash_ref)}}],
            "idempotencyKey":uuid::Uuid::new_v4().to_string(),
            "signedAt":chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
        });
        let request = transport::prepare_signed_request_with(
            &CleanChatSigningContext {
                actor_did: did.to_owned(),
                device_id: device_id.clone(),
                auth_generation: None,
            },
            CanonicalOperation::EnrollDevice,
            serde_json::to_vec(&body).map_err(|_| invalid())?,
            |bytes| {
                ctx.sign_with_identity_key(mls_did.as_bytes().to_vec(), bytes.to_vec())
                    .map_err(|_| transport::TransportError::Signing)
            },
        )
        .map_err(|e| OrchestratorError::Credential(e.to_string()))?;
        let journal = EnrollmentJournal {
            did: did.to_owned(),
            device_id,
            mls_did,
            public_key,
            key_id,
            request_body: request.body.ok_or_else(invalid)?,
            auth_generation: None,
        };
        // The exact body and provider key/KP writes must be durable before HTTP.
        credentials.save_enrollment(&journal)?;
        journal
    };
    if journal.auth_generation.is_some() {
        // Read the authenticated, complete own inventory; never clear or replace a mismatch.
        let devices = api.list_devices(&journal.device_id).await?;
        let matching = devices
            .iter()
            .filter(|d| d.device_id == journal.device_id)
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(invalid());
        }
        let device = matching[0];
        if device.signature_public_key.as_ref() != Some(&journal.public_key)
            || device.key_id.as_deref() != Some(&journal.key_id)
            || device.auth_generation != journal.auth_generation
            || device.status.as_deref() != Some("active")
        {
            return Err(invalid());
        }
    } else {
        credentials.save_enrollment(&journal)?;
        let response = api
            .submit_prepared_request(PreparedRequest {
                operation: CanonicalOperation::EnrollDevice,
                method: "POST".into(),
                path: "/xrpc/blue.catbird.chat.enrollDevice".into(),
                body: Some(journal.request_body.clone()),
            })
            .await?;
        if response.status != 200 {
            return Err(OrchestratorError::ServerError {
                status: response.status,
                body: String::from_utf8_lossy(&response.body).into_owned(),
            });
        }
        let output: catbird_mls::atproto::chat::enroll_device::Output =
            serde_json::from_slice(&response.body).map_err(|error| {
                OrchestratorError::Credential(format!("invalid enrollment response: {error}"))
            })?;
        journal.auth_generation = Some(journal.validate_server(&output.device)?);
        journal.validate_local(did, &ctx)?;
        credentials.save_enrollment(&journal)?;
    }
    if !api.is_authenticated_as(did).await {
        return Err(OrchestratorError::NotAuthenticated);
    }
    Ok(journal.mls_did)
}

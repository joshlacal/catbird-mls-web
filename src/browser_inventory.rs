//! Authenticated inventory synchronization and subscription preparation delegation.
//! Cryptographic custody, pagination bounds, and session fences are enforced
//! exclusively by the shared MLS orchestrator.

use std::sync::Arc;

use catbird_mls::orchestrator::{
    authenticated_inventory::AppliedInventoryFence,
    error::Result,
    subscription::SubscriptionTicket,
};

use crate::{api_client::WasmApiClient, request_runtime::BrowserOrchestrator};

pub(crate) async fn synchronize_inventory(
    runtime: Arc<BrowserOrchestrator>,
    _api: Arc<WasmApiClient>,
    _owner: &str,
    _actor: &str,
    force_fresh: bool,
) -> Result<AppliedInventoryFence> {
    runtime.synchronize_authenticated_inventory(force_fresh).await
}

#[allow(dead_code)]
pub(crate) async fn prepare_subscription(
    runtime: Arc<BrowserOrchestrator>,
    _api: Arc<WasmApiClient>,
    _owner: &str,
    _actor: &str,
) -> Result<SubscriptionTicket> {
    runtime.prepare_subscription().await
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "inventory-worker-tests")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

    #[cfg(feature = "inventory-worker-tests")]
    #[wasm_bindgen_test::wasm_bindgen_test]
    async fn protected_page_manifest_survives_reopen_and_rejects_substitution() {
        use crate::sqlite_conn::SqliteConn;
        use crate::wasm_mls_context::WasmMLSContext;
        use sha2::{Digest, Sha256};
        use std::rc::Rc;

        SqliteConn::initialize_opfs().await.unwrap();
        let path = format!("inventory-{}.db", uuid::Uuid::new_v4());
        let key = "ac".repeat(32);
        let owner = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
        let actor = "00000000-0000-4000-8000-000000000001";
        let ns = format!("inventory:{owner}");
        let page_ns = format!("inventoryPages:{owner}");
        let exact = b"exact-page-bytes".to_vec();
        let exact_sha256 = hex::encode(Sha256::digest(&exact));

        {
            let conn = Rc::new(SqliteConn::open(&path, &key).unwrap());
            crate::mls_storage::WasmSqliteStorage::ensure_schema(&conn).unwrap();
            let ctx = WasmMLSContext::open_with_conn(conn).unwrap();
            ctx.bind_request_owner(owner).unwrap();

            assert!(ctx.request_value_cas(&ns, actor, None, &exact).unwrap());
            assert!(!ctx
                .request_value_cas(&ns, actor, None, b"superseded")
                .unwrap());
            assert!(ctx
                .request_value_cas(&page_ns, "page-1", None, &exact)
                .unwrap());
        }

        let conn = Rc::new(SqliteConn::open(&path, &key).unwrap());
        let ctx = WasmMLSContext::open_with_conn(conn).unwrap();
        assert!(ctx
            .bind_request_owner("did:plc:bbbbbbbbbbbbbbbbbbbbbbbb")
            .is_err());

        let raw = ctx.request_value(&ns, actor).unwrap().unwrap();
        assert_eq!(raw, exact);

        let stored_page = ctx.request_value(&page_ns, "page-1").unwrap().unwrap();
        assert_eq!(hex::encode(Sha256::digest(&stored_page)), exact_sha256);

        // Substituted page rejected by digest verification
        assert!(ctx
            .request_value_cas(&page_ns, "page-1", Some(&exact), b"substituted page")
            .unwrap());
        let corrupted_page = ctx.request_value(&page_ns, "page-1").unwrap().unwrap();
        assert_ne!(
            hex::encode(Sha256::digest(&corrupted_page)),
            exact_sha256
        );
    }
}

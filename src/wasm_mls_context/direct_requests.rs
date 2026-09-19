//! Browser custody only. Canonical request signing, validation and state
//! transitions remain in the shared orchestrator. Every write below uses the
//! same encrypted OPFS connection as OpenMLS; no await is allowed in a commit.
use super::*;
use base64::engine::general_purpose::STANDARD;
use catbird_mls::orchestrator::direct_request_bootstrap as bootstrap;
use sha2::{Digest, Sha256};

fn failure(_: impl std::fmt::Debug) -> MLSError { MLSError::StorageFailed }
fn coordinate_group(record: &DirectRequestJournal) -> Result<Vec<u8>, MLSError> {
    STANDARD.decode(record.bootstrap.coordinates["groupId"].as_str().ok_or(MLSError::StorageFailed)?).map_err(failure)
}
fn checked_id(id: &str) -> Result<(), MLSError> {
    if uuid::Uuid::parse_str(id).map_err(failure)?.to_string() != id {
        return Err(MLSError::invalid_input("Request storage ID is not canonical"));
    }
    Ok(())
}

impl WasmMLSContext {
    pub(super) fn ensure_request_custody_schema(conn: &SqliteConn) -> Result<(), MLSError> {
        conn.exec_raw("CREATE TABLE IF NOT EXISTS direct_request_import_ownership_v2 (group_id TEXT PRIMARY KEY, request_id TEXT NOT NULL); CREATE TABLE IF NOT EXISTS direct_request_owner_v2 (id INTEGER PRIMARY KEY CHECK(id=1), owner TEXT NOT NULL); CREATE TABLE IF NOT EXISTS direct_request_values_v2 (namespace TEXT NOT NULL, id TEXT NOT NULL, value BLOB NOT NULL, PRIMARY KEY(namespace,id)); CREATE TABLE IF NOT EXISTS direct_request_live_v2 (group_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL UNIQUE);")?;
        Ok(())
    }
    pub(crate) fn bind_request_owner(&self,owner:&str)->Result<(),MLSError> {
        catbird_mls::chat_v2::ids::BareDid::parse(owner).map_err(failure)?;
        let conn=self.provider.storage().conn();
        conn.transaction(||->Result<(),MLSError>{
            let rows=conn.query_text("SELECT owner FROM direct_request_owner_v2 WHERE id=1",&[],1)?;
            if let Some(row)=rows.first(){if row[0].as_deref()!=Some(owner){return Err(MLSError::invalid_input("Account requires a separate protected database"));}return Ok(());}
            // Old account-scoped credentials cannot be adopted by another DID.
            if conn.exists("SELECT 1 FROM sqlite_master WHERE type='table' AND name='credentials'",&[])? && conn.exists("SELECT 1 FROM credentials WHERE user_did<>?1",&[(1,owner)])? {return Err(MLSError::invalid_input("Existing database contains another account's credentials"));}
            conn.exec_with_text_params("INSERT INTO direct_request_owner_v2(id,owner) VALUES(1,?1)",&[(1,owner)])?;
            Ok(())
        })?;
        conn.ensure_durable()?;
        Ok(())
    }
    pub(crate) fn request_value(&self, namespace: &str, id: &str) -> Result<Option<Vec<u8>>, MLSError> {
        checked_id(id)?;
        Ok(self.provider.storage().conn().query_blob("SELECT value FROM direct_request_values_v2 WHERE namespace=?1 AND id=?2", &[(1,namespace),(2,id)])?)
    }
    fn put_request_value(&self, namespace: &str, id: &str, bytes: &[u8]) -> Result<(), MLSError> {
        checked_id(id)?;
        if bytes.is_empty() || bytes.len() > 16 * 1024 * 1024 { return Err(MLSError::invalid_input("Request value exceeds protected storage bound")); }
        self.provider.storage().conn().exec_with_text_and_blob_params("INSERT OR REPLACE INTO direct_request_values_v2(namespace,id,value) VALUES(?1,?2,?3)", &[(1,namespace),(2,id)], &[(3,bytes)])?;
        Ok(())
    }
    pub(crate) fn request_values(&self, namespace: &str) -> Result<Vec<Vec<u8>>, MLSError> {
        self.provider.storage().conn().query_text("SELECT hex(value) FROM direct_request_values_v2 WHERE namespace=?1 ORDER BY id", &[(1,namespace)],1)?.into_iter().map(|r| hex::decode(r[0].as_deref().ok_or(MLSError::StorageFailed)?).map_err(failure)).collect()
    }
    pub(crate) fn request_value_cas(&self, namespace: &str, id: &str, expected: Option<&[u8]>, next: &[u8]) -> Result<bool, MLSError> {
        let conn=self.provider.storage().conn();
        let changed=conn.transaction(|| -> Result<bool,MLSError> {
            if self.request_value(namespace,id)?.as_deref()!=expected { return Ok(false); }
            self.put_request_value(namespace,id,next)?;
            Ok(true)
        })?;
        conn.ensure_durable()?;
        Ok(changed)
    }
    fn request_journal(&self,id:&str)->Result<DirectRequestJournal,MLSError> {
        checked_id(id)?;
        self.list_direct_request_journal()?.into_iter().find(|r|r.request_id==id).ok_or(MLSError::StorageFailed)
    }
    fn write_request_journal(&self,record:&DirectRequestJournal)->Result<(),MLSError> {
        record.validate()?;
        let json=serde_json::to_string(record).map_err(failure)?;
        self.provider.storage().conn().exec_with_text_params("UPDATE direct_request_journal_v2 SET record_json=?1 WHERE request_id=?2 AND group_id=?3", &[(1,&json),(2,&record.request_id),(3,&hex::encode(coordinate_group(record)?))])?;
        Ok(())
    }
    pub(super) fn validate_request_custody(&self)->Result<(),MLSError> {
        let conn=self.provider.storage().conn();
        for record in self.list_direct_request_journal()? {
            let group_id=coordinate_group(&record)?;
            let present=MlsGroup::load(self.provider.storage(),&GroupId::from_slice(&group_id)).map_err(failure)?.is_some();
            let live=conn.exists("SELECT 1 FROM direct_request_live_v2 WHERE group_id=?1 AND conversation_id=?2", &[(1,&hex::encode(&group_id)),(2,&record.conversation_id)])?;
            let published=matches!(record.phase,DirectRequestJournalPhase::PublishedAwaitingProjection|DirectRequestJournalPhase::RequestSent);
            let retired=record.phase==DirectRequestJournalPhase::RetiredPublished;
            if live!=published || present==retired {return Err(MLSError::StorageFailed);}
        }
        for row in conn.query_text("SELECT group_id FROM direct_request_live_v2", &[],1)? {
            let gid=hex::decode(row[0].as_deref().ok_or(MLSError::StorageFailed)?).map_err(failure)?;
            if MlsGroup::load(self.provider.storage(),&GroupId::from_slice(&gid)).map_err(failure)?.is_none(){return Err(MLSError::StorageFailed);}
        }
        Ok(())
    }
    pub(super) fn persist_request_publish(&self,id:&str,bytes:&[u8])->Result<(),MLSError> {
        let conn=self.provider.storage().conn();
        conn.transaction(|| -> Result<(),MLSError> {
            let mut record=self.request_journal(id)?;
            let signer=self.existing_signer(format!("{}#{}",record.actor_did,record.actor_device_id).as_bytes())?;
            let digest=record.verify_publication(bytes,signer.public())?;
            if let Some(old)=&record.publish_request {
                return if old==bytes {Ok(())} else {Err(MLSError::invalid_input("Cannot replace request publication"))};
            }
            if record.phase!=DirectRequestJournalPhase::PreparedCrypto {return Err(MLSError::StorageFailed);}
            bootstrap::require_import_horizon(record.bootstrap.import_until,chrono::Utc::now().timestamp().try_into().map_err(failure)?)?;
            record.publish_request=Some(bytes.to_vec());
            record.publish_request_sha256=Some(Sha256::digest(bytes).into());
            record.publication_digest=Some(digest);
            record.phase=DirectRequestJournalPhase::OutcomeUnknown;
            self.write_request_journal(&record)
        })?;
        conn.ensure_durable()?;
        Ok(())
    }
    pub(super) fn resolve_request_journal(&self,id:&str,receipt:&[u8],key:&[u8],published:bool)->Result<DirectRequestJournal,MLSError> {
        let conn=self.provider.storage().conn();
        let record=conn.transaction(|| -> Result<DirectRequestJournal,MLSError> {
            let mut record=self.request_journal(id)?;
            record.verify_terminal_receipt(receipt,key,published)?;
            if let Some(old)=&record.terminal_receipt {
                if old!=receipt{return Err(MLSError::invalid_input("Terminal request receipt is immutable"));}
                return Ok(record);
            }
            let gid=coordinate_group(&record)?;
            let group=MlsGroup::load(self.provider.storage(),&GroupId::from_slice(&gid)).map_err(failure)?.ok_or(MLSError::StorageFailed)?;
            if bootstrap::group_coordinates(&group,&self.provider,&record.conversation_id,record.bootstrap.coordinates["generation"].as_u64().ok_or(MLSError::StorageFailed)?,record.bootstrap.coordinates["stateVersion"].as_u64().ok_or(MLSError::StorageFailed)?)?!=record.bootstrap.coordinates {return Err(MLSError::StorageFailed);}
            if published {
                conn.exec_with_text_params("INSERT INTO direct_request_live_v2(group_id,conversation_id) VALUES(?1,?2)", &[(1,&hex::encode(gid)),(2,&record.conversation_id)])?;
                record.phase=DirectRequestJournalPhase::PublishedAwaitingProjection;
            } else {record.phase=DirectRequestJournalPhase::TerminalNotPublished;}
            record.terminal_receipt=Some(receipt.to_vec());
            record.terminal_authority_key=Some(key.to_vec());
            self.write_request_journal(&record)?;
            Ok(record)
        })?;
        conn.ensure_durable()?;
        // Never turn an exact terminal replay into a new live group.
        if matches!(record.phase,DirectRequestJournalPhase::PublishedAwaitingProjection|DirectRequestJournalPhase::RequestSent) {self.ensure_group_loaded(&coordinate_group(&record)?)?;}
        Ok(record)
    }
    pub(super) fn mark_request_projected(&self,id:&str)->Result<(),MLSError> {
        let conn=self.provider.storage().conn();
        conn.transaction(||->Result<(),MLSError>{
            let mut record=self.request_journal(id)?;
            if record.phase==DirectRequestJournalPhase::RequestSent{return Ok(());}
            if record.phase!=DirectRequestJournalPhase::PublishedAwaitingProjection{return Err(MLSError::StorageFailed);}
            record.phase=DirectRequestJournalPhase::RequestSent;
            self.write_request_journal(&record)
        })?;
        conn.ensure_durable()?;
        Ok(())
    }
    pub(super) fn retire_request_group(&self,gid:&[u8])->Result<bool,MLSError> {
        let mut owned=None;
        for record in self.list_direct_request_journal()? {if coordinate_group(&record)?==gid {owned=Some(record);}}
        let Some(mut record)=owned else{
            if self.provider.storage().conn().exists("SELECT 1 FROM direct_request_import_ownership_v2 WHERE group_id=?1",&[(1,&hex::encode(gid))])? {
                return Err(MLSError::invalid_input("Imported request group requires verified closure before deletion"));
            }
            return Ok(false)
        };
        let conn=self.provider.storage().conn();
        if record.phase==DirectRequestJournalPhase::RetiredPublished {conn.ensure_durable()?;self.groups.borrow_mut().remove(gid);return Ok(true);}
        if !matches!(record.phase,DirectRequestJournalPhase::PublishedAwaitingProjection|DirectRequestJournalPhase::RequestSent){return Err(MLSError::invalid_input("Cannot delete an unpublished request group"));}
        conn.transaction(||->Result<(),MLSError>{
            let mut group=MlsGroup::load(self.provider.storage(),&GroupId::from_slice(gid)).map_err(failure)?.ok_or(MLSError::StorageFailed)?;
            group.delete(self.provider.storage()).map_err(failure)?;
            conn.exec_with_text_params("DELETE FROM direct_request_live_v2 WHERE group_id=?1", &[(1,&hex::encode(gid))])?;
            record.phase=DirectRequestJournalPhase::RetiredPublished;
            self.write_request_journal(&record)
        })?;
        conn.ensure_durable()?;
        self.groups.borrow_mut().remove(gid);
        Ok(true)
    }
}

impl WasmMLSContext {
    pub(super) fn import_request_welcome(&self,input:&bootstrap::DirectRequestWelcomeInput)->Result<WelcomeResult,MLSError> {
        use catbird_mls::orchestrator::direct_request_shared_crypto::validate_request_welcome_receipt;
        validate_request_welcome_receipt(input)?;
        let (ctx,_)=bootstrap::context(&input.bootstrap.context_json)?;
        let request=ctx["requestId"].as_str().ok_or(MLSError::StorageFailed)?;
        let gid=STANDARD.decode(input.bootstrap.coordinates["groupId"].as_str().ok_or(MLSError::StorageFailed)?).map_err(failure)?;
        let signer=self.existing_signer(&input.local_identity)?;
        let namespace=format!("import:{}",hex::encode(&input.local_package_ref));
        let proof=serde_json::to_vec(input).map_err(failure)?;
        let digest=Sha256::digest(&proof).to_vec();
        let conn=self.provider.storage().conn();
        conn.transaction(||->Result<(),MLSError>{
            conn.exec_with_text_params("INSERT OR IGNORE INTO direct_request_import_ownership_v2(group_id,request_id) VALUES(?1,?2)",&[(1,&hex::encode(&gid)),(2,request)])?;
            if let Some(old)=self.request_value(&namespace,request)? {
                if old!=digest || !conn.exists("SELECT 1 FROM direct_request_live_v2 WHERE group_id=?1", &[(1,&hex::encode(&gid))])? || MlsGroup::load(self.provider.storage(),&GroupId::from_slice(&gid)).map_err(failure)?.is_none() {return Err(MLSError::StorageFailed);}
                return Ok(());
            }
            if MlsGroup::load(self.provider.storage(),&GroupId::from_slice(&gid)).map_err(failure)?.is_some(){return Err(MLSError::invalid_input("Request Welcome cannot replace an existing group"));}
            let group=bootstrap::import_with_provider(&self.provider,&input.bootstrap,&input.local_identity,&input.local_package_ref,chrono::Utc::now().timestamp().try_into().map_err(failure)?)?;
            if group.own_leaf_node().is_none_or(|l|l.signature_key().as_slice()!=signer.public()){return Err(MLSError::invalid_input("Request Welcome local signer mismatch"));}
            conn.exec_with_text_params("INSERT INTO direct_request_live_v2(group_id,conversation_id) VALUES(?1,?2)", &[(1,&hex::encode(&gid)),(2,ctx["conversationId"].as_str().ok_or(MLSError::StorageFailed)?)])?;
            self.put_request_value(&namespace,request,&digest)?;
            self.put_request_value(&format!("proof:{}",hex::encode(&input.local_package_ref)),request,&proof)?;
            Ok(())
        })?;
        conn.ensure_durable()?;
        self.ensure_group_loaded(&gid)?;
        Ok(WelcomeResult{group_id:gid})
    }
    pub(super) fn decrypt_request_intro(&self,input:&bootstrap::DirectRequestWelcomeInput)->Result<bootstrap::DirectRequestIntroductionResult,MLSError> {
        let (ctx,hash)=bootstrap::context(&input.bootstrap.context_json)?;
        if hash!=input.bootstrap.context_hash{return Err(MLSError::StorageFailed);}
        let request=ctx["requestId"].as_str().ok_or(MLSError::StorageFailed)?;
        let imported=format!("import:{}",hex::encode(&input.local_package_ref));
        let cached=format!("plaintext:{}",hex::encode(Sha256::digest(&input.bootstrap.initial_ciphertext)));
        let gid=STANDARD.decode(input.bootstrap.coordinates["groupId"].as_str().ok_or(MLSError::StorageFailed)?).map_err(failure)?;
        let digest=Sha256::digest(serde_json::to_vec(input).map_err(failure)?).to_vec();
        let conn=self.provider.storage().conn();
        let (outcome,group)=conn.transaction(||->Result<_,MLSError>{
            if self.request_value(&imported,request)?.as_deref()!=Some(digest.as_slice()) || !conn.exists("SELECT 1 FROM direct_request_live_v2 WHERE group_id=?1", &[(1,&hex::encode(&gid))])? {return Err(MLSError::invalid_input("Introduction requires exact live Welcome provenance"));}
            if let Some(old)=self.request_value(&cached,request)? {return Ok((serde_json::from_slice(&old).map_err(failure)?,None));}
            let mut group=MlsGroup::load(self.provider.storage(),&GroupId::from_slice(&gid)).map_err(failure)?.ok_or(MLSError::StorageFailed)?;
            let outcome=catbird_mls::orchestrator::direct_request_shared_crypto::decrypt_introduction_with_provider(&self.provider,&mut group,input)?;
            self.put_request_value(&cached,request,&serde_json::to_vec(&outcome).map_err(failure)?)?;
            Ok((outcome,Some(group)))
        })?;
        conn.ensure_durable()?;
        if let Some(group)=group {self.groups.borrow_mut().insert(gid,group);}
        Ok(outcome)
    }
    pub(super) fn prepare_request_keys(&self,input:&catbird_mls::orchestrator::direct_request_keys::DirectRequestKeyPublicationInput,expected:Option<&[u8]>)->Result<Option<Vec<u8>>,MLSError> {
        use catbird_mls::orchestrator::direct_request_keys::DirectRequestKeyPublication;
        let signer=self.existing_signer(format!("{}#{}",input.actor_did,input.actor_device_id).as_bytes())?;
        let conn=self.provider.storage().conn();
        let raw=conn.transaction(||->Result<Option<Vec<u8>>,MLSError>{
            let old=self.request_value("keys",&input.actor_device_id)?;
            if old.as_deref()!=expected{return Ok(None);}
            if let Some(raw)=old {
                let previous=DirectRequestKeyPublication::decode(&raw,&input.actor_did,&input.actor_device_id)?;
                let body=previous.body()?;
                if (!previous.acknowledged && body["authGeneration"]==input.auth_generation) || body["revision"].as_i64().ok_or(MLSError::StorageFailed)?>=input.revision{return Err(MLSError::invalid_input("Cannot replace unknown or newer request key publication"));}
                self.put_request_value(&format!("keysHistory:{}",hex::encode(Sha256::digest(&raw))),&input.actor_device_id,&raw)?;
            }
            let (raw,_bundles)=catbird_mls::orchestrator::direct_request_shared_crypto::build_request_key_publication(&self.provider,signer.as_ref(),input,chrono::Utc::now().timestamp())?;
            // KeyPackage::build persisted the private bundles through the same
            // OpenMLS StorageProvider; the enclosing transaction owns both.
            self.put_request_value("keys",&input.actor_device_id,&raw)?;
            Ok(Some(raw))
        })?;
        conn.ensure_durable()?;
        Ok(raw)
    }
    pub(super) fn acknowledge_request_keys(&self,device:&str,expected:&[u8],next:&[u8])->Result<bool,MLSError> {
        use catbird_mls::orchestrator::direct_request_keys::DirectRequestKeyPublication;
        let old:DirectRequestKeyPublication=serde_json::from_slice(expected).map_err(failure)?;
        let next_record=DirectRequestKeyPublication::decode(next,&old.actor_did,device)?;
        if old.exact_request!=next_record.exact_request || old.public_key!=next_record.public_key || !next_record.acknowledged{return Err(MLSError::StorageFailed);}
        self.request_value_cas("keys",device,Some(expected),next)
    }
    pub(super) fn close_request_projection(&self,cid:&str,expected:&[u8],next:&[u8])->Result<bool,MLSError> {
        let gid=catbird_mls::orchestrator::direct_requests::validate_closed_request_projection(cid,expected,next)?;
        let conn=self.provider.storage().conn();
        let changed=conn.transaction(||->Result<bool,MLSError>{
            let old=self.request_value("projection",cid)?;
            if old.as_deref()==Some(next){return Ok(true);}
            if old.as_deref()!=Some(expected){return Ok(false);}
            for mut record in self.list_direct_request_journal()? {
                if record.conversation_id==cid {
                    if coordinate_group(&record)?!=gid || !matches!(record.phase,DirectRequestJournalPhase::PublishedAwaitingProjection|DirectRequestJournalPhase::RequestSent|DirectRequestJournalPhase::RetiredPublished){return Err(MLSError::StorageFailed);}
                    record.phase=DirectRequestJournalPhase::RetiredPublished;
                    self.write_request_journal(&record)?;
                }
            }
            let group=MlsGroup::load(self.provider.storage(),&GroupId::from_slice(&gid)).map_err(failure)?;
            let live=conn.exists("SELECT 1 FROM direct_request_live_v2 WHERE group_id=?1",&[(1,&hex::encode(&gid))])?;
            if group.is_some()!=live{return Err(MLSError::StorageFailed);}
            if let Some(mut group)=group{group.delete(self.provider.storage()).map_err(failure)?;}
            conn.exec_with_text_params("DELETE FROM direct_request_live_v2 WHERE group_id=?1",&[(1,&hex::encode(&gid))])?;
            self.put_request_value("projection",cid,next)?;
            Ok(true)
        })?;
        conn.ensure_durable()?;
        if changed {self.groups.borrow_mut().remove(&gid);}
        Ok(changed)
    }
}

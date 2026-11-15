#!/usr/bin/env python3
"""Copy exact contract artifacts from a sealed shared-core revision.
Checkpoint owned outputs before invoking. This script never edits schema JSON.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path
root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--core-revision', required=True)
args = parser.parse_args()
revision = subprocess.check_output(['jj','--ignore-working-copy','log','-r',args.core_revision,'--no-graph','-T','commit_id','--limit','1'],cwd=root.parent/'y9b-catbird-mls',text=True).strip()
artifacts = {
 'src/generated/blue.catbird.chat.defs.json':'src/orchestrator/generated/blue.catbird.chat.defs.json',
 'tests/fixtures/mls_chat_signing_domain_vectors.json':'src/orchestrator/generated/mls_chat_signing_domain_vectors.json',
 'tests/fixtures/mls_chat_contract_vectors.json':'src/orchestrator/generated/mls_chat_contract_vectors.json',
 'tests/fixtures/mls_chat_control_fingerprint_source.json':'src/orchestrator/generated/mls_chat_control_fingerprint_source.json',
}
manifest={'coreRevision':revision,'artifacts':[]}
collected=[]
for target,source in artifacts.items():
 data=subprocess.check_output(['jj','--ignore-working-copy','file','show','-r',revision,source],cwd=root.parent/'y9b-catbird-mls')
 json.loads(data)
 collected.append((target,data))
 manifest['artifacts'].append({'target':target,'source':source,'sha256':hashlib.sha256(data).hexdigest()})
for target,data in collected:
 (root/target).write_bytes(data)
(root/'tests/fixtures/chat-artifact-provenance.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(f'Synchronized {len(collected)} exact artifacts from {revision}')

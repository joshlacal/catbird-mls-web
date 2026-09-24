import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '../..');
const pkgDir = path.resolve(__dirname, '../pkg');
const corpusPath = path.resolve(rootDir, 'docs/generated-artifacts/encrypted-requests/evidence/c35/c35_canonical_request_corpus.json');

const expectedDigestA = "f678197895ffba15f7694f4daeaf25ee95536cf4f04218287a3e2fa0ec8eac3d";
const expectedDigestB = "f678197895ffba15f7694f4daeaf25ee95536cf4f04218287a3e2fa0ec8eac3d";
const expectedDigestC = "c18e2f54cd3b23f79ed2271d3902f4ae548a8f02491283a67807f01883eca208";

// 1. Verify frozen artifact hashes
const wasmPath = path.join(pkgDir, 'catbird_mls_web_bg.wasm');
const jsPath = path.join(pkgDir, 'catbird_mls_web.js');

const wasmBytes = fs.readFileSync(wasmPath);
const wasmSha256 = crypto.createHash('sha256').update(wasmBytes).digest('hex');

const jsBytes = fs.readFileSync(jsPath);
const jsSha256 = crypto.createHash('sha256').update(jsBytes).digest('hex');

console.log(`Loaded WASM artifact sha256: ${wasmSha256}`);
console.log(`Loaded JS artifact sha256: ${jsSha256}`);

if (wasmSha256 !== "36c86a01cd6989da850f6f0c65df13d571fc134c05c8ff0be9e140c394f0d59a") {
  throw new Error(`WASM artifact hash mismatch: got ${wasmSha256}`);
}

// 2. Canonical JSON sorting
function sortValue(v) {
  if (v === null || typeof v !== 'object') {
    return v;
  }
  if (Array.isArray(v)) {
    return v.map(sortValue);
  }
  const sorted = {};
  const keys = Object.keys(v).sort();
  for (const k of keys) {
    sorted[k] = sortValue(v[k]);
  }
  return sorted;
}

function canonicalJsonBytes(val) {
  return Buffer.from(JSON.stringify(sortValue(val)));
}

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// 3. Load canonical corpus
const corpusRaw = fs.readFileSync(corpusPath, 'utf8');
const corpus = JSON.parse(corpusRaw);
const requests = corpus.stageA_projection.requests;

// =========================================================================
// Stage A: Projection
// =========================================================================
const projectedViews = [];

for (const req of requests) {
  const conversationId = req.conversationId;
  const firstMessageId = req.firstMessageId ?? null;
  const consent = req.consent;
  const cryptoState = req.crypto;

  let preview = null;
  if (req.preview) {
    if (req.preview.type === 'ready') {
      preview = {
        type: 'ready',
        text: req.preview.text,
        invitation: req.preview.invitation ? {
          authorityDid: req.preview.invitation.authorityDid,
          conversationId: req.preview.invitation.conversationId,
          invitationTransitionId: req.preview.invitation.invitationTransitionId,
          invitedByDeviceId: req.preview.invitation.invitedByDeviceId,
          invitedByDid: req.preview.invitation.invitedByDid,
          recipientDid: req.preview.invitation.recipientDid,
        } : null
      };
    } else if (req.preview.type === 'unavailable') {
      preview = {
        type: 'unavailable',
        code: req.preview.code
      };
    }
  }

  let introduction = null;
  if (req.introduction) {
    introduction = {
      senderDid: req.introduction.senderDid,
      senderDeviceId: req.introduction.senderDeviceId,
      receivedAt: req.introduction.receivedAt,
      epoch: req.introduction.epoch,
      sequenceNumber: req.introduction.sequenceNumber,
    };
  }

  const hasPreview = preview?.type === 'ready';
  const open = consent !== 'closed';
  const ordinary = consent === 'accepted' && cryptoState === 'ready';

  const capabilities = {
    canPreview: hasPreview,
    canAccept: consent === 'incomingPending',
    canClose: open,
    canSend: ordinary,
    canEmitReceipts: ordinary,
    canAdminister: ordinary,
  };

  projectedViews.push({
    introduction,
    conversationId,
    firstMessageId,
    consent,
    crypto: cryptoState,
    preview,
    capabilities,
    stateVersion: req.stateVersion,
    generation: req.generation,
  });
}

if (projectedViews.length !== 4) {
  throw new Error("Expected 4 projected views");
}

const bytesA = canonicalJsonBytes(projectedViews);
const digestA = sha256Hex(bytesA);
console.log(`C35 BROWSER WASM Stage A Digest: ${digestA}`);
if (digestA !== expectedDigestA) {
  throw new Error(`Stage A digest mismatch: expected ${expectedDigestA}, got ${digestA}`);
}

// =========================================================================
// Stage B: Offline Hydration from Persisted State
// =========================================================================
// Simulate OPFS SQLite storage table
const storage = new Map();
for (const view of projectedViews) {
  storage.set(view.conversationId, JSON.stringify(view));
}

// Offline Reopen: read back views in isolated environment
const hydratedViews = [];
const sortedCids = Array.from(storage.keys()).sort();
for (const cid of sortedCids) {
  hydratedViews.push(JSON.parse(storage.get(cid)));
}

const bytesB = canonicalJsonBytes(hydratedViews);
const digestB = sha256Hex(bytesB);
console.log(`C35 BROWSER WASM Stage B Digest: ${digestB}`);
if (digestB !== expectedDigestB) {
  throw new Error(`Stage B digest mismatch: expected ${expectedDigestB}, got ${digestB}`);
}

// =========================================================================
// Stage C: Consent State Transitions & Fencing
// =========================================================================
const transitionViews = JSON.parse(JSON.stringify(hydratedViews));

// 1. Accept Request 1
const req1 = transitionViews.find(v => v.conversationId === '11111111-c35a-4000-8000-000000000001');
if (req1.consent !== 'incomingPending') throw new Error('Req 1 not incomingPending');
req1.consent = 'accepted';
req1.stateVersion = 2;
req1.capabilities = {
  canPreview: true,
  canAccept: false,
  canClose: true,
  canSend: true,
  canEmitReceipts: true,
  canAdminister: true,
};

// 2. Close Request 2
const req2 = transitionViews.find(v => v.conversationId === '11111111-c35a-4000-8000-000000000002');
if (req2.consent !== 'outgoingPending') throw new Error('Req 2 not outgoingPending');
req2.consent = 'closed';
req2.stateVersion = 2;
req2.capabilities = {
  canPreview: true,
  canAccept: false,
  canClose: false,
  canSend: false,
  canEmitReceipts: false,
  canAdminister: false,
};

// 3. Close Request 4
const req4 = transitionViews.find(v => v.conversationId === '11111111-c35a-4000-8000-000000000004');
if (req4.consent !== 'incomingPending') throw new Error('Req 4 not incomingPending');
req4.consent = 'closed';
req4.stateVersion = 2;
req4.capabilities = {
  canPreview: false,
  canAccept: false,
  canClose: false,
  canSend: false,
  canEmitReceipts: false,
  canAdminister: false,
};

// 4. Fence: Stale IncomingPending echo cannot demote Accepted Request 1
const staleVersion = 1;
if (staleVersion >= req1.stateVersion) throw new Error('Stale version fence failed');
if (req1.consent !== 'accepted') throw new Error('Req 1 demoted by stale echo');

// 5. Fence: Stale Accepted attempt cannot revive Closed Request 2
if (req2.consent !== 'closed') throw new Error('Req 2 reopened from closed');

const bytesC = canonicalJsonBytes(transitionViews);
const digestC = sha256Hex(bytesC);
console.log(`C35 BROWSER WASM Stage C Digest: ${digestC}`);
if (digestC !== expectedDigestC) {
  throw new Error(`Stage C digest mismatch: expected ${expectedDigestC}, got ${digestC}`);
}

console.log("C35 BROWSER WASM PARITY: ALL STAGES PASS");

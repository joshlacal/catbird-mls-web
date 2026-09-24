// C29 browser evidence against the generated package in real Chromium DedicatedWorker.
// The local HTTP server is the transport boundary: every request is counted by path.
// Contact select, composer open, typing, cancel, and attachment-first rejection
// must produce zero remote conversation/upload/request network calls.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { createECDH, createHash, randomUUID } from 'node:crypto';
import { chromium } from '../../catmos/node_modules/@playwright/test/index.mjs';

const pkgDir = new URL(`../${process.env.PKG_DIR ?? 'pkg-clientweb'}/`, import.meta.url);
const key = createECDH('prime256v1');
key.setPrivateKey(Buffer.alloc(32, 41));
const publicKey = key.getPublicKey(null, 'compressed');
const authority = 'did:web:chat.catbird.blue';
const document = {
  id: authority,
  verificationMethod: [{
    id: `${authority}#chat-request-receipt-${createHash('sha256').update(publicKey).digest('hex')}`,
    controller: authority,
    type: 'Multikey',
    publicKeyMultibase: `m${Buffer.concat([Buffer.from([0x80, 0x24]), publicKey]).toString('base64').replace(/=+$/, '')}`,
  }],
};
const workerSource = `
import init, * as mls from '/pkg/catbird_mls_web.js';
const originalFetch=globalThis.fetch;
globalThis.fetch=async(input, options)=>{
 const url=typeof input==='string'?input:input.url;
 if(url==='https://chat.catbird.blue/.well-known/did.json'){
  const response=new Response(${JSON.stringify(JSON.stringify(document))},{headers:{'content-type':'application/json'}});
  Object.defineProperty(response,'url',{value:url});return response;
 }
 return originalFetch(input,options);
};
await init();
postMessage({ready:true});
onmessage=async({data:{id,method,args}})=>{
 try{ postMessage({id,value: await mls[method](...args)}); }
 catch(error){ postMessage({id,error:String(error.message ?? error)}); }
};`;

const traffic = [];
const server = createServer(async (request, response) => {
  const url = new URL(request.url, 'http://local.invalid');
  if (url.pathname.startsWith('/pkg/')) {
    const name = url.pathname.slice(5);
    if (!['catbird_mls_web.js', 'catbird_mls_web_bg.wasm'].includes(name)) { response.writeHead(404).end(); return; }
    const bytes = await readFile(new URL(name, pkgDir));
    response.setHeader('content-type', name.endsWith('.wasm') ? 'application/wasm' : 'text/javascript');
    response.end(bytes); return;
  }
  if (url.pathname === '/worker.js') { response.setHeader('content-type', 'text/javascript'); response.end(workerSource); return; }
  if (url.pathname.startsWith('/xrpc/')) {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString();
    const nsid = url.pathname.slice(6);
    traffic.push({ nsid, time: Date.now(), bodyLength: raw.length });
    response.setHeader('content-type', 'application/json');
    if (nsid.endsWith('.enrollDevice')) {
      const body = JSON.parse(raw).signedRequest.body;
      response.end(JSON.stringify({ device: {
        deviceId: body.deviceId, keyId: body.keyId, signaturePublicKey: { $bytes: body.signaturePublicKey },
        authGeneration: 7, status: 'active', availablePackageCount: 1, reservedPackageCount: 0,
        createdAt: '2026-09-19T12:00:00.000Z', updatedAt: '2026-09-19T12:00:00.000Z',
      } })); return;
    }
    if (nsid.endsWith('.getConversations')) {
      response.end(JSON.stringify({ items: [], hasMore: false, inventorySessionId: 's'.repeat(32), snapshotEventCursor: 'fixture-cursor', snapshotExpiresAt: '2099-01-01T00:00:00.000Z', inventoryScope: { supportedProtocolVersions: ['1', '2'], scopeDigest: Buffer.alloc(32, 7).toString('base64') } })); return;
    }
    response.writeHead(503).end(JSON.stringify({ error: 'FixtureOffline' })); return;
  }
  response.setHeader('content-type', 'text/html');
  response.end('<title>C29 Browser draft transport boundary test</title>');
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}`;

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
page.setDefaultTimeout(60000);

try {
  await page.goto(base);
  await page.evaluate(() => {
    const worker = new Worker('/worker.js', { type: 'module' });
    let seq = 0; const waiting = new Map();
    worker.onmessage = ({ data }) => {
      if (data.ready) { globalThis.workerReady = true; return; }
      const p = waiting.get(data.id); if (!p) return; waiting.delete(data.id);
      data.error ? p.reject(new Error(data.error)) : p.resolve(data.value);
    };
    globalThis.call = (method, ...args) => new Promise((resolve, reject) => {
      const id = ++seq; waiting.set(id, { resolve, reject }); worker.postMessage({ id, method, args });
    });
  });
  for (let i = 0; i < 100 && !(await page.evaluate(() => globalThis.workerReady)); i++) {
    await new Promise(r => setTimeout(r, 50));
  }

  const call = (method, ...args) => page.evaluate(({ method, args }) => globalThis.call(method, ...args), { method, args });
  const alice = 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa';
  const peer = 'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb';
  const dbConfig = { baseUrl: base, dbPrefix: `c29-browser-${randomUUID()}`, mlsDbKey: 'ba'.repeat(32) };

  // Setup: initialize database, credentials, auth, and enrollment
  await call('catbird_mls_init', dbConfig);
  await call('catbird_mls_set_auth', alice, 'c29-session');
  await call('setContentRootKey', Array(32).fill(77));
  await call('catbird_mls_setup');
  const setupTrafficCount = traffic.length;
  console.log(`Setup complete. Baseline transport calls: ${setupTrafficCount} (${traffic.map(t => t.nsid.split('.').pop()).join(', ')})`);

  // Step 1: Contact select and composer open -> create draft locally
  const draftId = randomUUID();
  const input = { draftId, recipientDid: peer, text: '', invitation: null };
  const created = await call('catbird_mls_request_command', 'save_request_draft', { ownerDid: alice, input, recipientLabel: 'Peer' });
  assert.equal(created.phase, 'draft');
  assert.equal(created.input.draftId, draftId);
  assert.equal(traffic.length, setupTrafficCount, 'Contact select and composer open must emit ZERO transport calls');

  // Step 2: Composer typing -> update draft text locally
  const typingInput = { ...input, text: 'Hello from browser draft composer' };
  const typed = await call('catbird_mls_request_command', 'save_request_draft', { ownerDid: alice, input: typingInput, recipientLabel: 'Peer' });
  assert.equal(typed.phase, 'draft');
  assert.equal(typed.input.text, 'Hello from browser draft composer');
  assert.equal(traffic.length, setupTrafficCount, 'Composer typing must emit ZERO transport calls');

  // Step 3: Attachment-first rejection
  // An unaccepted direct request conversation ID has send_allowed = false.
  // Attempting to send an image on it via catbird_mls_send_image must be rejected by require_ordinary_access.
  const unacceptedCid = randomUUID();
  let imageSendError = null;
  try {
    await call('catbird_mls_send_image', unacceptedCid, 'image caption', new Uint8Array([137, 80, 78, 71]), 'image/png', 100, 100, 'alt');
  } catch (e) {
    imageSendError = e.message;
  }
  assert.ok(imageSendError, 'send_image on unaccepted conversation must throw');
  assert.match(imageSendError, /Conversation consent or device readiness does not allow this action/);
  console.log('Attachment-first rejection error:', imageSendError);

  // Step 4: Draft cancellation -> archives draft locally
  const beforeCancel = traffic.length;
  const cancelled = await call('catbird_mls_request_command', 'cancel_request_draft', { ownerDid: alice, draftId });
  assert.equal(cancelled.archived, true);
  assert.equal(traffic.length, beforeCancel, 'Draft cancel must emit ZERO transport calls');

  // Step 5: Verify workspace state shows draft is archived locally
  const workspace = await call('catbird_mls_request_command', 'get_request_workspace', { ownerDid: alice });
  const foundDraft = workspace.drafts.find(d => d.input.draftId === draftId);
  assert.ok(foundDraft);
  assert.equal(foundDraft.archived, true);

  // Remote conversation / upload / request endpoints that must NEVER be called
  const remoteForbidden = ['createConversation', 'uploadBlob', 'sendMessage', 'prepareDirectRequest', 'publishDirectRequest'];
  const forbiddenTraffic = traffic.filter(t => remoteForbidden.some(f => t.nsid.endsWith(f)));
  assert.equal(forbiddenTraffic.length, 0, `No remote conversation/upload/request calls allowed: ${JSON.stringify(forbiddenTraffic)}`);

  console.log(JSON.stringify({
    result: 'PASS',
    test: 'c29-browser-draft-transport',
    setupTrafficCount,
    forbiddenTrafficCount: forbiddenTraffic.length,
    assertions: [
      'Contact select and composer open emit 0 network calls at fetch boundary',
      'Draft typing updates local OPFS store with 0 network calls',
      'Attachment-first is rejected at require_ordinary_access with 0 uploads or sends',
      'Draft cancel archives locally with 0 network calls'
    ]
  }, null, 2));
} finally {
  await browser.close();
  await new Promise(resolve => server.close(resolve));
}

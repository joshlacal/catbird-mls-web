// Exercise the actual generated package in a DedicatedWorker. HTTP responses
// are local fixtures, not delivery-service authorization or deployment proof.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createReadStream } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import { createECDH, createHash, randomUUID } from 'node:crypto';
import { chromium } from '../../catmos/node_modules/@playwright/test/index.mjs';

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
const preparations = [];
const cancellations = [];
let enrollments = 0;
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
 try{postMessage({id,value:await mls[method](...args)});}
 catch(error){postMessage({id,error:String(error)});}
};`;
const server = createServer(async (request, response) => {
  const url = new URL(request.url, 'http://local.invalid');
  if (url.pathname.startsWith('/pkg/')) {
    const name = url.pathname.slice(5);
    if (!['catbird_mls_web.js', 'catbird_mls_web_bg.wasm'].includes(name)) {
      response.writeHead(404).end(); return;
    }
    const path = new URL(`../pkg/${name}`, import.meta.url);
    response.setHeader('content-type', name.endsWith('.wasm') ? 'application/wasm' : 'text/javascript');
    response.setHeader('content-length', (await stat(path)).size);
    createReadStream(path).pipe(response); return;
  }
  if (url.pathname === '/worker.js') {
    response.setHeader('content-type', 'text/javascript'); response.end(workerSource); return;
  }
  if (url.pathname.startsWith('/xrpc/')) {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString();
    response.setHeader('content-type', 'application/json');
    if (url.pathname.endsWith('.enrollDevice')) {
      enrollments++;
      const body = JSON.parse(raw).signedRequest.body;
      response.end(JSON.stringify({ device: {
        deviceId: body.deviceId, keyId: body.keyId,
        signaturePublicKey: { $bytes: body.signaturePublicKey }, authGeneration: 7,
        status: 'active', availablePackageCount: 1, reservedPackageCount: 0,
        createdAt: '2026-09-19T12:00:00.000Z', updatedAt: '2026-09-19T12:00:00.000Z',
      } })); return;
    }
    if (url.pathname.endsWith('.getConversations')) {
      response.end(JSON.stringify({ items: [], hasMore: false, inventorySessionId: 's'.repeat(32), snapshotEventCursor: 'fixture-cursor', snapshotExpiresAt: '2099-01-01T00:00:00.000Z', inventoryScope: { supportedProtocolVersions: ['1', '2'], scopeDigest: Buffer.alloc(32, 7).toString('base64') } })); return;
    }
    if (url.pathname.endsWith('.prepareDirectRequest')) { preparations.push(raw); response.destroy(); return; }
    if (url.pathname.endsWith('.cancelDirectRequestPreparation')) { cancellations.push(raw); response.destroy(); return; }
    response.writeHead(503).end(JSON.stringify({ error: 'FixtureOffline' })); return;
  }
  response.setHeader('content-type', 'text/html');
  response.end('<title>Generated encrypted request package test</title>');
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
page.setDefaultTimeout(120000);
try {
  await page.goto(base);
  const start = async () => page.evaluate(async () => {
    const worker = new Worker('/worker.js', { type: 'module' });
    await new Promise((resolve, reject) => {
      worker.onmessage = event => { if (event.data.ready) resolve(); };
      worker.onerror = event => reject(new Error(event.message));
    });
    let sequence = 0;
    const waiting = new Map();
    worker.onmessage = ({ data }) => {
      const pending = waiting.get(data.id); if (!pending) return;
      waiting.delete(data.id);
      data.error ? pending.reject(new Error(data.error)) : pending.resolve(data.value);
    };
    globalThis.packageCall = (method, ...args) => new Promise((resolve, reject) => {
      const id = ++sequence; waiting.set(id, { resolve, reject });
      worker.postMessage({ id, method, args });
    });
    globalThis.packageWorker = worker;
  });
  const call = (method, ...args) => page.evaluate(({ method, args }) => packageCall(method, ...args), { method, args });
  const owner = 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa';
  const recipient = 'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb';
  const config = { baseUrl: base, dbPrefix: `generated-${randomUUID()}`, mlsDbKey: 'bd'.repeat(32) };
  const initialize = async () => {
    await start();
    await call('catbird_mls_init', config);
    await call('catbird_mls_set_auth', owner, 'local-fixture-session');
    await call('setContentRootKey', Array(32).fill(91));
    await call('catbird_mls_setup');
  };
  await start();
  await assert.rejects(call('catbird_mls_init', { baseUrl: base, dbPrefix: config.dbPrefix }), /Protected database key/);
  assert.equal(enrollments, 0);
  await page.evaluate(() => packageWorker.terminate());
  await initialize();
  const input = { draftId: randomUUID(), recipientDid: recipient, text: 'Generated package protected draft', invitation: null };
  const command = (name, extra = {}) => call('catbird_mls_request_command', name, { ownerDid: owner, ...extra });
  await command('save_request_draft', { input, recipientLabel: 'Recipient' });
  await command('submit_request_draft', { draftId: input.draftId });
  assert.ok(preparations.length >= 1);
  const initialPrepareCount = preparations.length;
  const first = preparations[0];
  assert.equal(JSON.parse(first).signedRequest.body.authGeneration, 7);
  await assert.rejects(command('save_request_draft', { input: { ...input, text: 'Changed' }, recipientLabel: 'Recipient' }), /immutable/);
  await page.evaluate(() => packageWorker.terminate());
  await initialize();
  assert.equal(enrollments, 1, 'Worker restart must retain enrolled identity');
  const workspace = await command('get_request_workspace');
  assert.equal(workspace.drafts[0].input.text, input.text);
  await command('resume_request_draft', { draftId: input.draftId });
  assert.ok(preparations.length > initialPrepareCount);
  assert.ok(preparations.every(raw => raw === first), 'Exact signed bytes survive Worker termination and transport retries');
  const finalPrepareCount = preparations.length;
  await command('cancel_request_draft', { draftId: input.draftId });
  assert.ok(cancellations.length >= 1);
  const initialCancelCount = cancellations.length;
  await page.evaluate(() => packageWorker.terminate());
  await initialize();
  await command('resume_request_draft', { draftId: input.draftId });
  assert.ok(cancellations.length > initialCancelCount);
  assert.ok(cancellations.every(raw => raw === cancellations[0]));
  assert.equal(preparations.length, finalPrepareCount, 'Cancel replay cannot return to preparation');
  await assert.rejects(call('catbird_mls_request_command', 'get_request_workspace', { ownerDid: recipient }), /not ready for this account/);
  await call('catbird_mls_clear_auth');
  await assert.rejects(command('get_request_workspace'), /not ready for this account/);
  const wasm = await readFile(new URL('../pkg/catbird_mls_web_bg.wasm', import.meta.url));
  console.log(JSON.stringify({ result: 'PASS', kind: 'generated-package-local-http-fixture', wasmSha256: createHash('sha256').update(wasm).digest('hex'), assertions: ['missing protected key before enrollment', 'real enrollment generation', 'immutable attempted draft', 'Worker termination and OPFS reopen', 'exact preparation and cancellation replay', 'account fencing'] }, null, 2));
} finally {
  await browser.close();
  await new Promise(resolve => server.close(resolve));
}

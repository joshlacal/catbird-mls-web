// F60 test: catbird_mls_list_conversations must return durable conversations after worker/page reload.
// Before fix: returns [] because it reads only the in-memory runtime.conversations() HashMap.
// After fix: returns durable conversations via conversation_display_snapshot(&owner).
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { createECDH, createHash, randomUUID } from 'node:crypto';
import { chromium } from '../../catmos/node_modules/@playwright/test/index.mjs';

const pkgDir = process.env.PKG_DIR ? (process.env.PKG_DIR.startsWith('/') ? new URL(`file://${process.env.PKG_DIR}/`) : new URL(process.env.PKG_DIR, import.meta.url)) : new URL('../pkg/', import.meta.url);
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
const originalFetch = globalThis.fetch;
globalThis.fetch = async (input, options) => {
  const url = typeof input === 'string' ? input : input.url;
  if (url === 'https://chat.catbird.blue/.well-known/did.json') {
    const response = new Response(${JSON.stringify(JSON.stringify(document))}, { headers: { 'content-type': 'application/json' } });
    Object.defineProperty(response, 'url', { value: url });
    return response;
  }
  return originalFetch(input, options);
};
await init();
postMessage({ ready: true });
onmessage = async ({ data: { id, method, args } }) => {
  try {
    const value = await mls[method](...args);
    postMessage({ id, value });
  } catch (error) {
    postMessage({ id, error: String(error) });
  }
};
`;

let wasmHash = null;
const server = createServer(async (request, response) => {
  const url = new URL(request.url, 'http://local.invalid');
  if (url.pathname.startsWith('/pkg/')) {
    const name = url.pathname.slice(5);
    if (!['catbird_mls_web.js', 'catbird_mls_web_bg.wasm'].includes(name)) {
      response.writeHead(404).end();
      return;
    }
    const bytes = await readFile(new URL(name, pkgDir));
    if (name.endsWith('.wasm')) {
      wasmHash = createHash('sha256').update(bytes).digest('hex');
    }
    response.setHeader('content-type', name.endsWith('.wasm') ? 'application/wasm' : 'text/javascript');
    response.end(bytes);
    return;
  }
  if (url.pathname === '/worker.js') {
    response.setHeader('content-type', 'text/javascript');
    response.end(workerSource);
    return;
  }
  if (url.pathname.startsWith('/xrpc/')) {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString();
    const nsid = url.pathname.slice(6);
    response.setHeader('content-type', 'application/json');
    if (nsid.endsWith('.enrollDevice')) {
      const body = JSON.parse(raw).signedRequest.body;
      response.end(JSON.stringify({
        device: {
          deviceId: body.deviceId,
          keyId: body.keyId,
          signaturePublicKey: { $bytes: body.signaturePublicKey },
          authGeneration: 1,
          status: 'active',
          availablePackageCount: 1,
          reservedPackageCount: 0,
          createdAt: '2026-09-19T12:00:00.000Z',
          updatedAt: '2026-09-19T12:00:00.000Z',
        }
      }));
      return;
    }
    if (nsid.endsWith('.getConversations')) {
      response.end(JSON.stringify({
        items: [],
        hasMore: false,
        inventorySessionId: 's'.repeat(32),
        snapshotEventCursor: 'fixture-cursor',
        snapshotExpiresAt: '2099-01-01T00:00:00.000Z',
        inventoryScope: {
          supportedProtocolVersions: ['1', '2'],
          scopeDigest: Buffer.alloc(32, 7).toString('base64')
        }
      }));
      return;
    }
    if (nsid.endsWith('.getPendingWelcomes') || nsid.endsWith('.getLeafRecoveryInbox')) {
      response.end(JSON.stringify({
        items: [],
        hasMore: false,
        inventorySessionId: 's'.repeat(32),
        snapshotEventCursor: 'fixture-cursor',
        snapshotExpiresAt: '2099-01-01T00:00:00.000Z',
        inventoryScope: {
          supportedProtocolVersions: ['1', '2'],
          scopeDigest: Buffer.alloc(32, 7).toString('base64')
        }
      }));
      return;
    }
    if (nsid.endsWith('.createConversation')) {
      const cid = randomUUID();
      response.end(JSON.stringify({
        result: {
          $type: 'blue.catbird.chat.defs#conversationCreatedResult',
          coordinates: {
            conversationId: cid,
            epoch: 1
          }
        }
      }));
      return;
    }
    response.writeHead(503).end(JSON.stringify({ error: 'FixtureOffline' }));
    return;
  }
  response.setHeader('content-type', 'text/html');
  response.end('<title>F60 reload list_conversations test</title>');
});

await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}`;

const installWorkerApi = page => page.evaluate(() => {
  globalThis.spawn = async name => {
    const worker = new Worker('/worker.js', { type: 'module', name });
    await new Promise((resolve, reject) => {
      worker.onmessage = e => e.data.ready && resolve();
      worker.onerror = e => reject(new Error(e.message));
    });
    let seq = 0;
    const waiting = new Map();
    worker.onmessage = ({ data }) => {
      const p = waiting.get(data.id);
      if (!p) return;
      waiting.delete(data.id);
      data.error ? p.reject(new Error(data.error)) : p.resolve(data.value);
    };
    const call = (method, ...args) => new Promise((resolve, reject) => {
      const id = ++seq;
      waiting.set(id, { resolve, reject });
      worker.postMessage({ id, method, args });
    });
    (globalThis.workers ??= {})[name] = { worker, call };
  };
  globalThis.wcall = (name, method, ...args) => workers[name].call(method, ...args);
  globalThis.kill = name => {
    workers[name].worker.terminate();
    delete workers[name];
  };
});

const on = (page, name, method, ...args) => page.evaluate(({ name, method, args }) => wcall(name, method, ...args), { name, method, args });
const settle = (page, name, method, ...args) => on(page, name, method, ...args).then(value => ({ ok: true, value }), error => ({ ok: false, error: String(error.message) }));

const alice = 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa';
const bob = 'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb';
const carol = 'did:plc:cccccccccccccccccccccccc';
const aliceDb = { baseUrl: base, dbPrefix: `f60-${randomUUID()}`, mlsDbKey: 'ba'.repeat(32) };
const browser = await chromium.launch({ headless: true });
const context = await browser.newContext();
const page = await context.newPage();
page.setDefaultTimeout(60000);

try {
  await page.goto(base);
  await installWorkerApi(page);

  // 1. First worker session: create conversation and verify list_conversations includes it
  await page.evaluate(() => spawn('w1'));
  const init1 = await settle(page, 'w1', 'catbird_mls_init', aliceDb);
  assert.ok(init1.ok, `w1 init failed: ${init1.error}`);
  await on(page, 'w1', 'catbird_mls_set_auth', alice, 'session-1');
  await on(page, 'w1', 'setContentRootKey', Array(32).fill(91));
  await on(page, 'w1', 'catbird_mls_setup');

  const created = await on(page, 'w1', 'catbird_mls_create_conversation', 'F60 Test Group', [bob, carol]);
  console.log('Created group conversation in w1:', created.id, created.displayName);

  const convos1 = await on(page, 'w1', 'catbird_mls_list_conversations');
  console.log('w1 list_conversations count:', convos1.length);
  assert.equal(convos1.length, 1, 'w1 must list the newly created conversation');
  assert.equal(convos1[0].id, created.id);

  // 2. Kill worker w1 (simulates reload / tab close / fresh launch)
  console.log('Terminating w1...');
  await page.evaluate(() => kill('w1'));
  await new Promise(r => setTimeout(r, 500));

  // 3. Second worker session (reloaded worker on same database)
  console.log('Spawning w2 on same database...');
  let reopened;
  for (let attempt = 0; attempt < 40; attempt++) {
    await page.evaluate(() => spawn('w2'));
    reopened = await settle(page, 'w2', 'catbird_mls_init', aliceDb);
    if (reopened.ok) break;
    await page.evaluate(() => kill('w2'));
    await new Promise(r => setTimeout(r, 250));
  }
  assert.ok(reopened.ok, `w2 init failed: ${reopened.error}`);
  await on(page, 'w2', 'catbird_mls_set_auth', alice, 'session-2');
  await on(page, 'w2', 'setContentRootKey', Array(32).fill(91));
  await on(page, 'w2', 'catbird_mls_setup');

  // 4. CRITICAL ASSERTION: w2 must list the conversation from durable storage!
  // Before fix: returns [] (FAILS).
  // After fix: returns [created] (PASSES).
  const convos2 = await on(page, 'w2', 'catbird_mls_list_conversations');
  console.log('w2 list_conversations count:', convos2.length);
  assert.equal(convos2.length, 1, `F60 REGRESSION: list_conversations after reload must return durable conversations, got ${convos2.length}`);
  assert.equal(convos2[0].id, created.id);
  console.log('F60 PASS: list_conversations preserved conversation after reload!');
} finally {
  await browser.close().catch(() => {});
  server.close();
}

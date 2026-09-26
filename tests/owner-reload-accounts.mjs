// C30/C35/C36 browser evidence against the generated package in real Chromium
// DedicatedWorkers, real tabs and a real page reload. The local HTTP server is
// the transport boundary: every request is counted by path. Service authority
// is a local fixture, not delivery-service or deployment proof.
// Run: node tests/owner-reload-accounts.mjs   (PKG_DIR defaults to ../pkg)
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
async function claim([config, owner, input]){
 await mls.catbird_mls_init(config);
 mls.catbird_mls_set_auth(owner,'contender-session');
 mls.setContentRootKey(Array(32).fill(91));
 await mls.catbird_mls_setup();
 return mls.catbird_mls_request_command('save_request_draft',{ownerDid:owner,input,recipientLabel:'Contender'});
}
onmessage=async({data:{id,method,args}})=>{
 try{ postMessage({id,value: method==='claim' ? await claim(args) : await mls[method](...args)}); }
 catch(error){ postMessage({id,error:String(error)}); }
};`;

// ---- transport boundary ---------------------------------------------------
const traffic = [];
const preparations = [];
const held = [];
let holdPrepare = false;
let wasmServed = [];
const server = createServer(async (request, response) => {
  const url = new URL(request.url, 'http://local.invalid');
  if (url.pathname.startsWith('/pkg/')) {
    const name = url.pathname.slice(5);
    if (!['catbird_mls_web.js', 'catbird_mls_web_bg.wasm'].includes(name)) { response.writeHead(404).end(); return; }
    const bytes = await readFile(new URL(name, pkgDir));
    if (name.endsWith('.wasm')) wasmServed.push(createHash('sha256').update(bytes).digest('hex'));
    response.setHeader('content-type', name.endsWith('.wasm') ? 'application/wasm' : 'text/javascript');
    response.end(bytes); return;
  }
  if (url.pathname === '/worker.js') { response.setHeader('content-type', 'text/javascript'); response.end(workerSource); return; }
  if (url.pathname.startsWith('/xrpc/')) {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString();
    const nsid = url.pathname.slice(6);
    traffic.push(nsid);
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
    if (nsid.endsWith('.prepareDirectRequest')) {
      preparations.push(raw);
      if (holdPrepare) { held.push(response); return; } // in flight until the page dies
      response.destroy(); return;
    }
    response.writeHead(503).end(JSON.stringify({ error: 'FixtureOffline' })); return;
  }
  response.setHeader('content-type', 'text/html');
  response.end('<title>Browser owner/reload/account evidence</title>');
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}`;
const count = name => traffic.filter(n => n.endsWith(name)).length;
const remoteRequestTraffic = () => traffic.filter(n => /prepareDirectRequest|publishDirectRequest|cancelDirectRequest|createConversation|uploadBlob|sendMessage/.test(n)).length;

// ---- page/worker helpers --------------------------------------------------
const installWorkerApi = page => page.evaluate(() => {
  globalThis.spawn = async name => {
    const worker = new Worker('/worker.js', { type: 'module', name });
    await new Promise((resolve, reject) => { worker.onmessage = e => e.data.ready && resolve(); worker.onerror = e => reject(new Error(e.message)); });
    let seq = 0; const waiting = new Map();
    worker.onmessage = ({ data }) => { const p = waiting.get(data.id); if (!p) return; waiting.delete(data.id); data.error ? p.reject(new Error(data.error)) : p.resolve(data.value); };
    const call = (method, ...args) => new Promise((resolve, reject) => { const id = ++seq; waiting.set(id, { resolve, reject }); worker.postMessage({ id, method, args }); });
    (globalThis.workers ??= {})[name] = { worker, call };
  };
  globalThis.wcall = (name, method, ...args) => workers[name].call(method, ...args);
  globalThis.kill = name => { workers[name].worker.terminate(); delete workers[name]; };
});
const on = (page, name, method, ...args) => page.evaluate(({ name, method, args }) => wcall(name, method, ...args), { name, method, args });
const settle = (page, name, method, ...args) => on(page, name, method, ...args).then(value => ({ ok: true, value }), error => ({ ok: false, error: String(error.message) }));

const alice = 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa';
const bob = 'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb';
const peer = 'did:plc:cccccccccccccccccccccccc';
const secret = `C30 browser protected introduction ${randomUUID()}`;
const aliceDb = { baseUrl: base, dbPrefix: `owner-a-${randomUUID()}`, mlsDbKey: 'bd'.repeat(32) };
const bobDb = { baseUrl: base, dbPrefix: `owner-b-${randomUUID()}`, mlsDbKey: 'be'.repeat(32) };
const assertions = [];
const record = (clause, detail) => { assertions.push({ clause, detail }); };

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext();
const page = await context.newPage();
page.setDefaultTimeout(120000);
// A terminated/reloaded owner releases its Web Lock and SAH handles
// asynchronously; retry only the ownership error, boundedly.
const open = async (target, name, config, owner) => {
  for (let attempt = 0; ; attempt++) {
    await target.evaluate(n => spawn(n), name);
    const init = await settle(target, name, 'catbird_mls_init', config);
    if (init.ok) break;
    assert.ok(attempt < 40 && /owned by another Worker|OPFS|handle/i.test(init.error), init.error);
    await target.evaluate(n => kill(n), name);
    await new Promise(r => setTimeout(r, 250));
  }
  await on(target, name, 'catbird_mls_set_auth', owner, `${name}-session`);
  await on(target, name, 'setContentRootKey', Array(32).fill(91));
  await on(target, name, 'catbird_mls_setup');
};
try {
  await page.goto(base); await installWorkerApi(page);

  // ---- C36: two real DedicatedWorkers race one account's cold store --------
  await page.evaluate(() => Promise.all([spawn('w1'), spawn('w2')]));
  const inputs = [randomUUID(), randomUUID()].map(draftId => ({ draftId, recipientDid: peer, text: `contender ${draftId}`, invitation: null }));
  const race = await page.evaluate(async ({ config, owner, inputs }) => {
    // Barrier: both Workers are live before either receives its claim message.
    const results = await Promise.allSettled([wcall('w1', 'claim', config, owner, inputs[0]), wcall('w2', 'claim', config, owner, inputs[1])]);
    return results.map(r => r.status === 'fulfilled' ? { ok: true, value: r.value } : { ok: false, error: String(r.reason.message) });
  }, { config: aliceDb, owner: alice, inputs });
  const winners = race.map((r, i) => r.ok ? i : -1).filter(i => i >= 0);
  assert.equal(winners.length, 1, `exactly one Worker owns the store: ${JSON.stringify(race)}`);
  const winner = `w${winners[0] + 1}`, loser = winners[0] === 0 ? 'w2' : 'w1';
  assert.match(race[winners[0] ? 0 : 1].error, /OPFS|storage|Storage|handle|locked|busy/i);
  const afterRace = await on(page, winner, 'catbird_mls_request_command', 'get_request_workspace', { ownerDid: alice });
  assert.deepEqual(afterRace.drafts.map(d => d.input.draftId), [inputs[winners[0]].draftId], 'only the owner mutated protected state');
  // The loser keeps retrying against the live owner and still cannot mutate.
  const retry = await settle(page, loser, 'claim', aliceDb, alice, inputs[winners[0] ? 0 : 1]);
  assert.equal(retry.ok, false);
  record('C36 two DedicatedWorkers', { race, winner, loserRetry: retry.error, drafts: afterRace.drafts.length });

  // ---- C36: second tab contends for the owned store ------------------------
  const tab = await context.newPage();
  await tab.goto(base); await installWorkerApi(tab);
  await tab.evaluate(() => spawn('tab2'));
  const tabClaim = await settle(tab, 'tab2', 'claim', aliceDb, alice, { draftId: randomUUID(), recipientDid: peer, text: 'second tab', invitation: null });
  assert.equal(tabClaim.ok, false, 'second tab cannot open the owned store');
  const afterTab = await on(page, winner, 'catbird_mls_request_command', 'get_request_workspace', { ownerDid: alice });
  assert.equal(afterTab.drafts.length, 1);
  await tab.close();
  record('C36 second tab', { error: tabClaim.error, draftsAfter: afterTab.drafts.length });

  // ---- C35: exported direct-request entry points drive the durable provider --
  const input = { draftId: randomUUID(), recipientDid: peer, text: secret, invitation: null };
  const beforeStart = traffic.length;
  const started = await on(page, winner, 'catbird_mls_start_direct_request', input);
  assert.equal(started.type, 'outcomeUnknown', JSON.stringify(started));
  assert.ok(preparations.length >= 1, 'the exported start signed and sent a preparation');
  const signed = preparations[0];
  assert.ok(preparations.every(raw => raw === signed), 'transport retries resend exact bytes');
  const afterStart = preparations.length;
  assert.equal(JSON.parse(signed).signedRequest.body.authGeneration, 7);
  await page.evaluate(n => kill(n), winner);
  await page.evaluate(n => kill(n), loser);
  await open(page, 'w3', aliceDb, alice);
  assert.equal(count('.enrollDevice'), 1, 'restarted Worker reuses the durable enrolled identity');
  const resumed = await on(page, 'w3', 'catbird_mls_resume_direct_request', input.draftId);
  assert.equal(resumed.type, 'outcomeUnknown');
  assert.ok(preparations.length > afterStart, 'exported resume after restart re-sends');
  assert.ok(preparations.every(raw => raw === signed), 'exported resume replays exact durable signed bytes');
  await assert.rejects(on(page, 'w3', 'catbird_mls_start_direct_request', { ...input, text: 'changed' }));
  record('C35 exports -> durable provider', { startedType: started.type, restartReplayExact: true, enrollments: count('.enrollDevice'), trafficDuringStart: traffic.slice(beforeStart) });

  // ---- C36: real page reload while a preparation is in flight --------------
  holdPrepare = true;
  const inflight = page.evaluate(id => wcall('w3', 'catbird_mls_resume_direct_request', id).then(v => ({ settled: v }), e => ({ settled: String(e) })), input.draftId)
    .catch(error => ({ destroyedByReload: String(error.message) }));
  for (let i = 0; i < 600 && held.length === 0; i++) await new Promise(r => setTimeout(r, 50));
  assert.equal(held.length, 1, 'preparation is in flight at the server when the page reloads');
  const preparedBeforeReload = preparations.length;
  await page.reload();
  const inflightOutcome = await inflight;
  assert.ok(inflightOutcome.destroyedByReload, `operation was still in flight at reload: ${JSON.stringify(inflightOutcome)}`);
  holdPrepare = false;
  for (const response of held.splice(0)) response.destroy();
  assert.equal(preparations[preparedBeforeReload - 1], signed, 'in-flight bytes were the same durable preparation');
  await installWorkerApi(page);
  let reopened;
  for (let attempt = 0; attempt < 40; attempt++) {
    await page.evaluate(() => spawn('w4'));
    reopened = await settle(page, 'w4', 'catbird_mls_init', aliceDb);
    if (reopened.ok) break;
    await page.evaluate(() => kill('w4'));
    await new Promise(r => setTimeout(r, 250));
  }
  assert.equal(reopened.ok, true, `store reacquired after reload: ${reopened.error}`);
  await on(page, 'w4', 'catbird_mls_set_auth', alice, 'after-reload');
  await on(page, 'w4', 'setContentRootKey', Array(32).fill(91));
  await on(page, 'w4', 'catbird_mls_setup');
  const workspace = await on(page, 'w4', 'catbird_mls_request_command', 'get_request_workspace', { ownerDid: alice });
  assert.equal(workspace.drafts.length, 1, 'no draft/intent duplicated or lost by the reload');
  const replay = await on(page, 'w4', 'catbird_mls_resume_direct_request', input.draftId);
  assert.equal(replay.type, 'outcomeUnknown');
  assert.ok(preparations.every(raw => raw === signed), 'every preparation across restart and reload is byte-identical');
  assert.equal(count('.enrollDevice'), 1);
  record('C36 real reload mid-operation', { preparations: preparations.length, allIdentical: true, draftsAfterReload: workspace.drafts.length, reacquireAttempts: 'bounded retry until SAH handles release' });

  // ---- C30: account switch cannot expose or resume -------------------------
  const sameDb = await settle(page, 'w4', 'catbird_mls_set_auth', bob, 'bob-on-alice-db');
  assert.equal(sameDb.ok, false);
  assert.match(sameDb.error, /separate protected database/);
  await assert.rejects(on(page, 'w4', 'catbird_mls_request_command', 'get_request_workspace', { ownerDid: bob }), /not ready for this account/);
  await page.evaluate(() => kill('w4'));
  const beforeBob = remoteRequestTraffic();
  await open(page, 'w5', bobDb, bob);
  const bobWorkspace = await on(page, 'w5', 'catbird_mls_request_command', 'get_request_workspace', { ownerDid: bob });
  assert.equal(bobWorkspace.drafts.length, 0, 'switched account sees none of the previous account drafts');
  const crossResume = await settle(page, 'w5', 'catbird_mls_resume_direct_request', input.draftId);
  assert.equal(crossResume.ok, false, 'switched account cannot resume the previous account request');
  const crossCommand = await settle(page, 'w5', 'catbird_mls_request_command', 'resume_request_draft', { ownerDid: bob, draftId: input.draftId });
  assert.equal(crossCommand.ok, false);
  const crossOwner = await settle(page, 'w5', 'catbird_mls_request_command', 'get_request_workspace', { ownerDid: alice });
  assert.equal(crossOwner.ok, false);
  assert.equal(remoteRequestTraffic(), beforeBob, 'cross-account attempts emit zero request transport');
  record('C30 account switch', { sameDbRebind: sameDb.error, crossResume: crossResume.error, crossCommand: crossCommand.error, crossOwner: crossOwner.error, bobDrafts: 0 });

  // ---- C30: encrypted OPFS only --------------------------------------------
  await page.evaluate(() => kill('w5'));
  await page.evaluate(() => spawn('w6'));
  let wrongKey;
  for (let attempt = 0; attempt < 40; attempt++) {
    wrongKey = await settle(page, 'w6', 'catbird_mls_init', { ...aliceDb, mlsDbKey: 'cd'.repeat(32) });
    if (!/OPFS|handle|locked|busy|unavailable/i.test(wrongKey.error ?? '')) break;
    await page.evaluate(() => kill('w6')); await page.evaluate(() => spawn('w6'));
    await new Promise(r => setTimeout(r, 250));
  }
  assert.equal(wrongKey.ok, false, 'wrong protected key cannot open the account store');
  await page.evaluate(() => kill('w6'));
  const opfs = await page.evaluate(async needle => {
    const encoder = new TextEncoder(); const pattern = encoder.encode(needle);
    const files = []; let hits = 0, bytes = 0;
    const contains = buf => { outer: for (let i = 0; i + pattern.length <= buf.length; i++) { for (let j = 0; j < pattern.length; j++) if (buf[i + j] !== pattern[j]) continue outer; return true; } return false; };
    async function walk(dir, path) {
      for await (const [name, handle] of dir.entries()) {
        if (handle.kind === 'directory') { await walk(handle, `${path}${name}/`); continue; }
        let buf;
        for (let attempt = 0; attempt < 40; attempt++) { try { buf = new Uint8Array(await (await handle.getFile()).arrayBuffer()); break; } catch { await new Promise(r => setTimeout(r, 250)); } }
        if (!buf) throw new Error(`OPFS file unreadable: ${path}${name}`);
        files.push(`${path}${name}`); bytes += buf.length; if (contains(buf)) hits++;
      }
    }
    await walk(await navigator.storage.getDirectory(), '/');
    return { files: files.length, bytes, hits };
  }, secret);
  assert.ok(opfs.bytes > 0 && opfs.files > 0, 'OPFS scan read the persisted store');
  assert.equal(opfs.hits, 0, 'pending text never appears in OPFS bytes');
  record('C30 encrypted OPFS', { wrongKey: wrongKey.error, opfsFilesScanned: opfs.files, opfsBytesScanned: opfs.bytes, plaintextHits: 0 });

  // Record loaded wasm hash from the page (the HTTP response body evaluated inside Chromium)
  const pageWasmSha256 = await page.evaluate(async () => {
    const res = await fetch('/pkg/catbird_mls_web_bg.wasm');
    const buf = await res.arrayBuffer();
    const digest = await crypto.subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
  });
  const loaded = [...new Set(wasmServed)];
  assert.equal(loaded.length, 1, 'one wasm artifact served to every Worker');
  assert.equal(pageWasmSha256, loaded[0], 'page-fetched wasm response body sha256 matches server-served wasm');
  console.log(JSON.stringify({
    result: 'PASS', kind: 'generated-package-real-chromium-workers-tabs-reload-local-http-fixture',
    wasmSha256Loaded: loaded[0],
    pageResponseWasmSha256: pageWasmSha256,
    wasmLoads: wasmServed.length, pkgDir: pkgDir.pathname,
    transport: traffic.reduce((all, n) => ({ ...all, [n]: (all[n] ?? 0) + 1 }), {}),
    assertions,
  }, null, 2));
} finally {
  for (const response of held) response.destroy();
  await browser.close();
  await new Promise(resolve => server.close(resolve));
}

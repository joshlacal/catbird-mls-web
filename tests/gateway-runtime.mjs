// Real Catmos UI/Worker -> synthetic confidential session gateway -> shipping DS.
// No response interception or preseeded browser devices. Test-only Chromium trust
// pins one fixture SPKI after separate CA/expiry/SAN checks; it is not a claim
// that Chromium performed normal X.509 hostname validation under that flag.
import assert from 'node:assert/strict';
import { readFile, mkdir, stat, writeFile } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { spawn, execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { createServer as createTlsServer } from 'node:https';
import { fileURLToPath } from 'node:url';
import { chromium } from '../../catmos/node_modules/@playwright/test/index.mjs';
const manifestPath=process.argv[2];
assert(manifestPath,'Usage: node tests/gateway-runtime.mjs /absolute/gateway/manifest.json');
const manifest=JSON.parse(await readFile(manifestPath,'utf8'));
assert.equal(manifest.fixtureOnly,true);
const origin=new URL(manifest.corsOrigin);
assert.equal(origin.hostname,'127.0.0.1');assert.equal(origin.protocol,'http:');assert(origin.port);
assert.match(manifest.origin,/^https:\/\/gateway-[a-z0-9-]+\.request-fixture\.catbird\.blue$/);
const sessionsPath=join(dirname(manifestPath),'sessions.json');
assert.equal((await stat(sessionsPath)).mode&0o077,0,'Synthetic sessions must remain private');
const sessions=JSON.parse(await readFile(sessionsPath,'utf8')).accounts;
const certificate=manifest.tlsCertificatePem;
execFileSync('openssl',['verify','-CAfile',manifest.caPem,certificate],{stdio:'pipe'});
execFileSync('openssl',['x509','-in',certificate,'-noout','-checkend','60'],{stdio:'pipe'});
for(const hostname of Object.keys(manifest.hosts)) {
 const result=execFileSync('openssl',['x509','-in',certificate,'-noout','-checkhost',hostname],{encoding:'utf8'});
 assert.match(result,/does match certificate/);
}
const publicPem=execFileSync('openssl',['x509','-in',certificate,'-pubkey','-noout']);
const publicDer=execFileSync('openssl',['pkey','-pubin','-outform','DER'],{input:publicPem});
assert.equal(createHash('sha256').update(publicDer).digest('base64'),manifest.tlsSpkiSha256);
const out=join(dirname(manifestPath),`browser-${randomUUID()}`);await mkdir(out,{mode:0o700});
const mappings=Object.entries(manifest.hosts).map(([host,target])=>`MAP ${host} ${target}`).join(',');
const basicArgs=[`--host-resolver-rules=${mappings}`,'--no-proxy-server'];
function allowedRemote(url, websocket=false) {
 if(url.protocol!==(websocket?'wss:':'https:')||url.port||url.username||url.password||!Object.hasOwn(manifest.hosts,url.hostname))return false;
 if(websocket)return url.hostname==='chat.catbird.blue'&&url.pathname==='/xrpc/blue.catbird.chat.subscribeEvents';
 if(url.origin===manifest.origin)return url.pathname==='/auth/session'||/^\/xrpc\/(blue\.catbird\.chat\.[A-Za-z]+|app\.bsky\.(actor\.getProfiles?|graph\.getBlocks)|com\.atproto\.repo\.(listRecords|getRecord|createRecord|putRecord))$/.test(url.pathname);
 return url.pathname==='/.well-known/did.json'||/^\/xrpc\/com\.atproto\.repo\.(listRecords|getRecord)$/.test(url.pathname);
}
// A different leaf on the exact allowed hostname must still fail before HTTP.
const wrongKey=join(out,'negative-leaf.key'),wrongCert=join(out,'negative-leaf.pem');
execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',wrongKey,'-out',wrongCert,'-days','1','-subj',`/CN=${new URL(manifest.origin).hostname}`,'-addext',`subjectAltName=DNS:${new URL(manifest.origin).hostname}`],{stdio:'pipe'});
let wrongLeafHttp=0;
const wrongServer=createTlsServer({key:await readFile(wrongKey),cert:await readFile(wrongCert)},(_request,response)=>{wrongLeafHttp++;response.end('must not be reached');});
await new Promise(resolve=>wrongServer.listen(0,'127.0.0.1',resolve));
const wrongBrowser=await chromium.launch({headless:true,args:[`--host-resolver-rules=MAP ${new URL(manifest.origin).hostname} 127.0.0.1:${wrongServer.address().port}`,'--no-proxy-server',`--ignore-certificate-errors-spki-list=${manifest.tlsSpkiSha256}`]});
try{const page=await wrongBrowser.newPage();await assert.rejects(page.goto(manifest.origin),/CERT_AUTHORITY_INVALID|CERT_INVALID/);assert.equal(wrongLeafHttp,0);}
finally{await wrongBrowser.close();await new Promise(resolve=>wrongServer.close(resolve));}

const untrusted=await chromium.launch({headless:true,args:basicArgs});
try { const page=await untrusted.newPage();await assert.rejects(page.goto(manifest.origin),/CERT_AUTHORITY_INVALID|CERT_INVALID/); }
finally {await untrusted.close();}
const vite=spawn(process.execPath,['node_modules/vite/bin/vite.js','--host','127.0.0.1','--port',origin.port,'--strictPort','--mode','local-runtime-fixture'],{
 cwd:fileURLToPath(new URL('../../catmos/',import.meta.url)),
 env:{...process.env,VITE_LOCAL_REQUEST_FIXTURE_ORIGIN:manifest.origin},stdio:['ignore','pipe','pipe'],
});
let viteLog='';vite.stdout.on('data',b=>{viteLog+=b});vite.stderr.on('data',b=>{viteLog+=b});
const browser=await chromium.launch({headless:true,args:[...basicArgs,`--ignore-certificate-errors-spki-list=${manifest.tlsSpkiSha256}`]});
const trace=[],blocked=[];let cid;
try {
 for(let retry=0;;retry++){
  try{const response=await fetch(manifest.corsOrigin);if(response.ok)break;}catch{}
  assert(retry<150,'Fixture UI did not start');await new Promise(resolve=>setTimeout(resolve,200));
 }
 async function client(label) {
  const actor=sessions.find(a=>a.label===label);assert(actor);
  const context=await browser.newContext({viewport:{width:1360,height:980},serviceWorkers:'block'});
  await context.route('**/*',route=>{
   const url=new URL(route.request().url());
   if(url.origin===manifest.corsOrigin||allowedRemote(url))return route.continue();
   blocked.push(url.hostname);return route.abort('blockedbyclient');
  });
  await context.routeWebSocket('**/*',socket=>{
   const url=new URL(socket.url());
   if((url.protocol==='ws:'&&url.host===origin.host)||allowedRemote(url,true))return socket.connectToServer();
   blocked.push(url.hostname);socket.close({code:1008,reason:'Unlisted fixture host'});
  });
  const page=await context.newPage();page.setDefaultTimeout(120000);
  page.on('response',response=>{const url=new URL(response.url());if(url.pathname.startsWith('/xrpc/'))trace.push({actor:label,path:url.pathname,status:response.status()});});
  await page.goto(manifest.corsOrigin);
  await page.evaluate(async()=>{
   const {auth}=await import('/src/lib/stores/auth.ts');
   let ready=false;const unsubscribe=auth.subscribe(value=>{ready=!value.loading});
   while(!ready)await new Promise(resolve=>setTimeout(resolve,20));unsubscribe();
  });
  await page.evaluate(async actor=>{
   const api=await import('/src/lib/wasm.ts');const {auth}=await import('/src/lib/stores/auth.ts');
   const user=await api.completeLogin(actor.session);if(user.did!==actor.did)throw new Error('Account mismatch');
   auth.setUser(user);globalThis.fixtureActor=user;
  },actor);
  await page.evaluate(async()=>{
   const {requests}=await import('/src/lib/stores/requests.ts');
   requests.bindAccount(fixtureActor.did,fixtureActor.authRevision);
   await requests.setDeliveryEnabled(true);await requests.load();requests.showInbox();
  });
  return{actor,page,context};
 }
 const bob=await client('bob');const alice=await client('alice');
 const introduction=`An encrypted introduction from the real browser Worker. ${randomUUID()}`;
 await alice.page.evaluate(async({recipient,text})=>{const {requests}=await import('/src/lib/stores/requests.ts');requests.begin(recipient,'Bob fixture',text);},{recipient:bob.actor.did,text:introduction});
 await alice.page.screenshot({path:join(out,'alice-compose.png')});
 await alice.page.getByRole('button',{name:'Send introduction',exact:true}).click();
 await alice.page.getByRole('heading',{name:'Request sent',exact:true}).waitFor();
 const sent=await alice.page.evaluate(async()=>{const api=await import('/src/lib/wasm.ts');return api.getRequestWorkspace(fixtureActor.did,fixtureActor.authRevision);});
 const outcome=sent.drafts.find(d=>d.input.text===introduction)?.outcome;assert.equal(outcome?.type,'requestSent');cid=outcome.conversationId;
 await bob.page.evaluate(async cid=>{const {requests}=await import('/src/lib/stores/requests.ts');await requests.load();requests.selectRequest(cid);},cid);
 await bob.page.getByLabel('Decrypted introduction').getByText(introduction,{exact:true}).waitFor();
 await bob.page.screenshot({path:join(out,'bob-encrypted-introduction.png')});
 const pending=await bob.page.evaluate(async cid=>{const api=await import('/src/lib/wasm.ts');return api.refreshDirectRequest(fixtureActor.did,cid,fixtureActor.authRevision);},cid);
 assert.equal(pending.consent,'incomingPending');assert.equal(pending.preview?.text,introduction);assert.equal(pending.capabilities.canSend,false);assert.equal(pending.capabilities.canEmitReceipts,false);
 await bob.page.getByRole('button',{name:'Accept conversation',exact:true}).click();
 await bob.page.getByRole('button',{name:'Open conversation',exact:true}).waitFor();
 const reply='Accepted reply encrypted by the browser shared orchestrator.';
 await bob.page.evaluate(async({cid,text})=>{const api=await import('/src/lib/wasm.ts');await api.sendMessage(cid,text,fixtureActor.did,fixtureActor.authRevision);},{cid,text:reply});
 const received=await alice.page.evaluate(async cid=>{const api=await import('/src/lib/wasm.ts');await api.refreshDirectRequest(fixtureActor.did,cid,fixtureActor.authRevision);return api.fetchNewMessages(cid,fixtureActor.did,fixtureActor.authRevision);},cid);
 assert(received.some(message=>message.content===reply),'Sender decrypts real accepted reply');
 await bob.page.screenshot({path:join(out,'bob-accepted-request.png')});
 // An unknown hostname is refused by this runner before any gateway effect.
 const denied=await bob.context.newPage();await assert.rejects(denied.goto('https://unlisted.request-fixture.catbird.blue/'),/BLOCKED_BY_CLIENT|FAILED/);assert(blocked.includes('unlisted.request-fixture.catbird.blue'));
 const report={result:'PASS',kind:'actual-Catmos-Worker-shipping-DS-with-synthetic-session-and-fixture-SPKI-trust',conversationId:cid,negativeTrust:['untrusted fixture CA refused by default browser','different leaf refused before HTTP with fixture SPKI configured','unlisted hostname blocked before network'],sourceTrust:'Production fixed receipt URL retained; dedicated Chromium fixture SPKI plus exact network allowlist; separate OpenSSL CA/expiry/SAN preflight.',screenshots:['alice-compose.png','bob-encrypted-introduction.png','bob-accepted-request.png'],trace};
 await writeFile(join(out,'report.json'),JSON.stringify(report,null,2),{mode:0o600});
 console.log(JSON.stringify({result:'PASS',evidence:out,conversationId:cid}));
}catch(error){await writeFile(join(out,'failure.json'),JSON.stringify({error:String(error),conversationId:cid,trace,blocked},null,2),{mode:0o600});throw error;}
finally{await browser.close();vite.kill('SIGTERM');await writeFile(join(out,'vite.log'),viteLog,{mode:0o600});}

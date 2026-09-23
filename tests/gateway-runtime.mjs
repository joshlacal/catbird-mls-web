// Real Catmos UI/Worker -> synthetic confidential session gateway -> shipping DS.
// No response interception or preseeded browser devices. Test-only Chromium trust
// pins one fixture SPKI after separate CA/expiry/SAN checks; it is not a claim
// that Chromium performed normal X.509 hostname validation under that flag.
import assert from 'node:assert/strict';
import { readFile, mkdir, stat, writeFile } from 'node:fs/promises';
import { createHash, randomUUID, X509Certificate } from 'node:crypto';
import { connect as connectTls } from 'node:tls';
import { spawn, execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { createServer as createTlsServer } from 'node:https';
import { fileURLToPath } from 'node:url';
import { chromium } from '../../catmos/node_modules/@playwright/test/index.mjs';
const manifestPath=process.argv[2];
assert(manifestPath,'Usage: node tests/gateway-runtime.mjs /absolute/gateway/manifest.json');
async function boundedFile(path,max=65536) { const info=await stat(path);assert(info.isFile()&&info.size<=max,'Fixture file bound');return readFile(path); }
const manifest=JSON.parse(await boundedFile(manifestPath));
assert.equal(manifest.fixtureOnly,true);
const origin=new URL(manifest.corsOrigin);
assert.equal(origin.hostname,'127.0.0.1');assert.equal(origin.protocol,'http:');assert(origin.port&&Number(origin.port)>0&&Number(origin.port)<=65535);
assert.equal(origin.origin,manifest.corsOrigin);assert.equal(origin.pathname,'/');assert(!origin.username&&!origin.password&&!origin.hash&&!origin.search);
assert.match(manifest.origin,/^https:\/\/gateway-[a-z0-9-]+\.request-fixture\.catbird\.blue$/);
const gatewayHost=new URL(manifest.origin).hostname;
assert(Array.isArray(manifest.accounts)&&manifest.accounts.length===2);
const labels=new Set(),dids=new Set();
for(const account of manifest.accounts){
 assert(['alice','bob'].includes(account.label)&&!labels.has(account.label));labels.add(account.label);
 assert.match(account.did,new RegExp(`^did:web:${account.label}-[a-z0-9-]+\\.request-fixture\\.catbird\\.blue$`));
 assert(!dids.has(account.did));dids.add(account.did);
 assert.match(account.deviceId,/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
}
const browserHosts=new Set([gatewayHost,'chat.catbird.blue',...manifest.accounts.map(a=>a.did.slice('did:web:'.length))]);
const expectedHosts=new Set([...browserHosts,'public.api.bsky.app']);
assert.deepEqual(new Set(Object.keys(manifest.hosts)),expectedHosts,'Only known synthetic actors/gateway and fixed service fixtures are admitted');
for(const [host,target] of Object.entries(manifest.hosts)){
 assert.match(host,/^[a-z0-9.-]+$/);assert.match(target,/^127\.0\.0\.1:[1-9][0-9]{0,4}$/);
 assert(Number(target.split(':')[1])<=65535,'Fixture target must be a loopback TCP port');
}
const sessionsPath=join(dirname(manifestPath),'sessions.json');
assert.equal((await stat(sessionsPath)).mode&0o077,0,'Synthetic sessions must remain private');
const sessions=JSON.parse(await boundedFile(sessionsPath)).accounts;
assert(Array.isArray(sessions)&&sessions.length===2);
const sessionTokens=new Set();
for(const actor of sessions){const declared=manifest.accounts.find(a=>a.label===actor.label);assert(declared);assert.equal(actor.did,declared.did);assert.equal(actor.deviceId,declared.deviceId);assert.match(actor.session,/^[A-Za-z0-9_-]{32,4096}$/);assert(!sessionTokens.has(actor.session));sessionTokens.add(actor.session);}
assert.equal(new Set(sessions.map(a=>a.label)).size,2);
const certificate=manifest.tlsCertificatePem;
for(const path of [certificate,manifest.caPem])assert.equal(dirname(path),dirname(manifestPath),'Certificate files belong to this fixture directory');
const certificateBytes=await boundedFile(certificate),caBytes=await boundedFile(manifest.caPem);
const x509=new X509Certificate(certificateBytes);
execFileSync('openssl',['verify','-CAfile',manifest.caPem,certificate],{stdio:'pipe'});
execFileSync('openssl',['x509','-in',certificate,'-noout','-checkend','60'],{stdio:'pipe'});
assert(x509.subjectAltName,'Fixture certificate must explicitly contain SANs');
for(const hostname of browserHosts)assert(x509.checkHost(hostname,{subject:'never',partialWildcards:false,multiLabelWildcards:false}),'SAN-only fixture hostname check');
const publicDer=x509.publicKey.export({type:'spki',format:'der'});
assert.equal(createHash('sha256').update(publicDer).digest('base64'),manifest.tlsSpkiSha256);
// Bind the certificate file to each live listener with normal Node TLS checks.
for(const hostname of browserHosts)await new Promise((resolve,reject)=>{
 const port=Number(manifest.hosts[hostname].split(':')[1]);
 const socket=connectTls({host:'127.0.0.1',port,servername:hostname,ca:caBytes,rejectUnauthorized:true},()=>{
  try{assert(socket.authorized);assert.deepEqual(socket.getPeerCertificate().raw,x509.raw);socket.end();resolve();}catch(error){socket.destroy();reject(error);}
 });socket.once('error',reject);socket.setTimeout(5000,()=>{socket.destroy();reject(new Error('Fixture TLS preflight timeout'));});
});
const out=join(dirname(manifestPath),`browser-${randomUUID()}`);await mkdir(out,{mode:0o700});
const mappings=[...browserHosts].map(host=>`MAP ${host} ${manifest.hosts[host]}`).join(',');
const basicArgs=[`--host-resolver-rules=${mappings}`,'--no-proxy-server'];
const rpcMethods=new Map();
for(const name of ['getOwnDevices','getDevices','getDeviceKey','getConversations','getPendingWelcomes','getLeafRecoveryInbox','getConversationState','getEntries','getDirectRequestOutcome'])rpcMethods.set(`/xrpc/blue.catbird.chat.${name}`,'GET');
for(const name of ['enrollDevice','publishDirectRequestKeys','replenishKeyPackages','prepareDirectRequest','publishDirectRequest','cancelDirectRequestPreparation','acknowledgeWelcome','rejectWelcome','acceptConversation','sendMessage','createConversation','submitTransition','closeConversation','requestLeave','getSubscriptionTicket'])rpcMethods.set(`/xrpc/blue.catbird.chat.${name}`,'POST');
for(const path of ['/auth/session','/xrpc/app.bsky.actor.getProfile','/xrpc/app.bsky.actor.getProfiles','/xrpc/app.bsky.graph.getBlocks','/xrpc/com.atproto.repo.listRecords','/xrpc/com.atproto.repo.getRecord'])rpcMethods.set(path,'GET');
function allowedRemote(url,method='GET',websocket=false) {
 if(url.protocol!==(websocket?'wss:':'https:')||url.port||url.username||url.password||url.hash||!browserHosts.has(url.hostname))return false;
 if(websocket)return url.hostname==='chat.catbird.blue'&&url.pathname==='/xrpc/blue.catbird.chat.subscribeEvents';
 if(url.origin===manifest.origin){const expected=rpcMethods.get(url.pathname);return expected!==undefined&&(method===expected||method==='OPTIONS');}
 return method==='GET'&&(url.pathname==='/.well-known/did.json'||/^\/xrpc\/com\.atproto\.repo\.(listRecords|getRecord)$/.test(url.pathname));
}
function allowedLocal(url,method){return url.origin===manifest.corsOrigin&&['GET','HEAD'].includes(method)&&(url.pathname==='/'||/^\/(src|node_modules|@vite|@id|@fs|\.svelte-kit|_app)\//.test(url.pathname)||/^\/(favicon|logo|catmos)[^/]*\.(svg|png|ico)$/.test(url.pathname));}
// A certificate using a different untrusted SPKI must fail before HTTP.
const wrongKey=join(out,'negative-leaf.key'),wrongCert=join(out,'negative-leaf.pem');
// X.509 CN is bounded at 64 bytes; the synthetic gateway hostname exceeds it. The
// exact hostname still travels in the SAN, so this certificate fails on the pinned
// SPKI (the property under test), not on a name mismatch.
execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',wrongKey,'-out',wrongCert,'-days','1','-subj','/CN=negative-leaf.request-fixture.catbird.blue','-addext',`subjectAltName=DNS:${new URL(manifest.origin).hostname}`],{stdio:'pipe'});
let wrongLeafHttp=0;
const wrongServer=createTlsServer({key:await readFile(wrongKey),cert:await readFile(wrongCert)},(_request,response)=>{wrongLeafHttp++;response.end('must not be reached');});
await new Promise(resolve=>wrongServer.listen(0,'127.0.0.1',resolve));
let wrongBrowser;
try{wrongBrowser=await chromium.launch({headless:true,args:[`--host-resolver-rules=MAP ${new URL(manifest.origin).hostname} 127.0.0.1:${wrongServer.address().port}`,'--no-proxy-server',`--ignore-certificate-errors-spki-list=${manifest.tlsSpkiSha256}`]});
const page=await wrongBrowser.newPage();await assert.rejects(page.goto(manifest.origin),/CERT_AUTHORITY_INVALID|CERT_INVALID/);assert.equal(wrongLeafHttp,0);}
finally{await wrongBrowser?.close();await new Promise(resolve=>wrongServer.close(resolve));}

const untrusted=await chromium.launch({headless:true,args:basicArgs});
try { const page=await untrusted.newPage();await assert.rejects(page.goto(manifest.origin),/CERT_AUTHORITY_INVALID|CERT_INVALID/); }
finally {await untrusted.close();}
const runId=randomUUID();
const sourceFiles={wasmAdapter:new URL('../../catmos/src/lib/wasm.ts',import.meta.url),workerAdapter:new URL('../../catmos/src/lib/mls-worker.ts',import.meta.url),authStore:new URL('../../catmos/src/lib/stores/auth.ts',import.meta.url),requestStore:new URL('../../catmos/src/lib/stores/requests.ts',import.meta.url),page:new URL('../../catmos/src/routes/+page.svelte',import.meta.url),wasm:new URL('../pkg/catbird_mls_web_bg.wasm',import.meta.url)};
async function sourceHashes(){return Object.fromEntries(await Promise.all(Object.entries(sourceFiles).map(async([name,path])=>[name,createHash('sha256').update(await readFile(path)).digest('hex')])));}
const sourceIdentity=await sourceHashes();
const vite=spawn(process.execPath,['node_modules/vite/bin/vite.js','--host','127.0.0.1','--port',origin.port,'--strictPort','--mode','local-runtime-fixture'],{
 cwd:fileURLToPath(new URL('../../catmos/',import.meta.url)),
 env:{...process.env,VITE_LOCAL_REQUEST_FIXTURE_ORIGIN:manifest.origin,VITE_LOCAL_REQUEST_FIXTURE_RUN_ID:runId},stdio:['ignore','pipe','pipe'],
});
let viteLog='';vite.stdout.on('data',b=>{viteLog+=b});vite.stderr.on('data',b=>{viteLog+=b});
let browser;
const trace=[],requests=[],blocked=[];let cid;
try {
 const exercise=async()=>{
 browser=await chromium.launch({headless:true,args:[...basicArgs,`--ignore-certificate-errors-spki-list=${manifest.tlsSpkiSha256}`]});
 for(let retry=0;;retry++){
  assert.equal(vite.exitCode,null,'The spawned fixture Vite must remain alive');
  if(/ready in/.test(viteLog)){try{const response=await fetch(manifest.corsOrigin);if(response.ok)break;}catch{}}
  assert(retry<150,'Fixture UI did not start');await new Promise(resolve=>setTimeout(resolve,200));
 }
 async function client(label) {
  const actor=sessions.find(a=>a.label===label);assert(actor);
  const context=await browser.newContext({viewport:{width:1360,height:980},serviceWorkers:'block'});
  await context.route('**/*',route=>{
   const url=new URL(route.request().url());
   if(allowedLocal(url,route.request().method())||allowedRemote(url,route.request().method()))return route.continue();
   blocked.push(url.hostname);return route.abort('blockedbyclient');
  });
  await context.routeWebSocket('**/*',socket=>{
   const url=new URL(socket.url());
   if((url.protocol==='ws:'&&url.host===origin.host&&url.pathname==='/')||allowedRemote(url,'GET',true))return socket.connectToServer();
   blocked.push(url.hostname);socket.close({code:1008,reason:'Unlisted fixture host'});
  });
  const page=await context.newPage();page.setDefaultTimeout(120000);
  page.on('request',request=>{const url=new URL(request.url());if(url.pathname.startsWith('/xrpc/'))requests.push({actor:label,path:url.pathname,method:request.method()});});
  page.on('response',response=>{const url=new URL(response.url());if(url.pathname.startsWith('/xrpc/'))trace.push({actor:label,path:url.pathname,status:response.status()});});
  await page.goto(manifest.corsOrigin);
  const marker=await page.evaluate(async()=>{const api=await import('/src/lib/wasm.ts');return api.localRuntimeFixtureBuild;});
  assert.deepEqual(marker,{runId,origin:manifest.origin},'Only this spawned fixture build may receive credentials');
  await page.evaluate(async()=>{
   const {auth}=await import('/src/lib/stores/auth.ts');
   let ready=false;const unsubscribe=auth.subscribe(value=>{ready=!value.loading});
   const deadline=Date.now()+15000;
   while(!ready){if(Date.now()>deadline){unsubscribe();throw new Error('Initial auth readiness timed out');}await new Promise(resolve=>setTimeout(resolve,20));}unsubscribe();
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
 const sendsBefore=requests.filter(row=>row.path.endsWith('.sendMessage')).length;
 const blockedPending=await bob.page.evaluate(async cid=>{const api=await import('/src/lib/wasm.ts');try{await api.sendMessage(cid,'Must not send before acceptance',fixtureActor.did,fixtureActor.authRevision);return null;}catch(error){return String(error);}},cid);
 assert(blockedPending,'Pending recipient cannot send');assert.equal(requests.filter(row=>row.path.endsWith('.sendMessage')).length,sendsBefore,'Pending refusal emits no sendMessage request');
 await bob.page.getByRole('button',{name:'Accept conversation',exact:true}).click();
 await bob.page.getByRole('button',{name:'Open conversation',exact:true}).waitFor();
 const reply='Accepted reply encrypted by the browser shared orchestrator.';
 await bob.page.evaluate(async({cid,text})=>{const api=await import('/src/lib/wasm.ts');await api.sendMessage(cid,text,fixtureActor.did,fixtureActor.authRevision);},{cid,text:reply});
 const received=await alice.page.evaluate(async cid=>{const api=await import('/src/lib/wasm.ts');await api.refreshDirectRequest(fixtureActor.did,cid,fixtureActor.authRevision);return api.fetchNewMessages(cid,fixtureActor.did,fixtureActor.authRevision);},cid);
 assert(received.some(message=>message.content===reply),'Sender decrypts real accepted reply');
 await bob.page.screenshot({path:join(out,'bob-accepted-request.png')});
 const group=await alice.page.evaluate(async recipient=>{const api=await import('/src/lib/wasm.ts');return api.createGroup('Separate invitation fixture',[recipient],undefined,fixtureActor.did,fixtureActor.authRevision);},bob.actor.did);
 const invitation=await alice.page.evaluate(async({groupId,recipient})=>{const api=await import('/src/lib/wasm.ts');return api.getGroupInvitationReference(fixtureActor.did,groupId,recipient,fixtureActor.authRevision);},{groupId:group.id,recipient:bob.actor.did});
 assert(invitation,'Pending group invitation has authenticated reference');
 const note='A separate invitation note after direct acceptance.';
 const noteDraft=await alice.page.evaluate(async({recipient,note,invitation})=>{const api=await import('/src/lib/wasm.ts');const draftId=crypto.randomUUID();await api.saveRequestDraft(fixtureActor.did,{draftId,recipientDid:recipient,text:note,invitation},'Bob fixture',fixtureActor.authRevision);return api.submitRequestDraft(fixtureActor.did,draftId,fixtureActor.authRevision);},{recipient:bob.actor.did,note,invitation});
 assert.equal(noteDraft.outcome?.type,'existingDirect');assert.equal(noteDraft.noteDelivery??null,null,'Creating the invitation draft does not auto-send');
 const noteSent=await alice.page.evaluate(async id=>{const api=await import('/src/lib/wasm.ts');return api.sendExistingInvitationNote(fixtureActor.did,id,fixtureActor.authRevision);},noteDraft.input.draftId);
 assert(noteSent.noteDelivery?.messageId,'Explicit note has one confirmed message identity');
 const noteMessages=await bob.page.evaluate(async cid=>{const api=await import('/src/lib/wasm.ts');return api.fetchNewMessages(cid,fixtureActor.did,fixtureActor.authRevision);},cid);
 assert(noteMessages.some(message=>message.content===note&&message.groupInvitation?.conversationId===group.id),'Receiver verifies and renders invitation metadata on ordinary MLS message');
 const stillPending=await alice.page.evaluate(async({groupId,recipient})=>{const api=await import('/src/lib/wasm.ts');return api.getGroupInvitationReference(fixtureActor.did,groupId,recipient,fixtureActor.authRevision);},{groupId:group.id,recipient:bob.actor.did});
 assert(stillPending,'Direct acceptance and note delivery do not accept group invitation');

 // An unknown hostname is refused by this runner before any gateway effect.
 const denied=await bob.context.newPage();await assert.rejects(denied.goto('https://unlisted.request-fixture.catbird.blue/'),/BLOCKED_BY_CLIENT|FAILED/);assert(blocked.includes('unlisted.request-fixture.catbird.blue'));
 assert.deepEqual(await sourceHashes(),sourceIdentity,'Runtime inputs changed during qualification');
 const report={sourceIdentity,result:'PASS',kind:'actual-Catmos-Worker-shipping-DS-with-synthetic-session-and-fixture-SPKI-trust',conversationId:cid,negativeTrust:['untrusted fixture CA refused by default browser','different untrusted SPKI refused before HTTP with fixture SPKI configured','unlisted hostname blocked before network'],runId,sourceTrust:'Production fixed receipt URL retained; dedicated Chromium fixture public-key SPKI pin plus explicit remote endpoint/method and local asset allowlists. Separate CA/time/SAN and live peer-certificate preflight. Chromium ordinary hostname verification is not claimed.',screenshots:['alice-compose.png','bob-encrypted-introduction.png','bob-accepted-request.png'],requests,trace};
 return report;
 };
 let timer,report;try{report=await Promise.race([exercise(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Browser runtime window exceeded twelve minutes')),720000);})]);}finally{clearTimeout(timer);}
 await writeFile(join(out,'report.json'),JSON.stringify(report,null,2),{mode:0o600});
 console.log(JSON.stringify({result:'PASS',evidence:out,conversationId:cid}));
}catch(error){await writeFile(join(out,'failure.json'),JSON.stringify({error:String(error),conversationId:cid,requests,trace,blocked},null,2),{mode:0o600});throw error;}
finally{await browser?.close();vite.kill('SIGTERM');await writeFile(join(out,'vite.log'),viteLog,{mode:0o600});}

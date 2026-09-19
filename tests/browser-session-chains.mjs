// Exact shipping main-thread functions, with real Comlink first-stage delivery.
// Synthetic HTTP/Worker responses isolate session continuation authorization.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import ts from '../../catmos/node_modules/typescript/lib/typescript.js';
import { chromium } from '../../catmos/node_modules/@playwright/test/index.mjs';
const source = await readFile(new URL('../../catmos/src/lib/wasm.ts', import.meta.url), 'utf8');
const ast = ts.createSourceFile('wasm.ts', source, ts.ScriptTarget.Latest, true);
const names = ['effectOwner','browserEffect','invalidateBrowserSession','checkBrowserRevision','discardBrowserSession','createGroup','resetGroup','blockRequestSender','requestInvoke','createBlock','submitPreparedRequest','completeLogin'];
const ownerFunctions = ast.statements.filter(n => ts.isFunctionDeclaration(n) && n.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword) && n.parameters.some(p => p.name.getText(ast) === 'ownerRevision'));
const ownerCalls = ownerFunctions.map(n => ({name:n.name.text,args:n.parameters.map(p => p.name.getText(ast) === 'ownerDid' ? 'alice' : p.name.getText(ast) === 'ownerRevision' ? 'browser:0' : null)}));
const functions = [...new Set([...names,...ownerFunctions.map(n=>n.name.text)])].map(name => {
  const node = ast.statements.find(n => ts.isFunctionDeclaration(n) && n.name?.text === name);
  assert(node, name); return node.getText(ast).replace(/^export /,'');
}).join('\n');
const script = ts.transpileModule(`let _worker, _rawWorker, workerAccount; let browserSessionRevision=0, _replenishInterval=null;
const isTauri=false, NEST_URL='http://fixture.invalid';
let cleared=0; const clearBrowserAuth=()=>{cleared++}; const getWorker=()=>_worker;
const readBrowserAuth=()=>({did:workerAccount,sessionId:'synthetic'});
${functions}
globalThis.effects={${[...new Set([...names,...ownerFunctions.map(n=>n.name.text)])].join(',')}};
globalThis.bindTestSession=(worker,owner)=>{invalidateBrowserSession();_worker=worker;workerAccount=owner;};
globalThis.getClearCount=()=>cleared;`, {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText;
const workerSource = await readFile(new URL('../../catmos/src/lib/mls-worker.ts', import.meta.url), 'utf8');
const workerAst = ts.createSourceFile('mls-worker.ts', workerSource, ts.ScriptTarget.Latest, true);
const workerFunctions = ['captureWorkerSession','closeSubscriptions','canonicalConversationId'].map(name => workerAst.statements.find(n=>ts.isFunctionDeclaration(n)&&n.name?.text===name).getText(workerAst)).join('\n');
const apiNode = workerAst.statements.find(n=>ts.isVariableStatement(n)&&n.declarationList.declarations.some(d=>d.name.getText(workerAst)==='api')).getText(workerAst);
const workerScript = ts.transpileModule(`globalThis.installWorkerProbe=()=>{
 let workerSessionRevision=0, releaseReady, releaseSetup; const calls=[];
 const wasmReady=new Promise(resolve=>{releaseReady=resolve});
 const setupGate=new Promise(resolve=>{releaseSetup=resolve});
 const wasm=new Proxy({}, {get(_target,name){return(...args)=>{calls.push(name);return name==='catbird_mls_setup'?setupGate:name==='catbird_mls_resolve_conversation_id'?'cid':undefined;}}});
 const browserAbi=wasm, plain=value=>value, subscriptions=new Map(), subscriptionAliases=new Map();
 ${workerFunctions}
 ${apiNode}
 return {api,calls,releaseReady,releaseSetup};
};`,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText;
const comlink = await readFile(new URL('../../catmos/node_modules/comlink/dist/esm/comlink.mjs', import.meta.url));
const server=createServer((request,response)=>{response.setHeader('content-type',request.url==='/comlink.js'?'text/javascript':'text/html');response.end(request.url==='/comlink.js'?comlink:'<title>Session continuation tests</title>');});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const browser=await chromium.launch({headless:true});
try {
 const page=await browser.newPage(); await page.goto(`http://127.0.0.1:${server.address().port}`); await page.addScriptTag({content:script}); await page.addScriptTag({content:workerScript});
 const result=await page.evaluate(async ownerCalls=>{
  const {expose,wrap}=await import('/comlink.js');
  const outcomes=[];
  for(const name of ['createGroup','resetGroup','blockRequestSender']) {
   let release,arrived,secondEffects=0,httpEffects=0;
   const gate=new Promise(resolve=>{release=resolve});const started=new Promise(resolve=>{arrived=resolve});
   const first=async()=>{arrived();await gate;return name==='blockRequestSender'?'did:plc:sender':{path:'/xrpc/fixture',method:'POST',body:'{}'}};
   const channel=new MessageChannel();
   expose({replenishKeyPackages:first,prepareSignedRequest:first,requestCommand:first,createConversation(){secondEffects++;return{};}},channel.port1);
   const worker=wrap(channel.port2);bindTestSession(worker,'alice');
   globalThis.fetch=async()=>{httpEffects++;return new Response('{}');};
   const operation=name==='createGroup'?effects.createGroup('group',[],undefined,'alice'):name==='resetGroup'?effects.resetGroup('cid',undefined,'alice'):effects.blockRequestSender('alice','cid');
   const settled=operation.then(()=>({success:true}),error=>({error:String(error)}));
   await started;bindTestSession(worker,'alice');release();
   outcomes.push({name,...await settled,secondEffects,httpEffects});channel.port1.close();channel.port2.close();
  }
  let release,arrived;const gate=new Promise(resolve=>{release=resolve});const started=new Promise(resolve=>{arrived=resolve});
  const worker={clearAuth:async()=>{}};bindTestSession(worker,'alice');
  globalThis.fetch=async()=>{arrived();await gate;return new Response(JSON.stringify({did:'alice'}));};
  const activation=effects.completeLogin('prior-token').then(()=>({success:true}),error=>({error:String(error)}));
  await started;bindTestSession(worker,'alice');release();
  outcomes.push({name:'superseded-login',...await activation,cleared:getClearCount()});
  let dispatched=0;
  bindTestSession(new Proxy({}, {get(){return()=>{dispatched++;throw new Error('unexpected dispatch')}}}),'alice');
  for(const call of ownerCalls) {
    const result=await effects[call.name](...call.args).then(()=>({success:true}),error=>({error:String(error)}));
    outcomes.push({name:`stale-owner-revision:${call.name}`,...result,secondEffects:dispatched,httpEffects:0});
  }
  for (const stage of ['requestCommand','setup','subscribe']) {
    const probe=installWorkerProbe();
    const operation=stage==='requestCommand'?probe.api.requestCommand('save_request_draft',{}):stage==='setup'?probe.api.setup():probe.api.subscribe('cid',()=>{},()=>{},()=>{});
    const settled=operation.then(()=>({success:true}),error=>({error:String(error)}));
    probe.api.clearAuth();probe.releaseReady();probe.releaseSetup();
    const result=await settled;
    const forbidden=probe.calls.filter(name=>['catbird_mls_request_command','catbird_mls_subscribe','catbird_mls_start_background_tasks'].includes(name));
    outcomes.push({name:`worker-continuation:${stage}`,...result,secondEffects:forbidden.length,httpEffects:0});
  }
  return outcomes;
 }, ownerCalls);
 for(const row of result){assert.match(row.error,/session changed/);assert.equal(row.success,undefined);if(row.name==='superseded-login')assert.equal(row.cleared,0);else{assert.equal(row.secondEffects,0);assert.equal(row.httpEffects,0);}}
 console.log(JSON.stringify({result:'PASS',kind:'exact-main-thread-functions-and-real-Comlink',cases:result},null,2));
}finally{await browser.close();await new Promise(resolve=>server.close(resolve));}

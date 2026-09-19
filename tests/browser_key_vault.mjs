// Exercise the exact production vault functions in Chromium using real
// IndexedDB, WebCrypto, Web Locks and OPFS. No MLS/server authorization claim.
import {readFile} from 'node:fs/promises';
import {createServer} from 'node:http';
import assert from 'node:assert/strict';
import ts from '../../catmos/node_modules/typescript/lib/typescript.js';
import {chromium} from '../../catmos/node_modules/@playwright/test/index.mjs';
const source=await readFile(new URL('../../catmos/src/lib/wasm.ts',import.meta.url),'utf8');
const parsed=ts.createSourceFile('wasm.ts',source,ts.ScriptTarget.Latest,true);
const names=['getOrCreateMlsDbKey','sha256Hex','didKey'];
const functions=names.map(name=>{const node=parsed.statements.find(n=>ts.isFunctionDeclaration(n)&&n.name?.text===name);assert(node,name);return node.getText(parsed);}).join('\n');
const constants=['SS_ACTIVE_DID','CONTENT_ROOT_PREFIX'].map(name=>{const node=parsed.statements.find(n=>ts.isVariableStatement(n)&&n.declarationList.declarations.some(d=>d.name.getText(parsed)===name));assert(node,name);return node.getText(parsed);}).join('\n');
const script=ts.transpileModule(`${functions}\n${constants}\nglobalThis.testVault=getOrCreateMlsDbKey;`,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText;
const server=createServer((_,r)=>{r.setHeader('content-type','text/html');r.end('<title>Protected browser custody test</title>');});await new Promise(r=>server.listen(0,'127.0.0.1',r));
const url=`http://127.0.0.1:${server.address().port}`;const browser=await chromium.launch({headless:true});const context=await browser.newContext();
const page=await context.newPage();const second=await context.newPage();
const initialize=async p=>{await p.goto(url);await p.addScriptTag({content:script});};
try{
 await initialize(page);await initialize(second);
 const alice='did:plc:aaaaaaaaaaaaaaaaaaaaaaaa',bob='did:plc:bbbbbbbbbbbbbbbbbbbbbbbb';
 const read=(p,did)=>p.evaluate(async did=>{const v=await testVault(did);return {key:v.key,dbPrefix:v.dbPrefix,content:[...v.contentRootKey]};},did);
 const [a,a2]=await Promise.all([read(page,alice),read(second,alice)]);assert.deepEqual(a,a2);assert.equal(a.key.length,64);
 const b=await read(page,bob);assert.notEqual(a.key,b.key);assert.notEqual(a.dbPrefix,b.dbPrefix);assert.notDeepEqual(a.content,b.content);
 await page.reload();await page.addScriptTag({content:script});assert.deepEqual(await read(page,alice),a);
 const binding=await page.evaluate(async()=>{const db=await new Promise(r=>{const q=indexedDB.open('catbird-protected-database-keys-v1');q.onsuccess=()=>r(q.result);});const key=await new Promise(r=>{const q=db.transaction('keys').objectStore('keys').get('wrapping-key');q.onsuccess=()=>r(q.result);});db.close();let exported=false;try{await crypto.subtle.exportKey('raw',key);exported=true;}catch{}return{extractable:key.extractable,exported};});assert.deepEqual(binding,{extractable:false,exported:false});
 // Remove only test-created records, simulating browser storage loss. A
 // surviving OPFS marker must prohibit silent replacement keys/enrollment.
 await page.evaluate(async did=>{const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(did));const id=[...new Uint8Array(digest)].map(x=>x.toString(16).padStart(2,'0')).join('');const db=await new Promise(r=>{const q=indexedDB.open('catbird-protected-database-keys-v1');q.onsuccess=()=>r(q.result);});await new Promise((r,j)=>{const t=db.transaction('keys','readwrite');t.objectStore('keys').delete(id);t.oncomplete=r;t.onerror=j;});db.close();},alice);
 await assert.rejects(read(page,alice),/account database key is missing/);assert.deepEqual(await read(page,bob),b);
 await page.evaluate(async()=>{const db=await new Promise(r=>{const q=indexedDB.open('catbird-protected-database-keys-v1');q.onsuccess=()=>r(q.result);});await new Promise((r,j)=>{const t=db.transaction('keys','readwrite');t.objectStore('keys').delete('wrapping-key');t.oncomplete=r;t.onerror=j;});db.close();});
 await assert.rejects(read(page,bob),/Existing protected keys are unavailable/);
 console.log('PASS: concurrent tabs, account isolation, page reload, nonexporting wrapping key, missing account key, missing wrapping key (actual browser storage).');
}finally{await browser.close();await new Promise(r=>server.close(r));}

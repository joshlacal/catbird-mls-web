// Negative admission checks execute the actual runner and fail before any TLS,
// browser or session-file use. Fixture-mode checks use the exact TS declarations.
import assert from 'node:assert/strict';
import { mkdtemp,writeFile,readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import vm from 'node:vm';
import ts from '../../catmos/node_modules/typescript/lib/typescript.js';
const root=await mkdtemp(join(tmpdir(),'catbird-gateway-negative-'));
const alice={label:'alice',did:'did:web:alice-case.request-fixture.catbird.blue',deviceId:'11111111-1111-4111-8111-111111111111'};
const bob={label:'bob',did:'did:web:bob-case.request-fixture.catbird.blue',deviceId:'22222222-2222-4222-8222-222222222222'};
const hosts=Object.fromEntries(['gateway-case.request-fixture.catbird.blue','alice-case.request-fixture.catbird.blue','bob-case.request-fixture.catbird.blue','chat.catbird.blue','public.api.bsky.app'].map(host=>[host,'127.0.0.1:34443']));
const base={fixtureOnly:true,origin:'https://gateway-case.request-fixture.catbird.blue',corsOrigin:'http://127.0.0.1:5173',accounts:[alice,bob],hosts};
const cases=[
 ['remote-target',v=>{v.hosts['chat.catbird.blue']='192.0.2.1:443'},/127\\\.0/],
 ['zero-port',v=>{v.hosts['chat.catbird.blue']='127.0.0.1:0'},/127\\\.0/],
 ['oversized-port',v=>{v.hosts['chat.catbird.blue']='127.0.0.1:99999'},/loopback TCP port/],
 ['extra-host',v=>{v.hosts['public.example']='127.0.0.1:34443'},/Only known synthetic/],
 ['resolver-injection',v=>{v.hosts['chat.catbird.blue']='127.0.0.1:443,MAP * 192.0.2.1'},/127\\\.0/],
 ['duplicate-account',v=>{v.accounts=[alice,alice]},/AssertionError/],
 ['public-account',v=>{v.accounts[0].did='did:web:alice.example'},/did:web:alice/],
 ['remote-cors',v=>{v.corsOrigin='http://example.com:5173'},/127\.0\.0\.1/],
];
for(const[name,change,pattern]of cases){const value=structuredClone(base);change(value);const path=join(root,`${name}.json`);await writeFile(path,JSON.stringify(value),{mode:0o600});const result=spawnSync(process.execPath,[new URL('./gateway-runtime.mjs',import.meta.url).pathname,path],{encoding:'utf8',timeout:10000});assert.notEqual(result.status,0,name);assert.match(result.stderr,pattern,name);}
const source=await readFile(new URL('../../catmos/src/lib/wasm.ts',import.meta.url),'utf8');const ast=ts.createSourceFile('wasm.ts',source,ts.ScriptTarget.Latest,true);
const selected=['localRuntimeFixtureOrigin','localRuntimeFixtureBuild'].map(name=>ast.statements.find(n=>ts.isVariableStatement(n)&&n.declarationList.declarations.some(d=>d.name.getText(ast)===name)).getText(ast).replace(/^export /,'')).join('\n').replaceAll('import.meta.env','__env');
const script=ts.transpileModule(selected+'\nglobalThis.result={origin:localRuntimeFixtureOrigin,marker:localRuntimeFixtureBuild};',{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText;
function evaluate(env){const context={URL,__env:env};vm.runInNewContext(script,context);return JSON.parse(JSON.stringify(context.result));}
assert.deepEqual(evaluate({MODE:'production',VITE_LOCAL_REQUEST_FIXTURE_ORIGIN:'https://evil.example'}),{origin:null,marker:null});
const configured={MODE:'local-runtime-fixture',VITE_LOCAL_REQUEST_FIXTURE_ORIGIN:base.origin,VITE_LOCAL_REQUEST_FIXTURE_RUN_ID:'33333333-3333-4333-8333-333333333333'};
assert.deepEqual(evaluate(configured),{origin:base.origin,marker:{runId:configured.VITE_LOCAL_REQUEST_FIXTURE_RUN_ID,origin:base.origin}});
for(const origin of ['http://gateway-case.request-fixture.catbird.blue','https://chat.catbird.blue','https://user@gateway-case.request-fixture.catbird.blue','https://gateway-case.request-fixture.catbird.blue:444','https://gateway-case.request-fixture.catbird.blue/path','https://gateway-case.request-fixture.catbird.blue/?x=1'])assert.throws(()=>evaluate({...configured,VITE_LOCAL_REQUEST_FIXTURE_ORIGIN:origin}));
assert.throws(()=>evaluate({...configured,VITE_LOCAL_REQUEST_FIXTURE_RUN_ID:undefined}),/identity/);
console.log('PASS: 8 actual-runner manifest negatives and exact fixture-mode production isolation/origin/run-marker checks.');

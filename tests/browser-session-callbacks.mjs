// Exact production callback fence, exercised through actual Comlink messages.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import ts from '../../catmos/node_modules/typescript/lib/typescript.js';
import { chromium } from '../../catmos/node_modules/@playwright/test/index.mjs';
const source = await readFile(new URL('../../catmos/src/lib/wasm.ts', import.meta.url), 'utf8');
const ast = ts.createSourceFile('wasm.ts', source, ts.ScriptTarget.Latest, true);
const names = ['sessionCallback', 'invalidateBrowserSession'];
const functions = names.map(name => {
  const node = ast.statements.find(n => ts.isFunctionDeclaration(n) && n.name?.text === name);
  assert(node, name); return node.getText(ast);
}).join('\n');
const script = ts.transpileModule(`let _worker, workerAccount; let browserSessionRevision=0;
${functions}
globalThis.makeGuard=(worker,owner,callback)=>sessionCallback(worker,owner,browserSessionRevision,callback);
globalThis.bindTestSession=(worker,owner)=>{invalidateBrowserSession();_worker=worker;workerAccount=owner;};`, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;
const comlink = await readFile(new URL('../../catmos/node_modules/comlink/dist/esm/comlink.mjs', import.meta.url));
const server = createServer((request, response) => {
  response.setHeader('content-type', request.url === '/comlink.js' ? 'text/javascript' : 'text/html');
  response.end(request.url === '/comlink.js' ? comlink : '<title>Comlink session fence</title>');
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.addScriptTag({ content: script });
  const result = await page.evaluate(async () => {
    const { expose, wrap, proxy } = await import('/comlink.js');
    const channel = new MessageChannel();
    let retained;
    expose({ subscribe(callback) { retained = callback; } }, channel.port1);
    const worker = wrap(channel.port2);
    const delivered = [];
    bindTestSession(worker, 'alice');
    await worker.subscribe(proxy(makeGuard(worker, 'alice', value => delivered.push(value))));
    await retained('current');
    const postedBeforeSwitch = retained('prior-account plaintext');
    bindTestSession(worker, 'bob');
    await postedBeforeSwitch;
    await retained('late old-account event');
    bindTestSession(worker, 'alice');
    await retained('same-DID prior-session status');
    await worker.subscribe(proxy(makeGuard(worker, 'alice', value => delivered.push(value))));
    await retained({ type: 'connected' });
    await retained({ type: 'fetchNeeded', reason: 'canonical' });
    bindTestSession({}, 'alice');
    await retained('superseded Worker');
    channel.port1.close(); channel.port2.close();
    return delivered;
  });
  assert.deepEqual(result, ['current', { type: 'connected' }, { type: 'fetchNeeded', reason: 'canonical' }]);
  console.log('PASS: actual Comlink callback queued before account switch, same-DID re-login, and Worker replacement cannot deliver prior-session content/status.');
} finally {
  await browser.close(); await new Promise(resolve => server.close(resolve));
}

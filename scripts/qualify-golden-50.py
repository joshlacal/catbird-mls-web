#!/usr/bin/env python3
"""Run the release WASM package's manifest and transcript verifiers on all 50 fixtures in Firefox."""
import argparse
import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGE = b"""<!doctype html><meta charset="utf-8"><title>Golden-50 browser qualification</title>
<script type="module">
async function check() {
  const mls = await import('/pkg/catbird_mls_web.js');
  await mls.default();
  const manifest = await (await fetch('/MANIFEST.sha256')).text();
  const files = [], verified = [];
  for (const line of manifest.trim().split(/\\r?\\n/)) {
    const [, filename] = line.split('  ');
    const bytes = new Uint8Array(await (await fetch('/' + filename)).arrayBuffer());
    const report = mls.verifyGoldenTranscriptJson(new TextDecoder().decode(bytes));
    if (report.index !== Number(filename.slice(11, 13)) || verified.includes(report.index)) {
      throw new Error('transcript index does not match manifest: ' + filename);
    }
    verified.push(report.index);
    files.push({filename, bytes});
  }
  const receipt = mls.verifyGoldenManifest(manifest, files);
  if (receipt.verifiedCount !== 50 || verified.length !== 50) throw new Error('incomplete corpus');
  return {...receipt, indexes: verified};
}
try {
  await fetch('/result', {method:'POST', body:JSON.stringify(await check())});
} catch (error) {
  await fetch('/result', {method:'POST', body:JSON.stringify({error:String(error)})});
}
</script>"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pkg", type=Path, default=ROOT / "pkg")
    parser.add_argument("--fixtures", type=Path, default=ROOT.parent / "catbird-sim/fixtures/golden_50")
    parser.add_argument("--firefox", default=shutil.which("firefox") or "/Applications/Firefox.app/Contents/MacOS/firefox")
    args = parser.parse_args()
    manifest_path = args.fixtures / "MANIFEST.sha256"
    manifest = manifest_path.read_bytes()
    names = []
    for line in manifest.decode().splitlines():
        match = re.fullmatch(r"[0-9a-f]{64}  (transcript_([0-9]{2})_[a-zA-Z0-9_-]+\.json)", line)
        if not match or int(match[2]) != len(names) + 1:
            raise SystemExit(f"invalid or out-of-order manifest entry: {line}")
        names.append(match[1])
    if len(names) != 50 or set(names) != {path.name for path in args.fixtures.glob("transcript_*.json")}:
        raise SystemExit("manifest must name exactly all 50 transcript files")
    wasm_name = "catbird_mls_web_bg.wasm"
    paths = {"/" + name: (args.fixtures / name, "application/json") for name in names}
    paths["/MANIFEST.sha256"] = manifest_path, "text/plain"
    paths["/pkg/catbird_mls_web.js"] = args.pkg / "catbird_mls_web.js", "text/javascript"
    paths["/pkg/" + wasm_name] = args.pkg / wasm_name, "application/wasm"
    received = queue.Queue()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path == "/":
                content, kind = PAGE, "text/html"
            elif self.path in paths:
                path, kind = paths[self.path]
                content = path.read_bytes()
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(content)

        def do_POST(self):
            if self.path != "/result":
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 16384:
                self.send_error(400)
                return
            report = json.loads(self.rfile.read(length))
            self.send_response(204)
            self.end_headers()
            received.put(report)

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as http, tempfile.TemporaryDirectory() as profile:
        threading.Thread(target=http.serve_forever, daemon=True).start()
        env = {**os.environ, "MOZ_HEADLESS": "1", "MOZ_CRASHREPORTER_DISABLE": "1"}
        url = f"http://127.0.0.1:{http.server_port}/"
        process = subprocess.Popen([args.firefox, "-headless", "-no-remote", "-profile", profile, url], env=env)
        try:
            report = received.get(timeout=240)
        finally:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            http.shutdown()
    if report.get("error"):
        raise SystemExit(report["error"])
    if sorted(report["indexes"]) != list(range(1, 51)) or report["manifestSha256"] != hashlib.sha256(manifest).hexdigest():
        raise SystemExit("unexpected verification receipt")
    print(json.dumps({"wasmSha256": hashlib.sha256((args.pkg / wasm_name).read_bytes()).hexdigest(), **report}))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Verify a built wasm-pack output against the fixture's wasmPackage record.

pkg/ is gitignored, so `cargo test --test provenance` cannot require it. Run this
after every ./build.sh (and against a consumer's copy, e.g. catmos
src/lib/wasm-pkg) to prove the files on disk are the ones the fixture names.
Exits non-zero on any missing file or SHA-256 mismatch.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--pkg-dir', default=str(root / 'pkg'),
                    help='directory holding the built files (default: pkg/)')
parser.add_argument('--fixture', default=str(root / 'tests/fixtures/chat-artifact-provenance.json'),
                    help='provenance fixture to check against (default: the vendored one)')
parser.add_argument('--no-siblings', action='store_true',
                    help='skip comparing the recorded revisions with ../catbird-mls, '
                         '../labyrinth, ../catbird-atproto, ../Petrel and ../PetrelCatbird')
args = parser.parse_args()
pkg = Path(args.pkg_dir).resolve()
manifest = json.loads(Path(args.fixture).read_bytes())
package = manifest.get('wasmPackage')
if not package or not package.get('files'):
    sys.exit('fixture has no wasmPackage.files record')
if package.get('coreRevision') != manifest.get('coreRevision'):
    sys.exit('wasmPackage.coreRevision differs from the vendored coreRevision')
failures = []


def sibling_head(repo):
    """Sealed parent commit of a clean sibling checkout."""
    if (repo / '.jj').exists():
        # Normal jj secondary workspaces have no .git working tree. Snapshot the current
        # files before checking the empty working-copy commit; --ignore-working-copy alone
        # can see a previously sealed snapshot while the build consumed new file contents.
        if subprocess.check_output(['jj', 'diff', '--summary'], cwd=repo, text=True).strip():
            return None, f'{repo} has unsealed working-copy changes'
        return subprocess.check_output(
            ['jj', '--ignore-working-copy', 'log', '--no-graph', '-r', '@-', '-T', 'commit_id'],
            cwd=repo, text=True).strip(), None
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=repo, text=True).strip():
        return None, f'{repo} has uncommitted changes'
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip(), None


if not args.no_siblings:
    for key, name in (('coreRevision', 'catbird-mls'),
                      ('labyrinthRevision', 'labyrinth'),
                      ('catbirdAtprotoRevision', 'catbird-atproto'),
                      ('petrelRevision', 'Petrel'),
                      ('petrelCatbirdRevision', 'PetrelCatbird')):
        repo = root.parent / name
        head, problem = sibling_head(repo)
        if problem:
            failures.append(problem)
            continue
        recorded = package.get(key)
        status = 'ok' if head == recorded else 'MISMATCH'
        print(f'{status} {key} {recorded} (../{name} head {head})')
        if head != recorded:
            failures.append(f'{key}: fixture records {recorded}, ../{name} is at {head}')
for name, expected in sorted(package['files'].items()):
    path = pkg / name
    if not path.is_file():
        failures.append(f'missing {path}')
        continue
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    status = 'ok' if actual == expected else 'MISMATCH'
    print(f'{status} {name} {actual}')
    if actual != expected:
        failures.append(f'{name}: expected {expected}, found {actual}')
if failures:
    sys.exit('\n'.join(failures))
print(f'{len(package["files"])} files in {pkg} match wasmPackage (core {package["coreRevision"]})')

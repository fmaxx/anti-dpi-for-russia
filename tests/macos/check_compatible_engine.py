#!/usr/bin/env python3
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import urllib.request

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'macos/app'))
from install import extract_source
from igareck import engine_arguments, load_catalogue


def main():
    parser = argparse.ArgumentParser(description='Build pinned macws2 and dry-run all 484 strategies without interception.')
    parser.add_argument('--upstream-dir', type=Path)
    args = parser.parse_args()
    if sys.platform != 'darwin':
        raise RuntimeError('This check requires macOS.')
    if os.geteuid() == 0:
        raise RuntimeError('Run without sudo; no traffic is intercepted.')
    meta = json.loads((REPO / 'macos/data/upstream.json').read_text())
    with tempfile.TemporaryDirectory(prefix='ig-macos-engine-check-') as temporary:
        root = Path(temporary)
        if args.upstream_dir:
            upstream = args.upstream_dir.resolve()
        else:
            archive = root / 'source.tar.gz'
            with urllib.request.urlopen(meta['url'], timeout=60) as response:
                content = response.read(100 * 1024 * 1024 + 1)
            if len(content) > 100 * 1024 * 1024 or sha256(content).hexdigest() != meta['sha256']:
                raise RuntimeError('Upstream archive SHA-256 mismatch.')
            archive.write_bytes(content)
            upstream = root / 'source'
            extract_source(archive, upstream, 'zapret2-' + meta['commit'])
        for name in ('darwin.c', 'darwin.h'):
            shutil.copy2(REPO / 'macos/engine' / name, upstream / 'nfq2' / name)
        patch_text = (REPO / 'macos/engine/zapret2-darwin.patch').read_text()
        subprocess.run(['patch', '-p1'], cwd=upstream, input=patch_text, text=True, check=True)
        subprocess.run(['make', '-C', str(upstream / 'nfq2'), '-j2', 'macos',
                        'MINSIZE=-ffunction-sections -fdata-sections', 'LDFLAGS=-Wl,-dead_strip'], check=True)
        engine = root / 'engine'
        engine.mkdir()
        shutil.copy2(upstream / 'nfq2/macws2', engine / 'macws2')
        shutil.copytree(upstream / 'lua', engine / 'lua')
        shutil.copytree(REPO / 'macos/data/lists', root / 'lists')
        shutil.copy2(REPO / 'macos/data/actual_tls_guard.lua', root / 'actual_tls_guard.lua')
        data = load_catalogue(REPO / 'macos/app')
        for row in data['ProfileRows']:
            checked = subprocess.run(engine_arguments(root, row) + ['--dry-run'], cwd=engine,
                                     capture_output=True, text=True, timeout=20)
            if checked.returncode:
                raise RuntimeError('Strategy ' + str(row['Number']) + ': ' + checked.stdout + checked.stderr)
        print('Verified 484/484 macOS parameter/Lua dry-runs against ' + meta['commit'] + '.')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Reproducible isolated loopback benchmark. No user clipboard/config is accessed.
Usage: python tools/benchmark.py --binary target/release/clipx --mib 128
"""
import argparse
import hashlib
import json
import os
import pathlib
import random
import socket
import subprocess
import tempfile
import time
try:
    import resource
except ImportError:
    resource = None

p = argparse.ArgumentParser()
p.add_argument('--binary', default='target/release/clipx')
p.add_argument('--mib', type=int, default=128)
a = p.parse_args()
binary = str(pathlib.Path(a.binary).resolve())
if a.mib < 1:
    p.error('--mib must be positive')

def call(config, *args):
    result = subprocess.run([binary, '--json', *map(str, args)], capture_output=True, text=True, check=True)
    return [json.loads(line) for line in result.stdout.splitlines()]

def hash_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

with tempfile.TemporaryDirectory(prefix='clipx-bench-') as td:
    root = pathlib.Path(td)
    sender, receiver, downloads = [root / n for n in ['sender', 'receiver', 'downloads']]
    rng = random.Random(1)
    paths = []
    for name, compressible in [('compressible', True), ('incompressible', False)]:
        f = root / name
        with f.open('wb') as out:
            for _ in range(a.mib):
                out.write(b'A' * 1048576 if compressible else rng.randbytes(1048576))
        paths.append(f)
    small = root / 'small-files'
    small.mkdir()
    for i in range(1000):
        (small / f'{i:04}.txt').write_bytes((f'file {i}\n' * 100).encode())
    paths.append(small)
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    log = (root / 'receiver.log').open('w+')
    server = subprocess.Popen([binary, '--downloads', str(downloads), '--port', str(port), '--json', 'recv', '--yes', '--bind', '127.0.0.1', '--headless'], stdout=log, stderr=log)
    try:
        for _ in range(100):
            time.sleep(.05)
            log.flush()
            if 'listening' in (root / 'receiver.log').read_text():
                break
            if server.poll() is not None:
                raise RuntimeError((root / 'receiver.log').read_text())
        for path in paths:
            files = sorted(path.rglob('*')) if path.is_dir() else [path]
            total = sum(f.stat().st_size for f in files if f.is_file())
            for transport in ['quic', 'tcp']:
                for compression in ['off', 'auto', 'zstd']:
                    before = resource.getrusage(resource.RUSAGE_CHILDREN) if resource else None
                    start = time.perf_counter()
                    output = call(sender, '--port', port, 'send', '--yes', '127.0.0.1', '--path', path, '--transport', transport, '--compression', compression)
                    elapsed = time.perf_counter() - start
                    after = resource.getrusage(resource.RUSAGE_CHILDREN) if resource else None
                    dest = pathlib.Path(next(e['data']['paths'][0] for e in output if e['event'] == 'verified'))
                    for f in files:
                        if f.is_file():
                            received = dest / f.relative_to(path) if path.is_dir() else dest
                            assert hash_file(f) == hash_file(received)
                    print(json.dumps({'case': path.name, 'transport': transport, 'compression': compression, 'bytes': total, 'seconds': elapsed, 'MiB_per_second': total / 1048576 / elapsed, 'verified': True, 'sender_cpu_seconds': (after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime) if after else None, 'peak_child_rss_so_far_kib': after.ru_maxrss if after else None}), flush=True)
    finally:
        server.terminate()
        server.wait(timeout=10)
        log.close()

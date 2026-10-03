"""Optional real >4 GiB test. Sparse source, real streamed receiver output; ~4.1 GiB free disk needed."""
import hashlib
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

binary = str(pathlib.Path(sys.argv[1]).resolve())
size = (1 << 32) + 17

def run(config, *args):
    return subprocess.run([binary, '--config-dir', str(config), '--json', *map(str, args)], capture_output=True, text=True, check=True)

def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1048576), b''):
            h.update(b)
    return h.hexdigest()

with tempfile.TemporaryDirectory(prefix='clipx-large-') as tmp:
    root = pathlib.Path(tmp)
    sc, rc, dl = [root / n for n in ['sender', 'receiver', 'downloads']]
    sfp = json.loads(run(sc, 'fingerprint').stdout)['data']['blake3_cert']
    rfp = json.loads(run(rc, 'fingerprint').stdout)['data']['blake3_cert']
    run(sc, 'peer', 'trust', rfp, '--host', '127.0.0.1')
    run(rc, 'peer', 'trust', sfp)
    source = root / 'over-4GiB.bin'
    with source.open('wb') as f:
        f.truncate(size)
        marker = b'CLIPX-U64-VERIFIED'
        f.seek(size - len(marker))
        f.write(marker)
    assert source.stat().st_size == size
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    with (root / 'receiver.log').open('w+') as log:
        server = subprocess.Popen([binary, '--config-dir', str(rc), '--downloads', str(dl), '--port', str(port), 'recv', '--bind', '127.0.0.1', '--headless'], stdout=log, stderr=log)
        try:
            for _ in range(100):
                time.sleep(.05)
                if 'listening' in (root / 'receiver.log').read_text():
                    break
            start = time.perf_counter()
            out = run(sc, '--port', port, 'send', '127.0.0.1', '--path', source, '--transport', 'quic', '--compression', 'zstd')
            done = next(json.loads(line)['data'] for line in out.stdout.splitlines() if json.loads(line)['event'] == 'verified')
            dest = pathlib.Path(done['paths'][0])
            assert dest.stat().st_size == size
            assert digest(source) == digest(dest)
            print(json.dumps({'bytes': size, 'transport': 'quic', 'compression': 'zstd', 'sha256_match': True, 'seconds_including_external_hashes': time.perf_counter() - start}))
        finally:
            server.terminate()
            server.wait(timeout=10)

"""Black-box fault test: sever TLS mid-payload, kill/restart receiver, verify automatic resume.
Runs only against disposable loopback identities/directories. No user clipboard.
"""
import hashlib
import json
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time

binary = str(pathlib.Path(sys.argv[1]).resolve())

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def run(config, *args):
    return subprocess.run([binary, '--json', *map(str, args)], text=True, capture_output=True, check=True)

def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1048576), b''):
            h.update(b)
    return h.hexdigest()

with tempfile.TemporaryDirectory(prefix='clipx-recovery-') as tmp:
    root = pathlib.Path(tmp)
    sc, rc, dl = [root / p for p in ['sender', 'receiver', 'downloads']]
    backend, frontend = port(), port()
    source = root / 'large.bin'
    with source.open('wb') as f:
        for i in range(64):
            f.write(bytes([i]) * 1048576)
    log = (root / 'receiver.log').open('w+')
    def receiver():
        child = subprocess.Popen([binary, '--downloads', str(dl), '--port', str(backend), 'recv', '--yes', '--bind', '127.0.0.1', '--headless', '--transport', 'tcp'], stdout=log, stderr=log)
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1', backend), .05):
                    return child
            except OSError:
                if child.poll() is not None:
                    raise RuntimeError((root / 'receiver.log').read_text())
                time.sleep(.05)
        raise RuntimeError('receiver startup timeout')
    server = receiver()
    cut = threading.Event()
    stop = threading.Event()
    errors = []
    listener = socket.socket()
    listener.bind(('127.0.0.1', frontend))
    listener.listen(8)
    listener.settimeout(.2)
    def proxy():
        first = True
        try:
            while not stop.is_set():
                try:
                    client, _ = listener.accept()
                except socket.timeout:
                    continue
                with client, socket.create_connection(('127.0.0.1', backend), 3) as upstream:
                    client.setblocking(True)
                    upstream.setblocking(True)
                    forwarded = 0
                    closed = False
                    while not stop.is_set() and not closed:
                        ready, _, _ = select.select([client, upstream], [], [], .2)
                        for src in ready:
                            data = src.recv(65536)
                            if not data:
                                closed = True
                                break
                            dest = upstream if src is client else client
                            dest.sendall(data)
                            if src is client:
                                forwarded += len(data)
                            if first and forwarded >= 8 * 1048576:
                                first = False
                                cut.set()
                                closed = True
                                break
        except OSError as e:
            if not stop.is_set():
                errors.append(str(e))
    worker = threading.Thread(target=proxy, daemon=True)
    worker.start()
    sender = subprocess.Popen([binary, '--json', '--port', str(frontend), 'send', '--yes', '127.0.0.1', '--path', str(source), '--transport', 'tcp', '--compression', 'off'], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert cut.wait(30), 'proxy did not interrupt transfer'
        server.kill()
        server.wait(timeout=5)
        server = receiver()
        stdout, stderr = sender.communicate(timeout=90)
        assert sender.returncode == 0, (stdout, stderr, errors)
        events = [json.loads(line) for line in stdout.splitlines()]
        assert any(e['event'] == 'reconnecting' for e in events), stdout
        done = next(e['data'] for e in events if e['event'] == 'verified')
        assert done['resumed_bytes'] >= 1048576, done
        assert digest(source) == digest(done['paths'][0])
        assert len(list(dl.glob('large*.bin'))) == 1
        print(json.dumps({'receiver_process_restart': True, 'automatic_retry': True, 'resumed_bytes': done['resumed_bytes'], 'total_bytes': done['total_bytes'], 'sha256_match': True}))
    finally:
        stop.set()
        sender.kill() if sender.poll() is None else None
        server.terminate()
        server.wait(timeout=5)
        worker.join(timeout=3)
        listener.close()
        log.close()

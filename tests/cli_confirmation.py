"""Exercise real CLI prompts, independent --yes flags, fresh codes and zero config writes."""
import json
import os
import pathlib
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time

binary = str(pathlib.Path(sys.argv[1]).resolve())

def free_port():
    # TCP-free does not imply UDP-free (notably on Windows runners).
    for _ in range(100):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, socket.socket() as tcp:
            udp.bind(('127.0.0.1', 0))
            port = udp.getsockname()[1]
            try:
                tcp.bind(('127.0.0.1', port))
                tcp.listen(1)
                return str(port)
            except OSError:
                continue
    raise RuntimeError('no jointly available UDP/TCP loopback port')

class Child:
    def __init__(self, args, env):
        self.p = subprocess.Popen([binary, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, encoding='utf-8', env=env, bufsize=1)
        self.lines = []
        self.q = queue.Queue()
        self.threads = []
        for stream in (self.p.stdout, self.p.stderr):
            t = threading.Thread(target=self.read, args=(stream,), daemon=True)
            t.start()
            self.threads.append(t)
    def read(self, stream):
        for line in stream:
            self.lines.append(line.rstrip())
            self.q.put(line.rstrip())
    def wait_line(self, prefix):
        end = time.monotonic() + 15
        while time.monotonic() < end:
            try:
                line = self.q.get(timeout=.1)
                if line.startswith(prefix):
                    return line[len(prefix):].strip()
            except queue.Empty:
                if self.p.poll() is not None:
                    break
        raise AssertionError((prefix, self.lines))
    def answer(self, value):
        self.p.stdin.write(value + '\n')
        self.p.stdin.flush()
    def finish(self, expected=0):
        assert self.p.wait(timeout=20) == expected, self.lines
        for t in self.threads:
            t.join(timeout=2)
    def close(self):
        if self.p.poll() is None:
            self.p.terminate()
            self.p.wait(timeout=5)

with tempfile.TemporaryDirectory(prefix='clipx-confirm-') as tmp:
    root = pathlib.Path(tmp)
    home = root / 'home'
    home.mkdir()
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home),
               XDG_CONFIG_HOME=str(home / '.config'), XDG_CACHE_HOME=str(home / '.cache'),
               APPDATA=str(home / 'AppData'), LOCALAPPDATA=str(home / 'LocalAppData'))
    codes = set()
    cases = 0
    for mode in ['tcp', 'quic', 'auto']:
        for send_yes, recv_yes in [(False, False), (True, False), (False, True), (True, True)]:
            port = free_port()
            dl = home / 'Downloads'
            server = Child(['--json', '--port', port, '--downloads', str(dl), 'recv',
                            '--headless', '--bind', '127.0.0.1', '--transport', mode,
                            *(['--yes'] if recv_yes else [])], env)
            sender = None
            try:
                server.wait_line('{"data":')
                before = set(dl.iterdir())
                sender = Child(['--json', '--port', port, 'send', *(['--yes'] if send_yes else []),
                                '127.0.0.1', '--transport', mode, '--text', 'session payload', '--retries', '0'], env)
                a = sender.wait_line('Pairing fingerprint:')
                b = server.wait_line('Pairing fingerprint:')
                assert a == b and a not in codes, (a, b, codes)
                assert len(a.replace(' ', '')) == 64
                codes.add(a)
                if not (send_yes and recv_yes):
                    time.sleep(.05)
                    assert set(dl.iterdir()) == before, 'payload written before approval'
                if not send_yes:
                    sender.wait_line('Allow this transfer only?')
                    sender.answer('y')
                if not recv_yes:
                    server.wait_line('Allow this transfer only?')
                    server.answer('y')
                sender.finish()
                assert not list(dl.glob('.clipx-*')), list(dl.iterdir())
                assert set(home.iterdir()) == {dl}, list(home.iterdir())
                assert any('verified' in line for line in sender.lines), sender.lines
                cases += 1
            finally:
                if sender:
                    sender.close()
                server.close()
    # Decline on either side, including an automatically accepting opposite endpoint.
    for decline_sender in [True, False]:
        port = free_port()
        server = Child(['--json', '--port', port, '--downloads', str(dl), 'recv', '--headless',
                        '--bind', '127.0.0.1', *(['--yes'] if decline_sender else [])], env)
        sender = None
        try:
            server.wait_line('{"data":')
            before = set(dl.iterdir())
            sender = Child(['--json', '--port', port, 'send', *([] if decline_sender else ['--yes']),
                            '127.0.0.1', '--text', 'must not write', '--retries', '0'], env)
            target = sender if decline_sender else server
            target.wait_line('Allow this transfer only?')
            target.answer('n')
            sender.finish(expected=1)
            assert set(dl.iterdir()) == before
        finally:
            if sender:
                sender.close()
            server.close()
    print(json.dumps({'real_cli_confirmation_cases': cases, 'decline_cases': 2,
                      'fresh_matching_session_codes': len(codes), 'no_config_or_identity_files': True,
                      'successful_checkpoint_cleanup': True}))

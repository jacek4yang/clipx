"""Real terminal tests: POSIX PTY / Windows ConPTY, never pipe-only prompt simulation."""
import json, os, pathlib, re, socket, subprocess, sys, tempfile, threading, time
binary = str(pathlib.Path(sys.argv[1]).resolve())
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07]*(?:\x07|\x1b\\)')

def free_port():
    for _ in range(100):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, socket.socket() as tcp:
            udp.bind(('127.0.0.1', 0)); port = udp.getsockname()[1]
            try: tcp.bind(('127.0.0.1', port)); tcp.listen(1); return str(port)
            except OSError: continue
    raise RuntimeError('no available loopback port')

class Child:
    def __init__(self, args, env):
        self.output = ''; self.position = 0; self.status = None
        if os.name == 'nt':
            from winpty import PtyProcess
            self.p = PtyProcess.spawn([binary, *args], env=env, dimensions=(30, 100))
        else:
            import pty, fcntl, struct, termios
            self.pid, self.fd = pty.fork()
            if self.pid == 0: os.execve(binary, [binary, *args], env)
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack('HHHH', 30, 100, 0, 0))
        self.reader = threading.Thread(target=self.read, daemon=True); self.reader.start()
    def read(self):
        import codecs
        decode = codecs.getincrementaldecoder('utf-8')('replace')
        try:
            while True:
                if os.name == 'nt': data = self.p.read(4096)
                else:
                    raw = os.read(self.fd, 4096)
                    if not raw: break
                    data = decode.decode(raw)
                if not data: break
                self.output += data
        except (OSError, EOFError): pass
    def clean(self): return ANSI.sub('', self.output).replace('\r', '')
    def poll(self):
        if os.name == 'nt':
            if self.p.isalive(): return None
            return self.p.exitstatus
        if self.status is None:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid: self.status = os.waitstatus_to_exitcode(status)
        return self.status
    def wait(self, text, timeout=20):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            output=self.clean(); at=output.find(text,self.position)
            if at>=0: self.position=at+len(text); return
            if self.poll() is not None: break
            time.sleep(.01)
        raise AssertionError((text,self.clean()))
    def code(self):
        self.wait('Pairing fingerprint: ')
        end=time.monotonic()+5
        while time.monotonic()<end:
            part=self.clean()[self.position:]; match=re.match(r'([0-9a-f]{8}(?: [0-9a-f]{8}){7})',part)
            if match: self.position+=len(match[1]); return match[1]
            time.sleep(.01)
        raise AssertionError(self.clean())
    def write(self, text):
        if os.name=='nt': self.p.write(text)
        else: os.write(self.fd,text.encode())
    def finish(self, success=True):
        end=time.monotonic()+25
        while self.poll() is None and time.monotonic()<end: time.sleep(.02)
        status=self.poll(); assert status is not None, self.clean()
        assert (status==0)==success,(status,self.clean())
        self.reader.join(timeout=1)
    def close(self):
        if self.poll() is None:
            if os.name=='nt': self.p.terminate(force=True)
            else:
                import signal
                os.kill(self.pid,signal.SIGKILL); os.waitpid(self.pid,0); self.status=-9
        if os.name!='nt': os.close(self.fd)

with tempfile.TemporaryDirectory(prefix='clipx-pty-') as tmp:
    root=pathlib.Path(tmp); home=root/'home';home.mkdir();dl=home/'Downloads'
    env=dict(os.environ,HOME=str(home),USERPROFILE=str(home),XDG_CONFIG_HOME=str(home/'.config'),
             XDG_CACHE_HOME=str(home/'.cache'),APPDATA=str(home/'AppData'),LOCALAPPDATA=str(home/'LocalAppData'),TERM='xterm-256color',NO_COLOR='1')
    codes=set(); cases=0
    for mode in ['tcp','quic','auto']:
        for sy,ry in [(False,False),(True,False),(False,True),(True,True)]:
            port=free_port();server=Child(['--json','--port',port,'--downloads',str(dl),'recv','--headless','--bind','127.0.0.1','--transport',mode,*(['--yes']if ry else[])],env);sender=None
            try:
                server.wait('listening');before=set(dl.iterdir())
                sender=Child(['--json','--port',port,'send',*(['--yes']if sy else[]),'127.0.0.1','--transport',mode,'--text','session payload','--retries','0'],env)
                a,b=sender.code(),server.code();assert a==b and a not in codes;(codes.add(a))
                if not sy: sender.wait('Fingerprints match?')
                if not ry: server.wait('Fingerprints match?')
                if not(sy and ry): assert set(dl.iterdir())==before
                if not sy: sender.write('y') # Deliberately NO Enter: real terminal keystroke.
                if not ry: server.write('Y')
                sender.finish();assert 'verified' in sender.clean(),sender.clean()
                assert not list(dl.glob('.clipx-*'));assert set(home.iterdir())=={dl}
                cases+=1
                print(f'PASS terminal case {cases}: {mode}, sender_yes={sy}, receiver_yes={ry}',flush=True)
            finally:
                if sender: sender.close()
                server.close()
    # Default Enter, N, Escape, and invalid key followed by decline; no accidental accept.
    for key in ['\r','n','\x1b','x\x1b']:
        port=free_port();server=Child(['--json','--port',port,'--downloads',str(dl),'recv','--yes','--headless','--bind','127.0.0.1'],env);sender=None
        try:
            server.wait('listening');before=set(dl.iterdir())
            sender=Child(['--json','--port',port,'send','127.0.0.1','--text','must not write','--retries','0'],env)
            sender.wait('Fingerprints match?');sender.write(key);sender.finish(False);assert set(dl.iterdir())==before
        finally:
            if sender:sender.close()
            server.close()
    # Peer cancellation must release the receiver's terminal, so the next prompt works.
    port=free_port();server=Child(['--json','--port',port,'--downloads',str(dl),'recv','--headless','--bind','127.0.0.1'],env)
    try:
        server.wait('listening')
        for answer in ['n','y']:
            sender=Child(['--json','--port',port,'send','127.0.0.1','--text','cancel then retry','--retries','0'],env)
            try:
                sender.wait('Fingerprints match?');server.wait('Fingerprints match?')
                sender.write(answer)
                if answer=='y':server.write('y')
                sender.finish(answer=='y');time.sleep(.15)
            finally:sender.close()
        # Ctrl+C at a pending prompt exits receiver and restores terminal state.
        sender=Child(['--json','--port',port,'send','--yes','127.0.0.1','--text','cancel','--retries','0'],env)
        try:
            server.code() # Advance past the previous completed prompt's rendered selection.
            server.wait('Fingerprints match?');server.write('\x03');server.finish();sender.finish(False)
        finally:sender.close()
    finally:server.close()
    print(json.dumps({'real_terminal': 'ConPTY' if os.name=='nt' else 'POSIX PTY', 'confirmation_cases':cases,
                      'single_key_without_enter':True,'default_and_escape_decline':True,'peer_cancel_then_new_prompt':True,
                      'ctrl_c_exit':True,'no_config_files':True}))

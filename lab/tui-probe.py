#!/usr/bin/env python3
# Drive the incredigo `guide` Bubble Tea TUI under a REAL pty so it renders genuine
# frames, send a scripted key sequence, and assert on what it draws. FAKE creds only.
# Run unbuffered (python3 -u). A SIGALRM watchdog guarantees it can never hang.
#
# argv: <guide-args...>
import os, pty, re, select, sys, time, fcntl, termios, struct, signal

ANSI = re.compile(rb'\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\x1b[=>]')
def clean(b): return ANSI.sub(b'', b).decode('utf-8', 'replace')

GUIDE_ARGS = sys.argv[1:]
ENV = dict(os.environ,
           GOPASS_HOMEDIR=os.path.expanduser('~/.lab-gopass'),
           GNUPGHOME=os.path.expanduser('~/.lab-gnupg'),
           INCREDIGO_PASSPHRASE='lab-seal-passphrase-001',
           PATH='/usr/local/bin:' + os.environ.get('PATH', ''),
           TERM='xterm-256color')

pid, fd = pty.fork()
if pid == 0:
    os.execvpe('incredigo', ['incredigo', 'guide', *GUIDE_ARGS], ENV)
    os._exit(127)
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', 40, 120, 0, 0))

# watchdog: kill everything after 25s no matter what, then report
def boom(*_):
    print("   WATCHDOG: timed out — killing child", flush=True)
    try: os.kill(pid, signal.SIGKILL)
    except OSError: pass
    print("\nTUI-PROBE FAILS: ['watchdog timeout']", flush=True)
    os._exit(2)
signal.signal(signal.SIGALRM, boom); signal.alarm(25)

buf = bytearray()
def respond(data):
    # Act like a real terminal: answer the queries termenv/bubbletea send before
    # it will render, otherwise it blocks forever waiting for the reply.
    if b'\x1b[6n' in data:                       # DSR cursor-position request
        os.write(fd, b'\x1b[24;80R')
    if b'\x1b]11;?' in data:                      # OSC 11 background-color query
        os.write(fd, b'\x1b]11;rgb:1c1c/1c1c/1c1c\x1b\\')
    if b'\x1b]10;?' in data:                      # OSC 10 foreground-color query
        os.write(fd, b'\x1b]10;rgb:c0c0/c0c0/c0c0\x1b\\')
    if b'\x1b[c' in data or b'\x1b[0c' in data:   # Primary Device Attributes
        os.write(fd, b'\x1b[?1;2c')
def drain(t=0.6):
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.15)
        if r:
            try: data = os.read(fd, 65536)
            except OSError: break
            if not data: break
            respond(data); buf.extend(data); end = time.time() + t
    return clean(bytes(buf))
def send(keys):
    os.write(fd, keys); time.sleep(0.25)

fails = []
def check(cond, label):
    print(('   OK: ' if cond else '   FAIL: ') + label, flush=True)
    if not cond: fails.append(label)
def cur(scr):
    # the LAST 'X of N' in the accumulated buffer is the currently-visible frame
    ms = re.findall(r'(\d+) of (\d+)', scr)
    return ms[-1] if ms else None

print(">> initial frame", flush=True)
scr = drain(1.5)
print("   (captured %d chars)" % len(scr), flush=True)
check('guided rotation' in scr, "header 'guided rotation' rendered")
m = re.search(r'(\d+) of (\d+)', scr)
total = int(m.group(2)) if m else 0
print("   parsed total =", total, flush=True)
check(m is not None and m.group(1) == '1', "starts at item 1")
check('0 marked done' in scr, "starts with 0 marked done")
check('Read-only' in scr, "read-only notice shown")
check('manual' in scr or 'auto' in scr, "rotation label (auto/manual) rendered")
buf.clear()

print(">> n,n -> item 3", flush=True)
send(b'n'); send(b'n'); scr = drain(0.5)
c = cur(scr)
check(c is not None and c[0] == '3', "after n,n -> item 3")
buf.clear()

print(">> prev clamp at top", flush=True)
for _ in range(5): send(b'p')
scr = drain(0.5)
c = cur(scr)
check(c is not None and c[0] == '1', "prev past top clamps at item 1")
buf.clear()

print(">> enter marks done", flush=True)
send(b'\r'); scr = drain(0.5)
check('done' in scr and '1 marked done' in scr, "enter -> ✓ done, count 1, advances")
buf.clear()

print(">> s skips", flush=True)
send(b's'); scr = drain(0.5)
check('1 marked done' in scr, "s skips, count still 1")
buf.clear()

print(">> next clamp at end", flush=True)
for _ in range(total + 2): send(b'n')
scr = drain(0.5)
c = cur(scr)
check(c is not None and c[0] == str(total), "next past end clamps at item %d" % total)
buf.clear()

print(">> 'o' open-link no crash", flush=True)
send(b'o'); scr = drain(0.6)
check('guided rotation' in scr or scr.strip() == '', "'o' did not crash TUI")
buf.clear()

print(">> quit with q", flush=True)
send(b'q'); drain(0.6)
# reap with bounded wait; escalate if needed
ok = False
for _ in range(20):
    wpid, status = os.waitpid(pid, os.WNOHANG)
    if wpid == pid:
        ok = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
        break
    time.sleep(0.1)
else:
    os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0)
check(ok, "q quits cleanly (exit 0)")

signal.alarm(0)
print("\nTUI-PROBE FAILS:", fails if fails else "none", flush=True)
sys.exit(1 if fails else 0)

#!/usr/bin/env python3
# Drives `incredigo passwords ... commit --allow-csv` inside a real pty so the command
# sees a TTY and PAUSES at its "press Enter to shred" prompt. While the child is blocked,
# we inspect the tmpfs CSV it staged (location, header, contents), then release it and
# confirm the file was shredded. This is the only way to observe the otherwise-ephemeral
# tmpfs CSV, since headless commit shreds it immediately.
#
# argv: mgr export stage backup audit old1 old2 want_header pwcol
import os, pty, sys, select, re, subprocess, time

mgr, export, stage, backup, audit, old1, old2, want_header, pwcol = sys.argv[1:10]
pwcol = int(pwcol)
fail = 0
def out(m): print("   " + m, flush=True)

cmd = ["incredigo", "passwords", "--manager", mgr, "--export-path", export,
       "--allow-csv", "commit", "--stage-in", stage, "--verified", "all",
       "--backup-out", backup, "--audit-log", audit]

master, slave = pty.openpty()
proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave, close_fds=True)
os.close(slave)

buf = b""
csv_path = None
deadline = time.time() + 30
while time.time() < deadline:
    r, _, _ = select.select([master], [], [], 0.5)
    if master in r:
        try:
            chunk = os.read(master, 4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        m = re.search(rb'(/dev/shm/incredigo/incredigo-pw-[0-9]+\.csv)', buf)
        if m and b'press Enter to shred' in buf:
            csv_path = m.group(1).decode()
            break
    if proc.poll() is not None:
        break

if not csv_path:
    out("FAIL: no tmpfs CSV / shred prompt seen")
    sys.stdout.write(buf.decode(errors="replace"))
    sys.exit(1)

out("staged CSV: " + csv_path)

# (a) on tmpfs?
fst = subprocess.run(["stat", "-f", "-c", "%T", csv_path],
                     capture_output=True, text=True).stdout.strip()
if fst == "tmpfs":
    out("OK: CSV is on tmpfs (%s)" % fst)
else:
    out("FAIL: CSV not on tmpfs (%s)" % fst); fail = 1

# (b) correct per-browser header + (c) NEW pw present, OLD gone
with open(csv_path) as f:
    lines = f.read().splitlines()
hdr = lines[0] if lines else ""
if hdr == want_header:
    out("OK: header = " + hdr)
else:
    out("FAIL: header=%s want=%s" % (hdr, want_header)); fail = 1

body = "\n".join(lines[1:])
for label, old in (("github", old1), ("gitlab", old2)):
    if old in body:
        out("FAIL: OLD %s pw present in CSV" % label); fail = 1
    else:
        out("OK: OLD %s pw absent from CSV" % label)

row1 = lines[1].split(",") if len(lines) > 1 else []
newpw = row1[pwcol - 1] if len(row1) >= pwcol else ""
if len(newpw) >= 16:
    out("OK: row1 new pw is strong (len %d)" % len(newpw))
else:
    out("FAIL: new pw too short (%d)" % len(newpw)); fail = 1

# (d) release the prompt -> shred
os.write(master, b"\n")
try:
    proc.wait(timeout=15)
except subprocess.TimeoutExpired:
    proc.kill(); out("FAIL: commit did not exit after release"); fail = 1

if not os.path.exists(csv_path):
    out("OK: tmpfs CSV shredded (file gone)")
else:
    out("FAIL: CSV still present after shred"); fail = 1

sys.exit(1 if fail else 0)

#!/usr/bin/python3 -I
"""Manual WSL integration test: cancel one marked session and inspect only its resources."""
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time

if os.geteuid()!=0: raise SystemExit('Run as root with the configured regular user UID as argument.')
uid=int(sys.argv[1]);gid=int(subprocess.check_output(['id','-g',str(uid)],text=True))
marker='40.'+str(secrets.randbelow(999999))
process=subprocess.Popen(['setpriv','--reuid',str(uid),'--regid',str(gid),'--init-groups',
    '/usr/local/bin/tun','/usr/bin/sleep',marker],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
owned=None
try:
    for _ in range(100):
        namespaces=subprocess.check_output(['ip','netns','list'],text=True).splitlines()
        for line in namespaces:
            name=line.split()[0]
            if not name.startswith('tunit-'): continue
            pid=int(name.partition('-')[2]);path=Path('/proc')/str(pid)/'cmdline'
            if path.exists() and [b'/usr/bin/sleep',marker.encode()] == path.read_bytes().split(b'\0')[-3:-1]:
                owned=name,pid;break
        if owned: break
        time.sleep(.1)
    if not owned: raise RuntimeError('Marked session not found.')
    time.sleep(1)
    children=(Path('/proc')/str(owned[1])/'task'/str(owned[1])/'children').read_text().split()
    sessions=[Path('/run/tun-it')/p for p in children]
    os.kill(owned[1],signal.SIGTERM);process.wait(timeout=12)
    names=subprocess.check_output(['ip','netns','list'],text=True)
    success=owned[0] not in names and not (Path('/etc/netns')/owned[0]).exists() and all(not p.exists() for p in sessions)
    print(json.dumps({'cancel_cleanup_passed':success}));sys.exit(0 if success else 1)
finally:
    if process.poll() is None:
        if owned:
            try: os.kill(owned[1],signal.SIGTERM)
            except ProcessLookupError: pass
        process.terminate()

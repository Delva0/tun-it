#!/usr/bin/python3 -I
"""Root sets up one private namespace; no shared routes, sysctls or firewall edits."""
import ipaddress
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys

BASE = Path('/usr/local/lib/tun-it')


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def main():
    if os.geteuid() != 0 or 'SUDO_UID' not in os.environ:
        raise SystemExit('Use tun COMMAND as your regular user.')
    uid = int(os.environ['SUDO_UID'])
    config_path = Path('/etc/tun-it/users') / (str(uid)+'.json')
    config = json.loads(config_path.read_text())
    if config['uid'] != uid or not ipaddress.ip_address(config['gateway']).is_private:
        raise SystemExit('Invalid adapter identity or private gateway.')
    if not sys.argv[1:]:
        raise SystemExit('Usage: tun COMMAND [ARGUMENTS...]')
    namespace = 'tunit-'+str(os.getpid())
    resolver = Path('/etc/netns')/namespace
    slirp = child = None
    created = False
    def stop(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    try:
        run('ip','netns','add',namespace); created = True
        resolver.mkdir(parents=True, mode=0o755)
        (resolver/'resolv.conf').write_text('nameserver 1.1.1.1\noptions timeout:2 attempts:2\n')
        ready_read, ready_write = os.pipe()
        try:
            slirp = subprocess.Popen(['slirp4netns','--configure','--mtu=1400',
                '--disable-host-loopback','--enable-seccomp',
                '--netns-type=path','--ready-fd='+str(ready_write),
                '/run/netns/'+namespace,'tap0'],pass_fds=(ready_write,),
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            os.close(ready_write); ready_write = None
            if not select.select([ready_read],[],[],8)[0] or os.read(ready_read,1) != b'1':
                raise RuntimeError('Private network carrier did not become ready.')
        finally:
            os.close(ready_read)
            if ready_write is not None: os.close(ready_write)
        gateway = str(ipaddress.ip_address(config['gateway'])); port = int(config['port'])
        firewall = f'''table inet tun_it_session {{
 chain out {{ type filter hook output priority 0; policy drop;
  oifname "lo" accept
  oifname "tunit_tun" accept
  oifname "tap0" ip daddr {gateway} tcp dport {port} accept
  oifname "tap0" ip daddr {gateway} udp dport {port} accept
 }}
 chain in {{ type filter hook input priority 0; policy drop;
  iifname "lo" accept
  ct state established,related accept
 }}
}}'''
        run('ip','netns','exec',namespace,'nft','-f','-',input=firewall)
        # Do not inherit loader settings into a root helper.
        environment = {k:v for k,v in os.environ.items() if k not in
            ('LD_PRELOAD','LD_LIBRARY_PATH','PYTHONPATH','PYTHONHOME')}
        child = subprocess.Popen(['ip','netns','exec',namespace,str(BASE/'inside.py'),
            str(config_path),*sys.argv[1:]],cwd=os.getcwd(),env=environment)
        return child.wait()
    finally:
        if created:
            result = subprocess.run(['ip','netns','pids',namespace],capture_output=True,text=True)
            for pid in result.stdout.split():
                try: os.kill(int(pid),signal.SIGKILL)
                except ProcessLookupError: pass
        if child is not None:
            child.wait()
            shutil.rmtree(Path('/run/tun-it')/str(child.pid),ignore_errors=True)
        if slirp is not None and slirp.poll() is None:
            slirp.terminate()
            try: slirp.wait(timeout=3)
            except subprocess.TimeoutExpired: slirp.kill(); slirp.wait()
        if created:
            subprocess.run(['ip','netns','del',namespace],stderr=subprocess.DEVNULL)
        shutil.rmtree(resolver,ignore_errors=True)


if __name__ == '__main__':
    try: sys.exit(main())
    except KeyboardInterrupt: sys.exit(130)
    except Exception as error:
        sys.exit(type(error).__name__+': private session failed; no direct fallback.')

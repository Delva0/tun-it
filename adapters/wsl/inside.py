#!/usr/bin/python3 -I
"""Native private TUN; user applications have no proxy environment or root rights."""
import json
import os
from pathlib import Path
import pwd
import pty
import shlex
import subprocess
import sys
import time

BASE = Path('/usr/local/lib/tun-it')
PROXY_KEYS = ('http_proxy','https_proxy','all_proxy','no_proxy','HTTP_PROXY',
    'HTTPS_PROXY','ALL_PROXY','NO_PROXY','NODE_USE_ENV_PROXY')


def main():
    if os.geteuid() != 0 or os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
        raise SystemExit('Private namespace required.')
    config_path, *command = sys.argv[1:]
    config = json.loads(Path(config_path).read_text())
    subprocess.run(['mount','--make-rprivate','/'],check=True)
    # Disable Windows executable interop in this mount namespace only.
    if Path('/init').exists(): subprocess.run(['mount','--bind','/usr/bin/false','/init'],check=True)
    session = Path('/run/tun-it')/str(os.getpid())
    session.mkdir(parents=True,mode=0o700)
    core_config = {'log':{'level':'error'},
        'inbounds':[{'type':'tun','tag':'private-tun','interface_name':'tunit_tun',
            'address':['198.18.0.1/30'],'mtu':1400,'auto_route':True,'strict_route':True,
            'route_exclude_address':[config['gateway']+'/32'],'stack':'gvisor'}],
        'outbounds':[{'type':'shadowsocks','tag':'carrier','server':config['gateway'],
            'server_port':config['port'],'method':'chacha20-ietf-poly1305',
            'password':config['password'],'bind_interface':'tap0'}],
        'dns':{'servers':[{'type':'https','tag':'private-dns','server':config['dns_server'],
            'path':'/dns-query','detour':'carrier'}],'final':'private-dns','strategy':'ipv4_only'},
        'route':{'rules':[{'port':53,'action':'hijack-dns'}],'final':'carrier'}}
    path = session/'core.json'; path.write_text(json.dumps(core_config)); path.chmod(0o600)
    core = None
    try:
        subprocess.run([str(BASE/'sing-box'),'check','-c',str(path)],check=True)
        with (session/'core.log').open('w') as log:
            core = subprocess.Popen([str(BASE/'sing-box'),'run','-c',str(path)],stdout=log,stderr=log)
            for _ in range(50):
                if core.poll() is not None: raise RuntimeError('Private TUN failed to start.')
                if Path('/sys/class/net/tunit_tun').exists(): break
                time.sleep(0.1)
            else: raise RuntimeError('Private TUN not ready.')
            expected = config.get('expected_exit','')
            if command[0] == '--check-core-failure':
                core.terminate(); core.wait(timeout=5)
                command = [str(BASE/'probe.py'),expected,'failure']
            elif command[0] == '--check-carrier-failure':
                subprocess.run(['nft','insert','rule','inet','tun_it_session','out',
                    'ip','daddr',config['gateway'],'drop'],check=True)
                command = [str(BASE/'probe.py'),expected,'failure']
            elif command[0] == '--check':
                command = [str(BASE/'probe.py'),expected,'healthy']
            else:
                preflight = subprocess.run([str(BASE/'probe.py'),expected,'preflight'],
                    capture_output=True,text=True,timeout=15)
                if preflight.returncode:
                    raise RuntimeError('Target unavailable. Enable v2rayN TUN; no direct fallback.')
            account = pwd.getpwuid(config['uid'])
            environment = os.environ.copy()
            environment.update(HOME=account.pw_dir,USER=account.pw_name,LOGNAME=account.pw_name,
                SHELL=account.pw_shell or '/bin/bash',WSL_INTEROP='')
            for key in (*PROXY_KEYS,'SUDO_UID','SUDO_GID','SUDO_USER','SUDO_COMMAND',
                        'LD_PRELOAD','LD_LIBRARY_PATH','PYTHONPATH','PYTHONHOME'):
                environment.pop(key,None)
            privilege = ['setpriv','--reuid',str(config['uid']),'--regid',str(config['gid']),
                '--init-groups','--bounding-set=-all','--no-new-privs']
            if command[0] == str(BASE/'probe.py'):
                return subprocess.run(privilege+command,env=environment).returncode
            # Read the user's aliases/functions, then remove proxy settings from startup files.
            shell = account.pw_shell if Path(account.pw_shell).name in ('bash','zsh') else '/bin/bash'
            statement = 'unset '+' '.join(PROXY_KEYS)+'; '+shlex.join(command)
            os.environ.clear(); os.environ.update(environment)
            result = pty.spawn(privilege+[shell,'-ic',statement])
            return os.waitstatus_to_exitcode(result)
    finally:
        if core is not None and core.poll() is None:
            core.terminate()
            try: core.wait(timeout=5)
            except subprocess.TimeoutExpired: core.kill(); core.wait()
        for name in ('core.json','core.log'): (session/name).unlink(missing_ok=True)
        session.rmdir()


if __name__ == '__main__':
    try: sys.exit(main())
    except KeyboardInterrupt: sys.exit(130)
    except Exception as error:
        sys.exit(type(error).__name__+': protected command failed; no direct fallback.')

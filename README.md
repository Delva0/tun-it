# tun-it

Route selected environments through a dedicated **v2rayN GUI node** on Windows. Keep ordinary Windows traffic on the node currently selected in v2rayN.

`tun` is a general WSL command launcher. It uses native sockets in a private Linux TUN/network namespace. It does not depend on application HTTP/SOCKS proxy settings or proxy environment variables.

```text
Android emulator / supported process adapter -> Windows v2rayN TUN -> dedicated GUI target
WSL: tun COMMAND -> private TUN -> encrypted local carrier -> Windows v2rayN TUN target
Other Windows traffic -> v2rayN's currently selected ordinary node
```

The remote target may implement its own multi-hop route. Configure that route on the server; tun-it preserves it rather than managing remote servers or proxy purchases.

## Requirements

- Windows 10/11, PowerShell 7.2+, Python 3.10+, Windows Firewall enabled on every profile.
- An initialized v2rayN installation with its sing-box core and a working ordinary node. Tested with v2rayN **7.20.2** and sing-box **1.13.7**. Other versions must pass database-schema and core validation before changes are applied.
- WSL adapter: **WSL2 with NAT networking**, a regular default user, Python 3, sudo, iproute2, nftables, util-linux, bash and slirp4netns. Tested on Ubuntu 22.04 and Ubuntu 24.04. The adapter contains no Ubuntu-version or user-name assumptions. Dependency installation supports apt, dnf and apk, but those other distributions are not yet integration-tested. WSL1 and mirrored networking are not supported.
- Android adapter: an existing Windows x64 Android SDK emulator and AVD. It attaches network rules without reinstalling Android, modifying its VPN settings, or deleting AVD data.

## Interactive deployment

Clone or download this repository, then run from Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\Deploy.ps1
```

The single deployment script opens in PowerShell 7 (and can install it through winget), asks for the v2rayN folder and Python path, then lets you:

1. Select an existing GUI target or paste a hidden **VLESS, VMess, Trojan or SIP002 Shadowsocks share URI**. Import creates a normal editable v2rayN GUI node. Supported transports are TCP/raw, WebSocket, gRPC and HTTPUpgrade; Shadowsocks plugins are unsupported.
2. Optionally pin an expected public IPv4 address for command preflight checks.
3. Attach an existing Android emulator and/or choose any supported WSL2 distributions.
4. Enable native TUN, validate a candidate, install guards and routing, restart v2rayN immediately, and check connectivity. An unsuccessful host sync restores the previous template and GUI settings, retaining protection until the error is resolved.

Administrator UAC is needed for host networking changes. WSL packages are installed as root when `-InstallDependencies` is used. Linux sing-box is downloaded from the official pinned release and its GitHub asset SHA-256 is checked. No credentials are printed or passed as command-line arguments.

Private configuration and backups live at **`%LOCALAPPDATA%\tun-it`**, restricted to the current Windows user, SYSTEM and Administrators. The source repository contains no live server configuration. Supply `-StatePath` to use another private location; one installation per v2rayN instance is supported.

## Commands

In an installed WSL distribution:

```bash
tun --help
tun curl https://example.com
tun python3 my_script.py --argument value
tun bash
tun --check
tun --check-core-failure
tun --check-carrier-failure
```

The launcher reads bash/zsh aliases and functions. Arguments remain quoted, the user's UID/GID and working directory are preserved, inherited proxy variables are removed after shell startup, and the command runs without root privileges or capabilities. The protected unit is the foreground command and its descendants. Existing background services, separately running supervisors, and the whole distribution are outside that unit. Windows executable interop is disabled within the private mount namespace to prevent an accidental host-network bypass.

On Windows:

```powershell
.\TunIt.ps1 -Action Status
.\TunIt.ps1 -Action Plan
.\TunIt.ps1 -Action Sync
.\TunIt.ps1 -Action Verify
.\TunIt.ps1 -Action StartAndroid
```

Edit the dedicated target in **v2rayN's GUI**, then run `Sync` to update owned TUN routes. Selecting another ordinary node in v2rayN does not change the isolated target. Ordinary non-TUN configuration is preserved. If you change v2rayN's underlying TUN/DNS settings, remove the adapters and deploy again to capture a fresh native baseline.

After WSL NAT addresses change, run `Sync` before using `tun`. The WSL listener uses a wildcard IPv4 bind so that an absent WSL adapter cannot prevent ordinary Windows TUN startup; explicit firewall blocks restrict it to the verified WSL host address and subnet. Stale WSL settings fail closed until refreshed. Every installed distribution receives the updated gateway automatically during sync.

## Independent adapters

Install or uninstall adapters without removing the other adapter:

```powershell
.\adapters\android\Adapter.ps1 -Action Install -Sdk 'D:\Android\Sdk' -AvdHome 'D:\Android\avd' -Avd MyDevice -EnableTun
.\adapters\android\Adapter.ps1 -Action Start
.\adapters\android\Adapter.ps1 -Action Uninstall

.\adapters\wsl\Adapter.ps1 -Action Install -Distribution Ubuntu-24.04 -InstallDependencies -EnableTun
.\adapters\wsl\Adapter.ps1 -Action Uninstall -Distribution Ubuntu-24.04
```

Run `Deploy.ps1` once for the common host configuration before installing individual adapters. Close the Android emulator before uninstalling its guards. Close protected command sessions before changing/removing their Linux helper. Uninstallation removes owned helpers, sudoers entries, routes and guards, retaining private rollback files; it does not remove system packages, user files or imported GUI nodes.

## Process and VM extension

The shared process adapter accepts exact executable paths in the private `config.json`:

```json
"process_adapters": [
  {"id": "example-client", "enabled": true, "executables": ["D:\\Apps\\Example\\example.exe"]}
]
```

Add the adapter, close its programs, and run `Sync`. Disable it and sync to remove its owned routes/guards. A VM is eligible only if **all its traffic is emitted by identifiable configured host processes**, as with the Android emulator's user-mode NAT. Bridged adapters, Hyper-V switches, services and WSL's shared kernel do not necessarily expose the originating guest process; they require a separate interface/source-based adapter. Process rules are not advertised as a universal VM capture mechanism.

## Failure behavior and removal

| State | Protected Android/processes | `tun` command |
| --- | --- | --- |
| v2rayN TUN on, target healthy | Dedicated target | Dedicated target |
| TUN off | Offline | Preflight fails / network blocked |
| v2rayN exited | Offline | Network blocked |
| Target, private core or carrier fails | No direct fallback | No direct fallback |

Each command has a private network/mount namespace, a TUN, encrypted TCP/UDP carrier and a default-drop nftables policy allowing only the carrier endpoint and TUN. DNS is hijacked to encrypted DNS through that target; IPv6 is blocked. Slirp userspace NAT avoids shared forwarding/sysctl/iptables edits. Its seccomp option is enabled; the optional slirp mount sandbox is intentionally disabled for WSL compatibility. Session cancellation removes owned processes, namespace, resolver files and temporary credentials.

Whole host removal:

```powershell
.\TunIt.ps1 -Action Remove
```

Close every protected process first. Removal restores the saved original TUN template and removes only tun-it's firewall group and Linux command entries. It preserves ordinary node selection, imported/adopted GUI nodes and rollback files.

## Validation

```powershell
python -m unittest discover -s tests -v
pwsh -File tests\Parse-PowerShell.ps1
```

On an installed WSL adapter, run the three `tun --check*` modes above. For SIGTERM cleanup, run as root with the configured user's UID:

```bash
sudo python3 tests/check_cleanup.py "$(id -u)"
```

CI verifies the configuration engine and PowerShell/shell syntax. Host routing and fail-closed behavior require live Windows/WSL/emulator checks; CI does not emulate that network stack. Use browser DNS and WebRTC checks inside the actual protected application, and assess exit IP classification separately. An exit's IP classification is determined by the provider and checker, not by this launcher.

## Dependencies

This project's code is MIT licensed. It integrates separately installed [v2rayN](https://github.com/2dust/v2rayN), [sing-box](https://github.com/SagerNet/sing-box), [slirp4netns](https://github.com/rootless-containers/slirp4netns), Linux networking tools and optionally the Android SDK. Their respective licenses apply; third-party binaries and credentials are not bundled in this repository.

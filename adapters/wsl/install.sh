#!/bin/bash
set -euo pipefail
test "$(id -u)" = 0
source_root=$1
runtime=$2
binary=$3
for tool in ip nft setpriv visudo python3 mount sudo slirp4netns; do command -v "$tool" >/dev/null || { echo "Missing dependency: $tool" >&2; exit 1; }; done
test -c /dev/net/tun
uid=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["uid"])' "$runtime")
user=$(getent passwd "$uid" | cut -d: -f1)
test -n "$user" && test "$uid" != 0
[[ "$user" =~ ^[a-zA-Z_][a-zA-Z0-9_-]*\$?$ ]]
if test -e /usr/local/bin/tun && ! grep -q 'tun-it managed command entry' /usr/local/bin/tun; then
  echo 'An unrelated tun command exists; preserved.' >&2; exit 1
fi
if ip netns list | grep -q '^tunit-'; then echo 'Close protected sessions before installing.' >&2; exit 1; fi
target=/usr/local/lib/tun-it
install -d -m 755 "$target" /etc/tun-it/users
for script in enter.py inside.py probe.py; do install -o root -g root -m 755 "$source_root/adapters/wsl/$script" "$target/$script"; done
install -o root -g root -m 755 "$binary" "$target/sing-box"
install -o root -g root -m 600 "$runtime" "/etc/tun-it/users/$uid.json"
install -o root -g root -m 755 "$source_root/adapters/wsl/tun" /usr/local/bin/tun
printf '%s ALL=(root) NOPASSWD: /usr/local/lib/tun-it/enter.py\n' "$user" > "$target/sudoers.staged"
chmod 440 "$target/sudoers.staged"
visudo -cf "$target/sudoers.staged" >/dev/null
install -o root -g root -m 440 "$target/sudoers.staged" "/etc/sudoers.d/tun-it-$uid"
rm -f "$target/sudoers.staged"
echo 'Installed tun for the selected distribution and user.'

#!/bin/bash
set -euo pipefail
test "$(id -u)" = 0
uid=$1
[[ "$uid" =~ ^[0-9]+$ ]]
if ip netns list | grep -q '^tunit-'; then echo 'Close protected sessions before uninstalling.' >&2; exit 1; fi
rm -f "/etc/tun-it/users/$uid.json" "/etc/sudoers.d/tun-it-$uid"
if ! find /etc/tun-it/users -name '*.json' -print -quit 2>/dev/null | grep -q .; then
  if grep -q 'tun-it managed command entry' /usr/local/bin/tun 2>/dev/null; then rm -f /usr/local/bin/tun; fi
  for name in enter.py inside.py probe.py sing-box; do rm -f "/usr/local/lib/tun-it/$name"; done
  rmdir /usr/local/lib/tun-it /etc/tun-it/users /etc/tun-it 2>/dev/null || true
fi
echo 'Removed tun; shared WSL networking and user files were preserved.'

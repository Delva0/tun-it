#!/bin/sh
set -eu
test "$(id -u)" = 0
if command -v apt-get >/dev/null; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iproute2 nftables util-linux sudo python3 bash slirp4netns ca-certificates
elif command -v dnf >/dev/null; then
  dnf install -y iproute nftables util-linux sudo python3 bash slirp4netns ca-certificates
elif command -v apk >/dev/null; then
  apk add iproute2 nftables util-linux sudo python3 bash slirp4netns ca-certificates
else
  echo 'Install iproute2, nftables, util-linux, sudo, Python 3, bash and slirp4netns using your package manager.' >&2
  exit 1
fi

#!/bin/sh
# The node identity and last-known-good configuration stay in
# /var/lib/edgeweir-node unless the package is purged (deb).
set -e
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi
if [ "$1" = "purge" ]; then
  rm -rf /var/lib/edgeweir-node /var/cache/edgeweir-node
fi

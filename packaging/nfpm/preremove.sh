#!/bin/sh
# Stop the service on removal (deb: "remove"/"purge", rpm: $1 = 0), not on
# upgrade.
set -e
case "$1" in
  remove|purge|0)
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
      systemctl disable --now edgeweir-node.service || true
      systemctl disable --now edgeweir-probe.service || true
    fi
    ;;
esac

#!/bin/sh
# Create state/cache directories and reload systemd. The service is not
# enabled automatically: the node must be enrolled first.
set -e
install -d -o edgeweir -g edgeweir -m 0700 /var/lib/edgeweir-node
install -d -o edgeweir -g edgeweir -m 0750 /var/cache/edgeweir-node
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
  # Upgrades: restart a running node (or probe) with the new binary.
  systemctl try-restart edgeweir-node.service || true
  systemctl try-restart edgeweir-probe.service || true
fi
cat <<'MSG'
edgeweir-node is installed. Next steps (the console's install.sh does this for you):
  export EDGEWEIR_TOKEN='<token>'   # or --token-file PATH; --token would show it in ps
  sudo --preserve-env=EDGEWEIR_TOKEN edgeweir-node enroll --server https://<console>:8443 --ca-sha256 <sha256>
  sudo systemctl enable --now edgeweir-node.service
The node runs /usr/lib/edgeweir-openresty itself; an openresty.service of
OpenResty's own packages, if any, must stay disabled.
MSG

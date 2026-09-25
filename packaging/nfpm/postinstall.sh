#!/bin/sh
# Create state/cache directories and reload systemd. The service is not
# enabled automatically: the node must be enrolled first.
set -e
install -d -o edgeweir -g edgeweir -m 0700 /var/lib/edgeweir-node
install -d -o edgeweir -g edgeweir -m 0750 /var/cache/edgeweir-node
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
  # Upgrades: restart a running node with the new binary.
  systemctl try-restart edgeweir-node.service || true
fi
cat <<'MSG'
edgeweir-node is installed. Next steps (the console's install.sh does this for you):
  sudo edgeweir-node enroll --server https://<console>:8443 --token <token> --ca-sha256 <sha256>
  sudo systemctl disable --now openresty.service 2>/dev/null || true
  sudo systemctl enable --now edgeweir-node.service
MSG

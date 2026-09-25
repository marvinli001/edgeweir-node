#!/bin/sh
# Create the unprivileged service user.
set -e
if ! getent group edgeweir >/dev/null 2>&1; then
  groupadd --system edgeweir
fi
if ! getent passwd edgeweir >/dev/null 2>&1; then
  nologin=$(command -v nologin 2>/dev/null || echo /bin/false)
  useradd --system --gid edgeweir --home-dir /var/lib/edgeweir-node --no-create-home \
    --shell "$nologin" --comment "Edgeweir edge node" edgeweir
fi

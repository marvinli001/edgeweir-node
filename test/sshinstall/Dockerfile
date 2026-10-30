# Host image of the SSH install test (test/sshinstall): a fresh Debian
# server with sshd, sudo and what install.sh needs, no systemd. Also the
# SSH client and the test console's runtime. Never published.
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openssh-server openssh-client sudo curl openssl ca-certificates procps \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /root/.ssh \
 && chmod 0700 /root/.ssh \
 # deploy: passwordless sudo; pwuser: sudo asks for a password.
 && useradd -m -s /bin/bash deploy && useradd -m -s /bin/bash pwuser \
 && echo 'pwuser:pw-secret-test' | chpasswd \
 && echo 'deploy ALL=(ALL) NOPASSWD:ALL' >/etc/sudoers.d/deploy \
 && echo 'pwuser ALL=(ALL) ALL' >/etc/sudoers.d/pwuser \
 && chmod 0440 /etc/sudoers.d/* \
 && printf 'PermitRootLogin prohibit-password\nPasswordAuthentication no\nAcceptEnv none\n' >/etc/ssh/sshd_config.d/test.conf
# The client's key is installed at start (run.sh mounts /keys).
CMD ["sh", "-c", "for u in root deploy pwuser; do h=$(getent passwd $u | cut -d: -f6); install -d -o $u -m 0700 $h/.ssh; install -o $u -m 0600 /keys/id_ed25519.pub $h/.ssh/authorized_keys; done; ssh-keygen -A >/dev/null; exec /usr/sbin/sshd -D -e"]

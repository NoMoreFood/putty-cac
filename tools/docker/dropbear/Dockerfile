# Dockerized Dropbear server for cross-implementation SSH interoperability tests.
# Dropbear is independent of the OpenSSH-derived PKIX-SSH server used for the
# RFC 6187 tests, so successful authentication here guards the standard raw-key
# paths against implementation-specific assumptions.

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        dropbear-bin \
        openssh-client \
        openssh-sftp-server \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/sh testuser \
    && echo "testuser:test" | chpasswd \
    && install -d -m 700 -o testuser -g testuser /home/testuser/.ssh \
    && install -m 600 -o testuser -g testuser /dev/null /home/testuser/.ssh/authorized_keys \
    && install -d -m 755 /etc/dropbear \
    && dropbearkey -t rsa -s 3072 -f /etc/dropbear/dropbear_rsa_host_key \
    && dropbearkey -t ecdsa -s 256 -f /etc/dropbear/dropbear_ecdsa_host_key \
    && dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key

EXPOSE 2223

# -F: foreground, -E: stderr logging, -s: disable password logins,
# -w: disallow root logins, -p: listen on the dedicated test port.
ENTRYPOINT ["/usr/sbin/dropbear", "-F", "-E", "-s", "-w", "-p", "0.0.0.0:2223", "-r", "/etc/dropbear/dropbear_rsa_host_key", "-r", "/etc/dropbear/dropbear_ecdsa_host_key", "-r", "/etc/dropbear/dropbear_ed25519_host_key"]

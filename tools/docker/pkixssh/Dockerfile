# Dockerfile for PKIX-SSH sshd with x509v3-ssh-rsa support
# Used by Test-PuTTYCAC.ps1 to test X.509v3 certificate authentication
#
# Build:  docker build -t pkixssh-test .
# Run:    docker run -d -p 2222:2222 -v /path/to/authorized_keys:/authorized_keys:ro pkixssh-test

FROM debian:bookworm-slim AS builder

ARG PKIXSSH_VERSION=18.0.3

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        libssl-dev \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

RUN curl -fsSL "https://www.roumenpetrov.info/openssh/src/pkixssh-${PKIXSSH_VERSION}.tar.gz" \
        -o pkixssh.tar.gz \
    && tar -xf pkixssh.tar.gz \
    && cd "pkixssh-${PKIXSSH_VERSION}" \
    && ./configure --prefix=/opt/pkixssh --with-privsep-path=/var/empty \
    && make -j"$(nproc)" \
    && make install

# --- Runtime stage ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 \
        zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/pkixssh /opt/pkixssh

# Create privilege-separation directory, sshd privsep user, and test user
RUN mkdir -p /var/empty && chmod 755 /var/empty \
    && useradd -r -d /var/empty -s /usr/sbin/nologin sshd \
    && useradd -m -s /bin/sh testuser \
    && echo "testuser:test" | chpasswd \
    && mkdir -p /home/testuser/.ssh \
    && chmod 700 /home/testuser/.ssh \
    && chown -R testuser:testuser /home/testuser/.ssh \
    && mkdir -p /etc/pkixssh

# Generate host keys
RUN /opt/pkixssh/bin/ssh-keygen -t rsa     -f /etc/pkixssh/ssh_host_rsa_key     -N "" \
    && /opt/pkixssh/bin/ssh-keygen -t ecdsa   -f /etc/pkixssh/ssh_host_ecdsa_key   -N "" \
    && /opt/pkixssh/bin/ssh-keygen -t ed25519 -f /etc/pkixssh/ssh_host_ed25519_key -N ""

# Write sshd_config
RUN printf '%s\n' \
    "Port 2222" \
    "ListenAddress 0.0.0.0" \
    "HostKey /etc/pkixssh/ssh_host_rsa_key" \
    "HostKey /etc/pkixssh/ssh_host_ecdsa_key" \
    "HostKey /etc/pkixssh/ssh_host_ed25519_key" \
    "StrictModes no" \
    "AuthorizedKeysFile /authorized_keys" \
    "PubkeyAuthentication yes" \
    "PasswordAuthentication no" \
    "KbdInteractiveAuthentication no" \
    "KeyAllowSelfIssued yes" \
    "PermitRootLogin no" \
    "AllowUsers testuser" \
    "Subsystem sftp /opt/pkixssh/libexec/sftp-server" \
    "LogLevel DEBUG" \
    > /etc/pkixssh/sshd_config

# Entrypoint: copy the mounted authorized_keys and start sshd in foreground
# The authorized_keys file is bind-mounted at /authorized_keys (read-only)
EXPOSE 2222

ENTRYPOINT ["/opt/pkixssh/sbin/sshd", "-D", "-e", "-f", "/etc/pkixssh/sshd_config"]

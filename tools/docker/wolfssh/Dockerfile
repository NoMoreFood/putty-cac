# wolfSSH server built with RFC 6187 X.509 certificate authentication.
# This complements the OpenSSH-derived PKIX-SSH server with an independent
# SSH protocol and certificate-validation implementation.

FROM debian:bookworm-slim AS builder

ARG WOLFSSL_VERSION=5.9.2
ARG WOLFSSH_VERSION=1.5.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        autoconf \
        automake \
        build-essential \
        ca-certificates \
        curl \
        libtool \
        openssh-client \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

RUN curl -fsSL "https://github.com/wolfSSL/wolfssl/archive/refs/tags/v${WOLFSSL_VERSION}-stable.tar.gz" \
        -o wolfssl.tar.gz \
    && tar -xf wolfssl.tar.gz \
    && mv "wolfssl-${WOLFSSL_VERSION}-stable" wolfssl

WORKDIR /build/wolfssl

RUN ./autogen.sh \
    && ./configure \
        --prefix=/opt/wolfssl \
        --disable-shared \
        --enable-static \
        --disable-mlkem \
        --enable-wolfssh \
    && make -j"$(nproc)" \
    && make install

WORKDIR /build

RUN curl -fsSL "https://github.com/wolfSSL/wolfssh/archive/refs/tags/v${WOLFSSH_VERSION}-stable.tar.gz" \
        -o wolfssh.tar.gz \
    && tar -xf wolfssh.tar.gz \
    && mv "wolfssh-${WOLFSSH_VERSION}-stable" wolfssh

WORKDIR /build/wolfssh

RUN ./autogen.sh \
    && PKG_CONFIG_PATH=/opt/wolfssl/lib/pkgconfig \
       CPPFLAGS="-I/opt/wolfssl/include -DWOLFSSH_NO_SHA1_SOFT_DISABLE" \
       LDFLAGS="-L/opt/wolfssl/lib" \
       ./configure \
        --prefix=/opt/wolfssh \
        --disable-shared \
        --enable-static \
        --enable-certs \
        --enable-scp \
        --enable-sftp \
        --enable-sshd \
    && make -j"$(nproc)" \
    && install -d /opt/wolfssh/sbin /opt/wolfssh/etc \
    && install -m 755 apps/wolfsshd/wolfsshd /opt/wolfssh/sbin/wolfsshd \
    && install -m 600 keys/server-key.pem /opt/wolfssh/etc/server-key.pem \
    && ssh-keygen -y -f /opt/wolfssh/etc/server-key.pem \
        > /opt/wolfssh/etc/server-key.pub

FROM debian:bookworm-slim

RUN install -d -m 755 /var/empty \
    && useradd -r -d /var/empty -s /usr/sbin/nologin sshd \
    && useradd -m -s /bin/sh testuser \
    && echo "testuser:test" | chpasswd \
    && install -d -m 755 /etc/wolfssh

COPY --from=builder /opt/wolfssh/sbin/wolfsshd /usr/local/sbin/wolfsshd
COPY --from=builder /opt/wolfssh/etc/server-key.pem /etc/wolfssh/server-key.pem
COPY --from=builder /opt/wolfssh/etc/server-key.pub /etc/wolfssh/server-key.pub

RUN touch /etc/wolfssh/client-ca.pem \
    && printf '%s\n' \
        'Port 2224' \
        'Protocol 2' \
        'LoginGraceTime 60' \
        'PermitRootLogin no' \
        'PasswordAuthentication no' \
        'PermitEmptyPasswords no' \
        'UsePrivilegeSeparation no' \
        'UseDNS no' \
        'TrustedUserCAKeys /etc/wolfssh/client-ca.pem' \
        'HostKey /etc/wolfssh/server-key.pem' \
        > /etc/wolfssh/sshd_config

EXPOSE 2224

ENTRYPOINT ["/usr/local/sbin/wolfsshd", "-D", "-d", "-f", "/etc/wolfssh/sshd_config"]

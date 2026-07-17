# AsyncSSH server for independent RFC 6187 X.509 interoperability tests.
# AsyncSSH is a Python SSH implementation and therefore exercises protocol,
# certificate-chain, command, SCP, and SFTP paths independent of PKIX-SSH and
# wolfSSH.

FROM python:3.12-slim-bookworm

ARG ASYNCSSH_VERSION=2.24.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir "asyncssh[pyOpenSSL]==${ASYNCSSH_VERSION}"

RUN useradd -m -s /bin/sh testuser \
    && install -d -m 755 /etc/asyncssh /opt/asyncssh \
    && ssh-keygen -q -t ed25519 -N '' -f /etc/asyncssh/ssh_host_ed25519_key \
    && touch /etc/asyncssh/client-ca.pem /etc/asyncssh/authorized_keys \
    && chmod 600 /etc/asyncssh/ssh_host_ed25519_key \
    && chmod 644 /etc/asyncssh/ssh_host_ed25519_key.pub \
        /etc/asyncssh/client-ca.pem /etc/asyncssh/authorized_keys \
    && chown testuser:testuser /etc/asyncssh/ssh_host_ed25519_key \
    && chown -R testuser:testuser /home/testuser

COPY server.py /opt/asyncssh/server.py

USER testuser
WORKDIR /home/testuser

EXPOSE 2225 2226 2227 2228 2229

ENTRYPOINT ["python", "-u", "/opt/asyncssh/server.py"]

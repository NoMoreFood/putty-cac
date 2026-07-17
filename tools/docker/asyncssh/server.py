#!/usr/bin/env python3

"""Isolated AsyncSSH RFC 6187 interoperability test server."""

import asyncio
import logging
import sys
from typing import Optional

import asyncssh


HOST_KEY = "/etc/asyncssh/ssh_host_ed25519_key"
CLIENT_CA = "/etc/asyncssh/client-ca.pem"
AUTHORIZED_KEYS = "/etc/asyncssh/authorized_keys"
AUTHORIZED_USER = "testuser"

# Each listener advertises exactly one X.509 user-authentication algorithm.
# ssh-ed25519 remains present only so the shared raw host key can sign key
# exchange; it cannot authenticate any of the RSA/ECDSA client certificates.
LISTENERS = (
    (2225, "x509v3-rsa2048-sha256"),
    (2226, "x509v3-ssh-rsa"),
    (2227, "x509v3-ecdsa-sha2-nistp256"),
    (2228, "x509v3-ecdsa-sha2-nistp384"),
    (2229, "x509v3-ecdsa-sha2-nistp521"),
)


class X509TestServer(asyncssh.SSHServer):
    """Apply the generated subject authorization only to the test account."""

    def __init__(self) -> None:
        self._conn: Optional[asyncssh.SSHServerConnection] = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn

    def begin_auth(self, username: str) -> bool:
        if username == AUTHORIZED_USER:
            assert self._conn is not None
            self._conn.set_authorized_keys(AUTHORIZED_KEYS)

        return True

    def public_key_auth_supported(self) -> bool:
        return True


def handle_process(process: asyncssh.SSHServerProcess[str]) -> None:
    """Provide the single command required by the interoperability tests."""

    if process.command == "whoami":
        process.stdout.write(f"{AUTHORIZED_USER}\n")
        process.exit(0)
    else:
        process.stderr.write("Only the test command is supported.\n")
        process.exit(127)


async def start_server() -> None:
    listeners = []

    for port, algorithm in LISTENERS:
        listener = await asyncssh.listen(
            "0.0.0.0",
            port,
            server_factory=X509TestServer,
            server_host_keys=[HOST_KEY],
            x509_trusted_certs=[CLIENT_CA],
            x509_purposes=["clientAuth"],
            signature_algs=[algorithm, "ssh-ed25519"],
            host_based_auth=False,
            password_auth=False,
            kbdint_auth=False,
            gss_host=None,
            process_factory=handle_process,
            sftp_factory=True,
            allow_scp=True,
        )
        listeners.append(listener)
        print(f"Listening on port {port} for {algorithm}", flush=True)

    await asyncio.Future()


logging.basicConfig(level=logging.DEBUG, format="%(levelname)s:%(name)s:%(message)s")
asyncssh.set_log_level(logging.DEBUG)
asyncssh.set_debug_level(1)

try:
    asyncio.run(start_server())
except (OSError, asyncssh.Error) as exc:
    sys.exit(f"AsyncSSH server failed: {exc}")

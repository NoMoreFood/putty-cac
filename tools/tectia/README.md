# SSH Tectia Server interoperability target

`Test-PuTTYCAC.ps1` can exercise PuTTY-CAC against an installed SSH Tectia
Server 7.0 evaluation. The Tectia installer and evaluation license remain
external to this repository.

## One-time local setup

Install Tectia Server, reboot Windows as required by its installer, and then
run the initializer from an elevated PowerShell 7 session:

```powershell
pwsh ./tools/tectia/Initialize-TectiaTestServer.ps1
```

The initializer:

- creates a persistent `PuTTYCAC Tectia Test Root` CA in the current user's
  certificate store;
- exports only its public certificate under
  `%ProgramData%\PuTTYCAC-Test\Tectia`;
- backs up the existing `ssh-server-config.xml`;
- validates the generated configuration against Tectia's installed DTD;
- adds four loopback-only listeners on ports 2230 through 2233; and
- restarts Tectia, rolling back automatically if the listeners do not start.

Each listener accepts exactly one client public-key algorithm:

| Port | Algorithm |
| ---: | --- |
| 2230 | `x509v3-rsa2048-sha256` |
| 2231 | `x509v3-ecdsa-sha2-nistp256` |
| 2232 | `x509v3-ecdsa-sha2-nistp384` |
| 2233 | `x509v3-ecdsa-sha2-nistp521` |

Tectia Server 7.0 does not offer the legacy `x509v3-ssh-rsa` algorithm for
user authentication. That variant remains covered by the suite's PKIX-SSH,
wolfSSH, and AsyncSSH targets.

The listeners bind only to `127.0.0.1`; the initializer preserves existing
listeners and authentication rules.

## Run the live tests

```powershell
pwsh ./tools/Test-PuTTYCAC.ps1 `
    -TectiaHost 127.0.0.1 `
    -TectiaUser "$env:COMPUTERNAME\$env:USERNAME"
```

`-TectiaBasePort` defaults to 2230. `-TectiaHostKey` can contain one or more
console-verified SHA-256 fingerprints. When omitted, the suite discovers the
fingerprint reported by Tectia; explicit pinning is preferable for a remote
test host.

The suite creates short-lived RSA and ECDSA certificates under the persistent
test root, authenticates a real `whoami` command on every exclusive listener,
and verifies that Tectia rejects a username-matching certificate from an
untrusted issuer. The short-lived certificates are removed during normal suite
cleanup.

## Restore the previous Tectia configuration

From an elevated PowerShell 7 session:

```powershell
pwsh ./tools/tectia/Initialize-TectiaTestServer.ps1 -Restore
```

This restores the pre-PuTTY-CAC XML backup and restarts Tectia. The test CA is
left in the current-user certificate store so the target can be initialized
again without changing its trust identity.

## Product documentation

The evaluation archive includes `TectiaServer_AdminManual.pdf`. Sections 3.1.3
and 5.7 document Windows service control and X.509 user authentication. Current
manuals are also available from [SSH Communications Security](https://docs.ssh.com/).

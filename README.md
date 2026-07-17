# PuTTY CAC
PuTTY CAC is a fork of PuTTY, a popular Secure Shell (SSH) terminal. It adds support for using the Windows Certificate API (CAPI), PKCS #11 libraries, and Fast Identity Online (FIDO) authenticators to perform SSH public key authentication.

PuTTY CAC works with many types of cryptographic authenticators, including YubiKeys and common smart card models. On Windows 11, FIDO support can also use compatible phone-based authenticators on Android and iPhone through Windows' built-in passkey/FIDO2 integration. The "CAC" in "PuTTY CAC" refers to Common Access Card, a smart card used in US Government facilities and one of the original drivers behind this project.

PuTTY CAC is maintained independently of the US Government by the open source community.

You can download the latest release of PuTTY CAC here: https://github.com/NoMoreFood/putty-cac/releases

PuTTY CAC source code and binaries are free to use for any purpose. The license can be found here: https://github.com/NoMoreFood/putty-cac/blob/master/code/LICENCE

## Prerequisites
* Microsoft Windows 10 or later
* For CAPI support, install an appropriate Windows smart card mini-driver. This is typically provided by the smart card manufacturer, though many common hardware tokens are supported by OpenSC.
* For PKCS support, install a PKCS #11 library (typically a DLL file) to interface with the hardware token. This is typically provided by the smart card manufacturer, though many common hardware tokens are supported by OpenSC.
* For FIDO support, use a FIDO authenticator supported by Windows. On Windows 11, this can include compatible phone-based authenticators (Android/iPhone) in addition to physical hardware keys.

## Usage
You can find basic usage instructions on the US Government ID Management website under the "SSH Using PuTTY-CAC" section:

[https://www.idmanagement.gov/implement/scl-ssh](https://www.idmanagement.gov/implement/scl-ssh/)

## Command Line Usage
PuTTY CAC supports the same command line options as PuTTY, plus additional PuTTY CAC-specific options.

For any PuTTY utility, you can use a certificate thumbprint or application identifier in place of a PuTTY key file path. For example:
* Connect to user@host using the certificate with thumbprint '716B8B58D8F2C3A7F98F3F645161B1BF9818B689' from the user certificate store:  
`putty.exe user@host -i CAPI:716B8B58D8F2C3A7F98F3F645161B1BF9818B689`
* Connect to user@host using the certificate with thumbprint 'B8B58D8F2C3A7F98F3F645161B1BF9818B689716' and PKCS library 'PKCS.dll':  
`putty.exe user@host -i PKCS:B8B58D8F2C3A7F98F3F645161B1BF9818B689716=C:\PKCS.dll`  
* Connect to user@host using the FIDO key identified by 'ssh:MyFidoKey' from the PuTTY CAC FIDO key cache:  
`putty.exe user@host -i FIDO:ssh:MyFidoKey`

PuTTY executables (putty.exe, pageant.exe, psftp.exe) support the following additional command line options. Most of these options are focused on Pageant behavior and can also be set from its user interface. Once set, these options apply automatically to subsequent executions unless explicitly unset. Settings that filter Pageant certificate selection dialogs also affect certificate selection dialogs in the standard PuTTY application:
* Automatically load any compatible CAPI certificates at startup: `-autoload`,`-autoloadoff`
* Save key list between PuTTY executions: `-savecertlist`,`-savecertlistoff`
* Enable supplementary PIN caching in Pageant: `-forcepincache`,`-forcepincacheoff`
* Prompt when certificate signing operation is requested: `-certauthprompting`,`-certauthpromptingoff`
* Attempt X.509v3 certificate authentication when the server advertises it per RFC 6187: `-x509`,`-x509off`
* Only display trusted certificates in certificate selection dialogs: `-trustedcertsonly`,`-trustedcertsonlyoff`
* Do not display expired certificates in certificate selection dialogs: `-ignoreexpiredcerts`,`-ignoreexpiredcertsoff`
* Disable all filtering in certificate selection dialogs: `-allowanycert`,`-allowanycertoff`

## Special Considerations
### Certificates
For PuTTY CAC, a certificate is simply a convenient way to reference a private/public key pair. If you want to use PuTTY CAC to securely log on to your system and do not have access to a Certificate Authority (CA), the certificate can be self-signed. Conversely, PuTTY CAC can be used with managed SSH servers to enforce multifactor authentication. This can be done by ensuring that the OpenSSH authorized_keys file only contains public keys associated with approved authenticators (for example, hardware tokens or managed FIDO devices), either procedurally or by creating an index of all issued certificates and looking them up through OpenSSH directives such as AuthorizedKeysCommand.
### Federal Information Processing Standards (FIPS) Compliance
The code used to interface with the hardware token relies on Microsoft cryptographic libraries, which are governed by system-level FIPS settings (see [Microsoft's website](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/system-cryptography-use-fips-compliant-algorithms-for-encryption-hashing-and-signing)). Similarly, the hardware token used for signing authentication challenges is guaranteed to use FIPS-compliant algorithms if the hardware key is FIPS certified; see the hardware token manufacturer's website for more information. PuTTY itself uses proprietary encryption and hashing once the SSH session is established, and this has not undergone evaluation for FIPS compliance or certification.
## Notes On Building PuTTY CAC
### Prerequisites
* Visual Studio 2026 with C++ Desktop Application Development
* WiX Toolset (to build the MSI files)
* Windows PowerShell (to build the MSI/ZIP/Hash files)

### Building
* Execute 'packager\build.cmd' to create build files
* Visual Studio solution files will be generated under 'build'

### Dependencies
* PuTTYImp is used to import existing FIDO resident keys. This links libfido2 statically; libfido2 and its binary dependencies are included in this repository. All other PuTTY executables have no dependencies other than those included within the Windows operating system and its associated SDKs.

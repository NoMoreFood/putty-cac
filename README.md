# PuTTY CAC
PuTTY CAC is a fork of PuTTY, a popular Secure Shell (SSH) terminal. PuTTY CAC adds the ability to use the Windows Certificate API (CAPI), Public Key Cryptography Standards (PKCS) libraries, or  Fast Identity Online (FIDO) keys to perform SSH public key authentication using a private key associated with a certificate that is stored on a hardware token.

PuTTY CAC can be used with many types of cryptographic tokens such as Yubikeys and popular smart card models. The 'CAC' in 'PuTTY CAC' refers to Common Access Card, a smart card token used for US Government facilities which was one of the initial drivers for the development of PuTTY CAC.

PuTTY CAC is maintained independently from the US Government by the open source community. 

You can download the latest release of PuTTY CAC here: https://github.com/NoMoreFood/putty-cac/releases

## Prerequisites
* Microsoft Windows 10 or Later
* For CAPI support, an appropriate Windows smart card mini-driver must be installed. This is typically provided by the smart card manufacturer although many common hardware tokens are supported by OpenSC.
* For PKCS support, a PKCS #11 library (typically a DLL file) is needed to interface with the hardware token. This is typically provided by the smart card manufacturer although many common hardware tokens are supported by OpenSC.
* For FIDO support, a FIDO key supported by Windows 10.

## Usage
You can find a basic set of instructions on the usage of United States Government's ID Management website under the 'SSH Using PuTTY-CAC' section: 

https://playbooks.idmanagement.gov/piv/engineer/ssh/

## Command Line Usage
PuTTY CAC supports the same command line options as PuTTY with some additional, specialized options for PuTTY CAC specifically. 

In place of a PuTTY key file path for any PuTTY utility, you can specific certificate thumbprint or application identifier. For example:
* Connect to user@host using the certificate with thumbprint '716B8B58D8F2C3A7F98F3F645161B1BF9818B689' the user certificate store:  
`putty.exe user@host -i CAPI:716B8B58D8F2C3A7F98F3F645161B1BF9818B689`
* Connect to user@host using the certificate with thumbprint 'B8B58D8F2C3A7F98F3F645161B1BF9818B689716' using PKCS library 'PKCS.dll':  
`putty.exe user@host -i PKCS:B8B58D8F2C3A7F98F3F645161B1BF9818B689716=C:\PKCS.dll`  
* Connect to user@host using FIDO key identified by 'ssh:MyFidoKey' from PuTTY CAC FIDO key cache:  
`putty.exe user@host -i FIDO:ssh:MyFidoKey`

PuTTY executables (putty.exe, pageant.exe, psftp.exe) support the following additional command line options. Most of these options are focused on the operation of Pageant and are also settable from its user interface. Once set, these options will apply automatically to subsequent executions unless specifically unset. Settings that filter Pageant certificate selection dialogs will also affect filter certificate selection dialogs in the standard PuTTY application:
* Automatically load any compatible CAPI certificates at startup: `-autoload`,`-autoloadoff`
* Save key list between PuTTY executions: `-savecertlist`,`-savecertlistoff`
* Enable supplementary PIN caching in Pageant: `-forcepincache`,`-forcepincacheoff`
* Prompt when certificate signing operation is requested: `-certauthprompting`,`-certauthpromptingoff`
* Only display trusted certificates in certificate selection dialogs: `-trustedcertsonly`,`-trustedcertsonlyoff`
* Do not display expired certificates in certificate selection dialogs: `-ignoreexpiredcerts`,`-ignoreexpiredcertsoff`
* Disable all filtering in certificate selection dialogs: `-allowanycert`,`-allowanycertoff`

## Special Considerations
### Certificates
For the purposes of PuTTY CAC, the certificate is simply a convenient way to reference a private/public key pair. If you want to use PuTTY CAC to securely logon to your system and do not have access to a Certificate Authority (CA), the certificate can be self-signed. Conversely, PuTTY CAC can be used in conjunction with managed SSH servers to enforce multifactor authentication. This can be done by ensuring that the OpenSSH authorized_keys file only contains public keys associated with hardware tokens either procedurally or by creating an index of all issued certs and looking them up through OpenSSH directives like AuthorizedKeysCommand.
### Federal Information Processing Standards (FIPS) Compliance
The specific code used to interface with the hardware token utilizes the Microsoft cryptographic libraries which in turn are governed by system-level FIPS settings (see [Microsoft's website](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/system-cryptography-use-fips-compliant-algorithms-for-encryption-hashing-and-signing)).  Similarly, the hardware token that is used for signing authentication challenges is guaranteed to use FIPS compliant algorithms if the hardware key is FIPS certified; see the hardware token's manufacturer website for more information. PuTTY itself utilizes proprietary encryption and hashing once the SSH session is established which has not undergone evaluation for FIPS compliance or certification. 
## Notes On Building PuTTY CAC
### Prerequisites
* Visual Studio 2022 with C++ Desktop Application Development
* WiX Toolset (to build the MSI files)
* Windows PowerShell (to build the MSI/ZIP/Hash files)

### Building
* Execute 'packager\build.cmd' to create build files
* Visual Studio solution files will be generated under 'build'

### Dependencies
* PuTTYImp is used to import existing FIDO resident keys. This links libfido2 statically; libfido2 and its binary dependencies are included in this repository. All other PuTTY executables have no dependencies other than those included within the Windows operating system and its associated SDKs.

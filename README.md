# PuTTY CAC

PuTTY CAC is a fork of PuTTY, a popular Secure Shell (SSH) terminal. PuTTY CAC adds the ability to use the Windows Certificate API (CAPI) or a Public Key Cryptography Standards (PKCS) library to perform SSH public key authentication using a private key associated with a certificate that is stored on a hardware token.

PuTTY CAC can be used with many types of cryptographic tokens such as Yubikeys and popular smart card models. The 'CAC' in 'PuTTY CAC' refers to Common Access Card, a smart card token used for US Government facilities which was one of the initial drivers for the development of PuTTY CAC.

PuTTY CAC is maintained independently from the US Government by the open source community. 

You can download the latest release of PuTTY CAC here: https://github.com/NoMoreFood/putty-cac/releases

## Prerequisites
* Microsoft Windows 7 or Later
* For CAPI support, an appropriate Windows smart card mini-driver must be installed. This is typically provided by the smart card manufacturer although many common hardware tokens are supported by OpenSC.
* For PKCS support, a PKCS #11 library (typically a DLL file) is needed to interface with the hardware token. This is typically provided by the smart card manufacturer although many common hardware tokens are supported by OpenSC.

## Usage
You can find a basic set of instructions on the usage of United States Government's ID Management website under the 'SSH Using PuTTY-CAC' section: 

https://playbooks.idmanagement.gov/piv/engineer/ssh/

## Command Line Usage
PuTTY CAC supports the same command line options as PuTTY. In place of a PuTTY key file path for any PuTTY utility, you can specific certificate thumbprint. For example, `putty.exe CAPI:716B8B58D8F2C3A7F98F3F645161B1BF9818B689 ...` will load the noted thumbprint from the Windows certificate store. For certificates from PKCS libraries, the syntax is the similiar with the addition the library following the thumbprint. For example, `PKCS:716B8B58D8F2C3A7F98F3F645161B1BF9818B689=C:\Windows\Library.dll ...`. 

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
The specific code used to interface with the hardware token utilizes the Microsoft cryptographic libraries which in turn are governed by system-level FIPS settings. However, PuTTY itself utilizes proprietary encryption and hashing for communication which has not undergone evaluation for FIPS compliance or certification. 
## Notes On Building PuTTY CAC
### Prerequisites
* Visual Studio 2022 with C++ Desktop Application Development
* WiX Toolset (to build the MSI files)
* Windows PowerShell (to build the MSI/ZIP/Hash files)

### Visual Studio Notes
* Solution File: 'Code\windows\VS2022\putty.sln'


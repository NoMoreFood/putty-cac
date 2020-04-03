# PuTTY CAC

PuTTY CAC is a fork of the PuTTY, a popular Secure Shell (SSH) terminal. PuTTY CAC adds the ability to use the Windows Certificate API (CAPI) or a Public Key Cryptography Standards (PKCS) library to perform SSH public key authentication using a private key associated with a certificate that is stored on a hardware token.

PuTTY CAC can be use with many types of cryptographic tokens such as Yubikeys and popular smart card models.  The 'CAC' in 'PuTTY CAC' refers to Common Access Card, a smart card token used for US Government facilities which was one of the initial drivers for the development of PuTTY CAC.

PuTTY CAC is maintained independently from the US Government by the open source community.  

## Prerequisites
* Microsoft Windows 7 or Later
* For CAPI support, an appropriate Windows smart card mini-driver must be installed.  This is typically provided by the smart card manufacturer although many common hardware tokens are supported by OpenSC.
* For PKCS support, a PKCS #11 library (typically a DLL file) is needed to interface with the hardware token.  This is typically provided by the smart card manufacturer although many common hardware tokens are supported by OpenSC.

## Usage
You can find a basic set of instructions on the usage of United States Government's ID Management website under the 'SSH Using PuTTY-CAC' section: 

https://piv.idmanagement.gov/engineering/ssh/
## Special Considerations
### Certificates
For the purposes of PuTTY CAC, the certificate is simply a convenient way to reference a private/public key pair.  If you want to use PuTTY CAC to securely logon to your system and do not have access to a Certificate Authority (CA), the certificate can be self-signed.  Conversely, PuTTY CAC can be used in conjunction with managed SSH servers to enforce multifactor authentication.  This can be done by ensuring that the OpenSSH authorized_keys file only contains public keys associated with hardware tokens either procedurally or by creating an index of all issued certs and looking them up through OpenSSH directives like AuthorizedKeysCommand.
### Federal Information Processing Standards (FIPS) Compliance
The specific code used to interface with the hardware token utilizes the Microsoft cryptographic libraries which in turn are governed by system-level FIPS settings.  However, PuTTY itself utilizes proprietary encryption and hashing for communication which has not undergone evaluation for FIPS compliance or certification. 
## Notes On Building PuTTY CAC
### Prerequisites
* Visual Studio 2019 with C++ Desktop Application Development
* WiX Toolset (to build the MSI files)
* Windows PowerShell (to build the MSI/ZIP/Hash files)

### Visual Studio Notes
* Solution File: 'Code\windows\VS2019\putty.sln'


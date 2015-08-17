PuTTY-CAC
=========
secure shell client with support for US Gov't Smartcards and other X.509 certificates.

This is a fork of PuTTY.  It breaks much of the delictious goodness of
the original PuTTY, in that it only builds for Windows, and is only
known to build correctly with Microsoft Visual C, at this time.

But it supports the DoD Common Access Card (CAC) and a number of other smartcards.  

PuTTY-CAC is now updated to 0.65 and is in sync with the newest PuTTY
Suite 0.65. I synced the PuTTY-CAC code with the latest version of PuTTY
0.65 to get PuTTY-CAC 0.65. This is a non-official release. If and/or
when Daniel Risacher (the developer of PuTTY-CAC) updates his release I
recommend using his instead.

What's changed since version 0.63?
PuTTY
0.64, fixes a security hole in 0.63 and before: private-key-not-wiped-2.
Also diffie-hellman-range-check has been argued to be a security hole.
In addition to these and other less critical bug fixes, 0.64 also
supports the major new feature of sharing an SSH connection between
multiple instances of PuTTY and its tools, and a command-line and config
option to specify the expected host key(s).

PuTTY 0.65, fixes the
Vista bug where the configuration dialog became invisible, and a few
other bugs, large and small.

Source:
http://www.chiark.greenend.org.uk/~sgtatham/putty/ (Original PuTTY as
developed by Simon Tatham.)
Source: http://www.risacher.org/putty-cac/
(PuTTY-CAC was developed by Dan Risacher.)

WARNING: The PKCS11 API
originally from PuTTY-SC has been removed from all applications in this
PuTTY-CAC Suite due to complications I was having with the code.
However, CAPI support is still functional which is the main premise
behind PuTTY-CAC anyways. If you need to use PKCS11 then DO NOT DOWNLOAD
ANY OF THESE VERSIONS. Download an older release of 0.62 which has
support for PKCS11. If you do not know what I am talking about then this
release should be fine for your needs. Also, none of these releases will
include the PuTTYtel application.

I have included compiled versions of
the PuTTY-CAC suite that can be found in the EXECUTABLES folder for each
type listed above for those that do not want to compile the code.
However, these compiled applications may only work on Windows 7/8. They
have not been tested on older OS’s such as Vista/XP or newer OS's such
as 10.

If you choose to compile the source code yourself you will need
to use the MakeFile.vc as I did not update nor do I support the other
MakeFile.* files.
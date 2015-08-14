putty-cac
=========

secure shell client with support for US Gov't Smartcards and other X.509 certificates.

This is a fork of PuTTY.  It breaks much of the delictious goodness of
the original PuTTY, in that it only builds for Windows, and is only
known to build correctly with Microsoft Visual C, at this time.

But it supports the DoD Common Access Card (CAC) and a number of other smartcards.  

A version that is syncronized with PuTTY beta 0.65 is available from http://risacher.org/putty-cac/ and https://software.forge.mil/sf/frs/do/viewRelease/projects.community_cac/frs.putty_cac.2015_08_14_0_65. (DoD PKI required for software.forge.mil access)  These improvements will be merged with this codebase in September.

This version (as of 2012-08-29) has support for Microsoft's
Cryptographic API (CAPI) in addition to the PKCS#11 API, thanks to a
patch contributed by Andrew Prout of the MIT Lincoln Laboratory.  What
this means is that it is likely to support a broader range of
middleware and certificates, including soft-certs.

putty-cac
=========

secure shell client with support for US Gov't Smartcards and other X.509 certificates.

This is a fork of PuTTY.  It breaks much of the delictious goodness of the original PuTTY, in that it only builds for Windows, and is only known to build correctly with Microsoft Visual C, at this time.  

But it supports the DoD Common Access Card (CAC) and a number of other smartcards.  

This version (as of 2012-08-29) has support for Microsoft's Cryptographic API (CAPI) in addition to the PKCS#11 API, thanks to a patch contributed by Andrew PRout of the MIT Lincoln Laboratory.  What this means is that it is likely to support a broader range of middleware and certificates, including soft-certs.
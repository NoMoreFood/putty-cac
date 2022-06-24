#pragma once

#ifdef PUTTY_CAC

#include <windows.h>

// forward declarations for shared structures
struct ssh2_userkey;
struct strbuf;

// used to determine whether these variables are marked as extern
// for external source files including these files
#undef EXTERN
#ifdef DEFINE_VARIABLES
#define EXTERN 
#else
#ifdef __cplusplus
#define EXTERN EXTERN_C
#else
#define EXTERN extern
#endif
#endif

// functions used by the common module
EXTERN BOOL cert_pkcs_test_hash(LPCSTR szCert, DWORD iHashRequest);
EXTERN BYTE * cert_pkcs_sign(struct ssh2_userkey * userkey, LPCBYTE pDataToSign, int iDataToSignLen, int * iSigLen, LPCSTR sHashAlgName);
EXTERN void cert_pkcs_load_cert(LPCSTR szCert, PCCERT_CONTEXT* ppCertCtx, HCERTSTORE* phStore);
EXTERN HCERTSTORE cert_pkcs_get_cert_store();

#endif // PUTTY_CAC
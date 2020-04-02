#pragma once

#ifdef PUTTY_CAC

#include <windows.h>

// include ssh for types
#ifndef SSH_AGENT_SUCCESS
#include "ssh.h"
#endif

// used to determine whether these variables are marked as extern
// for external source files including these files
#undef EXTERN
#ifdef DEFINE_VARIABLES
#define EXTERN 
#else
#define EXTERN extern
#endif

// functions used by the common module
EXTERN BYTE * cert_pkcs_sign(struct ssh2_userkey * userkey, LPCBYTE pDataToSign, int iDataToSignLen, int * iSigLen, HWND hwnd);
EXTERN void cert_pkcs_load_cert(LPCSTR szCert, PCCERT_CONTEXT* ppCertCtx, HCERTSTORE* phStore);
EXTERN HCERTSTORE cert_pkcs_get_cert_store(LPCSTR * szHint, HWND hWnd);

#endif // PUTTY_CAC
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

// functions used only by the capi and pkcs addon modules
EXTERN void cert_reverse_array(LPBYTE pb, DWORD cb);
EXTERN void cert_prompt_cert(HCERTSTORE hStore, HWND hWnd, LPSTR * szCert, LPCSTR szIden, LPCSTR szHint);
EXTERN BOOL cert_load_cert(LPCSTR szCert, PCERT_CONTEXT * ppCertContext, HCERTSTORE * phCertStore);
EXTERN LPSTR cert_get_cert_hash(LPCSTR szIden, PCCERT_CONTEXT pCertContext, LPCSTR szHint);
EXTERN PVOID cert_pin(LPSTR szCert, BOOL bUnicode, LPVOID szPin, HWND hWnd);
EXTERN BOOL cert_cache_enabled(DWORD bEnable);
EXTERN BOOL cert_auth_prompting(DWORD bEnable);

// functions used by putty code 
EXTERN LPSTR cert_key_string(LPCSTR szCert);
EXTERN LPSTR cert_subject_string(LPCSTR szCert);
EXTERN LPSTR cert_prompt(LPCSTR szIden, HWND hWnd);
EXTERN LPBYTE cert_sign(struct ssh2_userkey * userkey, LPCBYTE pDataToSign, int iDataToSignLen, int * iWrappedSigLen, HWND hWnd);
EXTERN struct ssh2_userkey * cert_load_key(LPCSTR szCert);
EXTERN VOID cert_display_cert(LPCSTR szCert, HWND hWnd);
EXTERN int cert_all_certs(LPSTR ** pszCert);
EXTERN void cert_convert_legacy(LPSTR szCert);
EXTERN LPBYTE cert_get_hash(LPCSTR szAlgo, LPCBYTE pDataToHash, DWORD iDataToHashSize, DWORD * iHashedDataSize, BOOL bPrependDigest);

// used in pageant for dialog controls
#define IDC_PAGEANT_ADD_PKCS 104
#define IDC_PAGEANT_ADD_CAPI 105
#define IDC_PAGEANT_CLIP_KEY 106

#define SHA1_BINARY_SIZE (160 / 8)
#define SHA1_HEX_SIZE (SHA1_BINARY_SIZE * 2)

#define IDEN_CAPI "CAPI:"
#define IDEN_CAPI_SIZE (strlen(IDEN_CAPI))
#define IDEN_PKCS "PKCS:"
#define IDEN_PKCS_SIZE (strlen(IDEN_PKCS))

#define IDEN_SPLIT(p) (strchr(p,':') + 1)
#define IDEN_TYPE(p) (cert_is_capipath(p) ? "CAPI" : "PKCS")

#define cert_is_capipath(p) (strnicmp((LPSTR) p, IDEN_CAPI, IDEN_CAPI_SIZE) == 0)
#define cert_is_pkcspath(p) (strnicmp((LPSTR) p, IDEN_PKCS, IDEN_PKCS_SIZE) == 0)
#define cert_is_certpath(p) (p != NULL && (cert_is_capipath(p) || cert_is_pkcspath(p)))
#define cert_iden(p) (cert_is_capipath(p) ? IDEN_CAPI : (cert_is_pkcspath(p) ? IDEN_PKCS : "")))

#endif /* PUTTY_CAC */


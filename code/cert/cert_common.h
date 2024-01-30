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

// enum for setting controls
typedef enum CERT_SETCMD
{
	CERT_UNSET    = 1 << 0,
	CERT_SET      = 1 << 1,
	CERT_SETTABLE = 1 << 2,
	CERT_QUERY    = 1 << 3,
	CERT_ENFORCED = 1 << 4
}
CERT_SETCMD;

// functions used only by the capi and pkcs addon modules
EXTERN VOID cert_reverse_array(LPBYTE pb, DWORD cb);
EXTERN BOOL cert_load_cert(LPCSTR szCert, PCERT_CONTEXT * ppCertContext, HCERTSTORE * phCertStore);
EXTERN BOOL cert_check_valid(LPCSTR szIden, PCCERT_CONTEXT pCertContext);
EXTERN LPSTR cert_get_cert_thumbprint(LPCSTR szIden, PCCERT_CONTEXT pCertContext);
EXTERN PVOID cert_pin(LPSTR szCert, BOOL bUnicode, LPVOID szPin);
EXTERN BOOL cert_save_cert_list_enabled(CERT_SETCMD iCommand);
EXTERN BOOL cert_cache_enabled(CERT_SETCMD iCommand);
EXTERN BOOL cert_auth_prompting(CERT_SETCMD iCommand);
EXTERN BOOL cert_smartcard_certs_only(CERT_SETCMD iCommand);
EXTERN BOOL cert_ignore_expired_certs(CERT_SETCMD iCommand);
EXTERN BOOL cert_trusted_certs_only(CERT_SETCMD iCommand);
EXTERN BOOL cert_allow_any_cert(CERT_SETCMD iCommand);
EXTERN BOOL cert_auto_load_certs(CERT_SETCMD iCommand);
EXTERN LPCSTR cert_ignore_cert_name(LPCSTR sValue);
EXTERN BOOL cert_cmdline_parse(LPCSTR sCommand);
EXTERN DWORD cert_menu_flags(BOOL(*func)(CERT_SETCMD iCommand));

// functions used by putty code 
EXTERN LPSTR cert_key_string(LPCSTR szCert);
EXTERN LPSTR cert_subject_string(LPCSTR szCert);
EXTERN LPSTR cert_prompt(LPCSTR szIden, BOOL bAutoSelect, LPCWSTR sCustomPrompt);
EXTERN BOOL cert_test_hash(LPCSTR szCert, DWORD iHashRequest);
EXTERN BOOL cert_confirm_signing(LPCSTR sFingerPrint, LPCSTR sComment);
EXTERN BOOL cert_sign(struct ssh2_userkey * userkey, LPCBYTE pDataToSign, int iDataToSignLen, int iAgentFlags, struct strbuf* pSignature);
EXTERN struct ssh2_userkey * cert_load_key(LPCSTR szCert);
EXTERN VOID cert_display_cert(LPCSTR szCert, HWND hWnd);
EXTERN int cert_all_certs(LPSTR ** pszCert);
EXTERN VOID cert_convert_legacy(LPSTR szCert);
EXTERN LPBYTE cert_get_hash(LPCSTR szAlgo, LPCBYTE pDataToHash, DWORD iDataToHashSize, DWORD * iHashedDataSize, BOOL bPrependDigest);
EXTERN BOOL cert_capi_delete_key(LPCSTR szCert);
EXTERN BOOL fido_create_key(LPCSTR szAlgName, LPCSTR szDisplayName, LPCSTR szApplication, BOOL bResidentKey, BOOL bUserVerification);
EXTERN BOOL fido_delete_key(LPCSTR szCert);
EXTERN VOID fido_import_keys();
EXTERN LPSTR fido_import_openssh_key();
EXTERN VOID fido_clear_keys();
EXTERN LPSTR cert_capi_create_key(LPCSTR szAlgName, LPCSTR sSubjectName, BOOL bHardware);

// ed25519 oid; no native support in windows
#ifndef szOID_ED25119
#define szOID_ED25119 "1.3.6.1.4.1.11591.15.1"
#endif

#define SHA1_BINARY_SIZE (160 / 8)
#define SHA1_HEX_SIZE (SHA1_BINARY_SIZE * 2)

#define IDEN_CAPI "CAPI:"
#define IDEN_CAPI_SIZE (strlen(IDEN_CAPI))
#define IDEN_PKCS "PKCS:"
#define IDEN_PKCS_SIZE (strlen(IDEN_PKCS))
#define IDEN_FIDO "FIDO:"
#define IDEN_FIDO_SIZE (strlen(IDEN_FIDO))

#define IDEN_SPLIT(p) (strchr(p,':') + 1)
#define IDEN_PREFIX(p) (cert_is_capipath(p) ? IDEN_CAPI : cert_is_pkcspath(p) ? IDEN_PKCS : IDEN_FIDO)

#define cert_is_capipath(p) (p != NULL && _strnicmp((LPSTR) p, IDEN_CAPI, IDEN_CAPI_SIZE) == 0)
#define cert_is_pkcspath(p) (p != NULL && _strnicmp((LPSTR) p, IDEN_PKCS, IDEN_PKCS_SIZE) == 0)
#define cert_is_fidopath(p) (p != NULL && _strnicmp((LPSTR) p, IDEN_FIDO, IDEN_FIDO_SIZE) == 0)
#define cert_is_certpath(p) (p != NULL && (cert_is_capipath(p) || cert_is_pkcspath(p) || cert_is_fidopath(p)))
#define cert_iden(p) (cert_is_capipath(p) ? IDEN_CAPI : (cert_is_pkcspath(p) ? IDEN_PKCS : (cert_is_fidopath(p) ? IDEN_FIDO : "")))

#endif /* PUTTY_CAC */


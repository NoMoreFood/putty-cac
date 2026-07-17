#pragma once

#ifdef PUTTY_CAC

#include <windows.h>

// forward declarations for shared structures
struct ssh2_userkey;
struct ssh_keyalg;
struct strbuf;

#ifdef PUTTY_CAC_SSH_TYPES_DEFINED
struct x509_ssh_rsa_key
{
	struct RSAKey rsa;
	unsigned char * cert_data;
	size_t cert_len;
};

struct x509_ssh_ecdsa_key
{
	struct ecdsa_key ecdsa;
	unsigned char * cert_data;
	size_t cert_len;
};

extern const struct ssh_keyalg ssh_x509v3_ssh_rsa;
extern const struct ssh_keyalg ssh_x509v3_rsa2048_sha256;
extern const struct ssh_keyalg ssh_x509v3_ecdsa_nistp256;
extern const struct ssh_keyalg ssh_x509v3_ecdsa_nistp384;
extern const struct ssh_keyalg ssh_x509v3_ecdsa_nistp521;
#endif

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
	CERT_QUERY    = 1 << 2,
	CERT_ENFORCED = 1 << 3
}
CERT_SETCMD;

// functions used only by the capi and pkcs addon modules
EXTERN VOID cert_reverse_array(LPBYTE pb, DWORD cb);
EXTERN BOOL cert_parse_sha1_selector(LPCSTR szSelector, LPCSTR szPrefix,
	CHAR chSeparator, LPBYTE pbThumb, LPCSTR * pszPayload);
EXTERN BOOL cert_context_matches_sha1(PCCERT_CONTEXT pCertContext,
	LPCBYTE pbThumb);
EXTERN BOOL cert_keyalg_is_rsa(const struct ssh_keyalg * vt);
EXTERN BOOL cert_keyalg_is_ecdsa(const struct ssh_keyalg * vt);
EXTERN BOOL cert_hash_alg(LPCSTR szAlgo, DWORD iHashRequest,
	DWORD * piHashAlg, LPCWSTR * psHashAlgId);
EXTERN BOOL cert_parse_x509_public_blob(LPCSTR szKeyAlg,
	LPCBYTE pBlob, size_t iBlobLen,
	LPCBYTE * ppBody, size_t * piBodyLen,
	LPCBYTE * ppLeafCert, size_t * piLeafCertLen);
EXTERN BOOL cert_der_read_tlv(LPCBYTE * ppData, LPCBYTE pEnd,
	PBYTE pTag, LPCBYTE * ppValue, size_t * piValueLen);
EXTERN BOOL cert_x509_subject_public_key(LPCBYTE pCert, size_t iCertLen,
	LPCBYTE * ppAlgorithm, size_t * piAlgorithmLen,
	LPCBYTE * ppPublicKey, size_t * piPublicKeyLen);
EXTERN BOOL cert_x509_rsa_public_key(LPCBYTE pCert, size_t iCertLen,
	LPCBYTE * ppModulus, size_t * piModulusLen,
	LPCBYTE * ppExponent, size_t * piExponentLen);
EXTERN BOOL cert_x509_ecdsa_public_key(LPCSTR szKeyAlg,
	LPCBYTE pCert, size_t iCertLen,
	LPCBYTE * ppPublicKey, size_t * piPublicKeyLen);
EXTERN BOOL cert_decode_ecdsa_signature(LPCBYTE pDer, size_t iDerLen,
	size_t iPartLen, LPBYTE pSignature);
EXTERN BOOL cert_load_cert(LPCSTR szCert, PCERT_CONTEXT * ppCertContext, HCERTSTORE * phCertStore);
EXTERN BOOL cert_check_x509_usage(PCCERT_CONTEXT pCertContext, PBOOL pbFoundSmartCardLogon);
EXTERN BOOL cert_check_valid(LPCSTR szIden, PCCERT_CONTEXT pCertContext);
EXTERN LPSTR cert_get_cert_thumbprint(LPCSTR szIden, PCCERT_CONTEXT pCertContext);
EXTERN BOOL cert_save_cert_list_enabled(CERT_SETCMD iCommand);
EXTERN BOOL cert_cache_enabled(CERT_SETCMD iCommand);
EXTERN BOOL cert_auth_prompting(CERT_SETCMD iCommand);
EXTERN BOOL cert_smartcard_certs_only(CERT_SETCMD iCommand);
EXTERN BOOL cert_ignore_expired_certs(CERT_SETCMD iCommand);
EXTERN BOOL cert_trusted_certs_only(CERT_SETCMD iCommand);
EXTERN BOOL cert_allow_any_cert(CERT_SETCMD iCommand);
EXTERN BOOL cert_auto_load_certs(CERT_SETCMD iCommand);
EXTERN BOOL cert_auth_x509_enabled(CERT_SETCMD iCommand);
EXTERN LPCSTR cert_ignore_cert_name(LPCSTR sValue);
EXTERN BOOL cert_cmdline_parse(LPCSTR sCommand);
EXTERN DWORD cert_menu_flags(BOOL(*func)(CERT_SETCMD iCommand));
EXTERN struct ssh2_userkey * cert_load_key_for_keyalg(LPCSTR szCert, const struct ssh_keyalg * requested_vt);
EXTERN BOOL cert_sign_for_keyalg(LPCSTR szCert,
	const struct ssh_keyalg * requested_vt, const void * expected_blob,
	size_t expected_blob_len,
	LPCBYTE pDataToSign, int iDataToSignLen, int iAgentFlags, struct strbuf * pSignature);

// functions used by putty code 
EXTERN LPSTR cert_key_string(LPCSTR szCert);
EXTERN LPSTR cert_subject_string(LPCSTR szCert);
EXTERN LPSTR cert_prompt(LPCSTR szIden, BOOL bAutoSelect, LPCWSTR sCustomPrompt);
EXTERN BOOL cert_test_hash(LPCSTR szCert, DWORD iHashRequest);
EXTERN BOOL cert_confirm_signing(LPCSTR sFingerPrint, LPCSTR sComment,
	BOOL bProviderBacked);
EXTERN BOOL cert_sign(struct ssh2_userkey * userkey,
	LPCBYTE pExpectedBlob, size_t iExpectedBlobLen,
	LPCBYTE pDataToSign, int iDataToSignLen, int iAgentFlags,
	struct strbuf * pSignature);
EXTERN BOOL cert_public_blob_matches(struct ssh2_userkey * userkey,
	LPCBYTE pExpectedBlob, size_t iExpectedBlobLen);
EXTERN BOOL cert_build_x509_public_blob_body(PCCERT_CONTEXT pCertContext, HCERTSTORE hCertStore,
	unsigned char ** ppBlob, size_t * pBlobLen);
EXTERN struct ssh2_userkey * cert_load_key_with_x509(LPCSTR szCert, BOOL bAttemptX509);
EXTERN struct ssh2_userkey * cert_load_key(LPCSTR szCert);
EXTERN VOID cert_display_cert(LPCSTR szCert, HWND hWnd);
EXTERN int cert_all_certs(LPSTR ** pszCert);
EXTERN LPBYTE cert_get_hash(LPCSTR szAlgo, LPCBYTE pDataToHash, DWORD iDataToHashSize, DWORD * iHashedDataSize, BOOL bPrependDigest);
EXTERN PVOID cert_pin(LPSTR szCert, BOOL bWide, LPVOID szPin);
EXTERN PVOID cert_prompt_pin(BOOL bWide);
EXTERN BOOL cert_capi_delete_key(LPCSTR szCert);
EXTERN BOOL fido_create_key(LPCSTR szAlgName, LPCSTR szDisplayName, LPCSTR szApplication, BOOL bResidentKey, BOOL bUserVerification);
EXTERN BOOL fido_delete_key(LPCSTR szCert);
EXTERN VOID fido_import_keys();
EXTERN LPSTR fido_import_openssh_key();
EXTERN VOID fido_clear_keys();
EXTERN LPSTR cert_capi_create_key(LPCSTR szAlgName, LPCSTR sSubjectName, BOOL bHardware);

// ed25519 oid; no native support in windows
#ifndef szOID_ED25519
#define szOID_ED25519 "1.3.6.1.4.1.11591.15.1"
#endif

// RFC 6187 id-kp-secureShellClient; not defined by the Windows SDK
#ifndef szOID_PKIX_KP_SECURE_SHELL_CLIENT
#define szOID_PKIX_KP_SECURE_SHELL_CLIENT "1.3.6.1.5.5.7.3.21"
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

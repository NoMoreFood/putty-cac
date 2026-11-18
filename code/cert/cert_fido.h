#pragma once

#ifdef PUTTY_CAC

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#define FIDO_REG_ROOT L"Software\\SimonTatham\\PuTTY\\Fido"
#define FIDO_REG_PUBKEYS FIDO_REG_ROOT L"\\PubKeyBlobs"
#define FIDO_REG_CREDIDS FIDO_REG_ROOT L"\\CredIdBlobs"
#define FIDO_REG_USERVER FIDO_REG_ROOT L"\\UserVerification"
#define FIDO_MAX_APPID_LEN 256
#define FIDO_MAX_CREDID_LEN 1023
#define FIDO_MAX_COORDINATE_LEN 66
#define FIDO_CREDENTIAL_ID_PROP CERT_FIRST_USER_PROP_ID

typedef struct {
	BCRYPT_ECCKEY_BLOB tHeader;
	BYTE pCoordinates[2 * FIDO_MAX_COORDINATE_LEN];
} fido_public_key_buffer_t;

// forward declarations for shared structures
struct ssh2_userkey;
struct strbuf;

// used to determine whether these variables are marked as extern
// for external source files including these files
#undef EXTERN
#ifdef DEFINE_VARIABLES
#define EXTERN 
#else
#define EXTERN extern
#endif

// functions used by the common module
EXTERN BOOL cert_fido_test_hash(LPCSTR szCert, DWORD iHashRequest);
EXTERN BYTE* cert_fido_sign(struct ssh2_userkey* userkey, const BYTE* pDataToSign, int iDataToSignLen,
	int* iSigLen, LPCSTR sHashAlgName, PDWORD iCounter, PBYTE iFlags);
EXTERN void cert_fido_load_cert(LPCSTR szCert, PCCERT_CONTEXT* ppCertCtx, HCERTSTORE* phStore);
EXTERN HCERTSTORE cert_fido_get_cert_store();

LPWSTR fido_get_user_id(void);
HANDLE cert_fido_cache_lock(LPCWSTR sid);
void cert_fido_cache_unlock(HANDLE mutex);
BOOL cert_fido_update_cache(LPCWSTR sid, LPCWSTR app, const fido_public_key_buffer_t *key, DWORD key_len,
	const BYTE *id, DWORD id_len, DWORD verification, const CRYPT_DATA_BLOB *expected);

#endif // PUTTY_CAC

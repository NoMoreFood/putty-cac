#ifdef PUTTY_CAC

#include <WinSock2.h>
#include <stdio.h>
#include <bcrypt.h>
#include <wincred.h>
#include <sddl.h>
#include <webauthn.h>

#include "ssh.h"
#include "mpint.h"
#include "ecc.h"
#include "putty.h"

#define DEFINE_VARIABLES
#include "cert_fido.h"
#undef DEFINE_VARIABLES

#include "cert_common.h"

#pragma comment(lib,"crypt32.lib")
#pragma comment(lib,"credui.lib")
#pragma comment(lib,"ncrypt.lib")
#pragma comment(lib,"webauthn.lib")
#pragma comment(lib,"delayimp.lib")

// registry key locations for fido
#define FIDO_REG_PUBKEYS L"Software\\SimonTatham\\PuTTY\\Fido\\PubKeyBlobs"
#define FIDO_REG_CREDIDS L"Software\\SimonTatham\\PuTTY\\Fido\\CredIdBlobs"
#define FIDO_REG_USERVER L"Software\\SimonTatham\\PuTTY\\Fido\\UserVerification"

// special define since not currently included in header
#ifndef WEBAUTHN_COSE_ALGORITHM_EDDSA_ED25519
#define WEBAUTHN_COSE_ALGORITHM_EDDSA_ED25519 -8
#endif

// Bounds for FIDO identifiers and supported public-key encodings.
#define FIDO_MAX_APPID_LEN 256
#define FIDO_MAX_DISPLAY_LEN 64
#define FIDO_MAX_CREDID_LEN 1023
#define FIDO_MAX_COORDINATE_LEN 66

typedef struct _fido_public_key_buffer_t
{
	BCRYPT_ECCKEY_BLOB tHeader;
	BYTE pCoordinates[2 * FIDO_MAX_COORDINATE_LEN];
}
fido_public_key_buffer_t;

typedef struct _fido_algorithm_details_t
{
	LPCSTR sAlgorithm;
	LPCWSTR sHashAlgorithm;
	DWORD iSignaturePartSize;
	BOOL bEd25519;
	LONG iCoseAlgorithm;
	LONG iCoseKeyType;
	LONG iCoseCurve;
	ULONG iPublicKeyMagic;
}
fido_algorithm_details_t;

typedef struct _fido_cbor_reader_t
{
	LPCBYTE pData;
	LPCBYTE pEnd;
}
fido_cbor_reader_t;

struct GetAttestationThreadParams
{
	HWND hWnd;
	LPCWSTR pwszRpId;
	PCWEBAUTHN_CLIENT_DATA pWebAuthNClientData;
	PCWEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS pWebAuthNGetAssertionOptions;
	PWEBAUTHN_ASSERTION ppWebAuthNAssertion;
};

static INIT_ONCE fido_webauthn_once = INIT_ONCE_STATIC_INIT;
static BOOL fido_webauthn_loaded = FALSE;

static BOOL CALLBACK cert_fido_load_webauthn(PINIT_ONCE pOnce, PVOID pParameter, PVOID* ppContext)
{
	(void)pOnce;
	(void)pParameter;
	(void)ppContext;
	fido_webauthn_loaded = LoadLibraryExW(L"webauthn.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32) != NULL;
	return TRUE;
}

BOOL LoadDelayLoadedLibaries()
{
	if (!InitOnceExecuteOnce(&fido_webauthn_once, cert_fido_load_webauthn, NULL, NULL))
	{
		return FALSE;
	}
	if (!fido_webauthn_loaded)
	{
		MessageBoxW(NULL, L"PuTTY CAC FIDO support is not available on this platform.",
			L"FIDO Not Supported", MB_SYSTEMMODAL | MB_ICONERROR | MB_OK);
	}

	return fido_webauthn_loaded;
}

DWORD WINAPI WebAuthNAuthenticatorGetAssertionThread(LPVOID lpParam)
{
	struct GetAttestationThreadParams* pParams = lpParam;

	HRESULT hMakeResult = WebAuthNAuthenticatorGetAssertion(pParams->hWnd, pParams->pwszRpId,
		pParams->pWebAuthNClientData, pParams->pWebAuthNGetAssertionOptions, &pParams->ppWebAuthNAssertion);
	if (hMakeResult != S_OK)
	{
		if (pParams->hWnd != NULL) PostMessage(pParams->hWnd, WM_USER, 0, 0);
		ExitThread(1);
		return FALSE;
	}

	if (pParams->hWnd != NULL) PostMessage(pParams->hWnd, WM_USER, 0, 0);
	ExitThread(0);
	return TRUE;
}

static const fido_algorithm_details_t fido_algorithms[] = {
	{ "sk-ecdsa-sha2-nistp256@openssh.com", WEBAUTHN_HASH_ALGORITHM_SHA_256, 32, FALSE, -7, 2, 1,
		BCRYPT_ECDSA_PUBLIC_P256_MAGIC },
	{ "sk-ecdsa-sha2-nistp384@openssh.com", WEBAUTHN_HASH_ALGORITHM_SHA_384, 48, FALSE, -35, 2, 2,
		BCRYPT_ECDSA_PUBLIC_P384_MAGIC },
	{ "sk-ecdsa-sha2-nistp521@openssh.com", WEBAUTHN_HASH_ALGORITHM_SHA_512, 66, FALSE, -36, 2, 3,
		BCRYPT_ECDSA_PUBLIC_P521_MAGIC },
	{ "sk-ssh-ed25519@openssh.com", WEBAUTHN_HASH_ALGORITHM_SHA_256, 32, TRUE, -8, 1, 6,
		BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC },
};

static const fido_algorithm_details_t* cert_fido_lookup_algorithm(LPCSTR sAlgorithm)
{
	if (sAlgorithm == NULL) return NULL;
	for (size_t iAlgorithm = 0; iAlgorithm < _countof(fido_algorithms); iAlgorithm++)
	{
		if (strcmp(sAlgorithm, fido_algorithms[iAlgorithm].sAlgorithm) == 0)
			return &fido_algorithms[iAlgorithm];
	}
	return NULL;
}

static BOOL cert_fido_cbor_head(fido_cbor_reader_t* pReader, PBYTE pMajor, PULONGLONG pArgument)
{
	if (pReader->pData >= pReader->pEnd) return FALSE;
	BYTE iInitial = *pReader->pData++;
	BYTE iAdditional = iInitial & 0x1F;
	*pMajor = iInitial >> 5;
	if (iAdditional < 24)
	{
		*pArgument = iAdditional;
		return TRUE;
	}

	size_t iArgumentBytes = iAdditional == 24 ? 1 : iAdditional == 25 ? 2 :
		iAdditional == 26 ? 4 : iAdditional == 27 ? 8 : 0;
	if (iArgumentBytes == 0 || (size_t)(pReader->pEnd - pReader->pData) < iArgumentBytes)
	{
		return FALSE;
	}

	ULONGLONG iArgument = 0;
	for (size_t i = 0; i < iArgumentBytes; i++)
		iArgument = (iArgument << 8) | *pReader->pData++;
	*pArgument = iArgument;
	return TRUE;
}

static BOOL cert_fido_cbor_int(fido_cbor_reader_t* pReader, PLONG pValue)
{
	BYTE iMajor;
	ULONGLONG iArgument;
	if (!cert_fido_cbor_head(pReader, &iMajor, &iArgument) || iArgument > LONG_MAX || (iMajor != 0 && iMajor != 1))
	{
		return FALSE;
	}
	*pValue = iMajor == 0 ? (LONG)iArgument : -1 - (LONG)iArgument;
	return TRUE;
}

static BOOL cert_fido_cbor_bytes(fido_cbor_reader_t* pReader, LPCBYTE* ppValue, size_t* piValueLen)
{
	BYTE iMajor;
	ULONGLONG iArgument;
	if (!cert_fido_cbor_head(pReader, &iMajor, &iArgument) || iMajor != 2 ||
		iArgument > (ULONGLONG)(pReader->pEnd - pReader->pData))
	{
		return FALSE;
	}
	*ppValue = pReader->pData;
	*piValueLen = (size_t)iArgument;
	pReader->pData += (size_t)iArgument;
	return TRUE;
}

static BOOL cert_fido_cbor_skip(fido_cbor_reader_t* pReader, unsigned iDepth)
{
	BYTE iMajor;
	ULONGLONG iArgument;
	if (iDepth > 8 || !cert_fido_cbor_head(pReader, &iMajor, &iArgument))
	{
		return FALSE;
	}

	if (iMajor == 2 || iMajor == 3)
	{
		if (iArgument > (ULONGLONG)(pReader->pEnd - pReader->pData))
			return FALSE;
		pReader->pData += (size_t)iArgument;
		return TRUE;
	}
	if (iMajor == 4 || iMajor == 5)
	{
		ULONGLONG iItems = iMajor == 5 ? iArgument * 2 : iArgument;
		if (iItems < iArgument || iItems > (ULONGLONG)(pReader->pEnd - pReader->pData))
		{
			return FALSE;
		}
		for (ULONGLONG i = 0; i < iItems; i++)
			if (!cert_fido_cbor_skip(pReader, iDepth + 1)) return FALSE;
		return TRUE;
	}
	if (iMajor == 6)
		return cert_fido_cbor_skip(pReader, iDepth + 1);
	return iMajor == 0 || iMajor == 1 || iMajor == 7;
}

static BOOL cert_fido_public_key_valid(const fido_algorithm_details_t* pAlgorithm, LPCBYTE pX, LPCBYTE pY)
{
	const struct ec_curve* pCurve = NULL;
	const ssh_keyalg* pKeyAlg = NULL;
	if (!pAlgorithm->bEd25519)
	{
		int iBits = pAlgorithm->iSignaturePartSize == 66 ? 521 : (int)pAlgorithm->iSignaturePartSize * 8;
		if (!ec_nist_alg_and_curve_by_bits(iBits, &pCurve, &pKeyAlg))
			return FALSE;
		mp_int* x = mp_from_bytes_be(make_ptrlen(pX, pAlgorithm->iSignaturePartSize));
		mp_int* y = mp_from_bytes_be(make_ptrlen(pY, pAlgorithm->iSignaturePartSize));
		if (mp_cmp_hs(x, pCurve->p) || mp_cmp_hs(y, pCurve->p))
		{
			mp_free(x);
			mp_free(y);
			return FALSE;
		}
		WeierstrassPoint* pPoint = ecc_weierstrass_point_new(pCurve->w.wc, x, y);
		mp_free(x);
		mp_free(y);
		BOOL bValid = pPoint != NULL && ecc_weierstrass_point_valid(pPoint);
		if (pPoint != NULL) ecc_weierstrass_point_free(pPoint);
		return bValid;
	}

	if (!ec_ed_alg_and_curve_by_bits(256, &pCurve, &pKeyAlg)) return FALSE;
	mp_int* y = mp_from_bytes_le(make_ptrlen(pX, pAlgorithm->iSignaturePartSize));
	unsigned iParity = mp_get_bit(y, pCurve->fieldBytes * 8 - 1);
	mp_set_bit(y, pCurve->fieldBytes * 8 - 1, 0);
	if (mp_cmp_hs(y, pCurve->p))
	{
		mp_free(y);
		return FALSE;
	}
	EdwardsPoint* pPoint = ecc_edwards_point_new_from_y(pCurve->e.ec, y, iParity);
	mp_free(y);
	if (pPoint == NULL) return FALSE;

	// Require a non-identity Ed25519 point in the prime-order subgroup.
	mp_int* one = mp_from_integer(1);
	EdwardsPoint* pIdentity = ecc_edwards_point_new_from_y(pCurve->e.ec, one, 0);
	mp_free(one);
	EdwardsPoint* pMultiple = ecc_edwards_multiply(pPoint, pCurve->e.G_order);
	BOOL bValid = pIdentity != NULL && pMultiple != NULL &&
		!ecc_edwards_eq(pPoint, pIdentity) && ecc_edwards_eq(pMultiple, pIdentity);
	if (pMultiple != NULL) ecc_edwards_point_free(pMultiple);
	if (pIdentity != NULL) ecc_edwards_point_free(pIdentity);
	ecc_edwards_point_free(pPoint);
	return bValid;
}

static BOOL cert_fido_decode_credential(LPCSTR sAlgorithm, LPCBYTE pAuthenticatorData, DWORD iAuthenticatorDataLen,
	LPCBYTE pCredentialId, DWORD iCredentialIdLen, fido_public_key_buffer_t* pPublicKey, PDWORD piPublicKeyLen)
{
	if (piPublicKeyLen != NULL) *piPublicKeyLen = 0;
	const fido_algorithm_details_t* pAlgorithm = cert_fido_lookup_algorithm(sAlgorithm);
	if (pAlgorithm == NULL || pAuthenticatorData == NULL || pCredentialId == NULL || iCredentialIdLen == 0 ||
		pPublicKey == NULL || piPublicKeyLen == NULL || iAuthenticatorDataLen < 55 ||
		(pAuthenticatorData[32] & 0x40) == 0)
	{
		return FALSE;
	}
	memset(pPublicKey, 0, sizeof(*pPublicKey));

	// Locate the COSE_Key after AAGUID and credential ID.
	size_t iAuthenticatorCredentialIdLen = ((size_t)pAuthenticatorData[53] << 8) | pAuthenticatorData[54];
	if (iAuthenticatorCredentialIdLen != iCredentialIdLen || iCredentialIdLen > FIDO_MAX_CREDID_LEN ||
		iCredentialIdLen > iAuthenticatorDataLen - 55 || memcmp(pAuthenticatorData + 55, pCredentialId, iCredentialIdLen))
	{
		return FALSE;
	}
	fido_cbor_reader_t tReader = {
		pAuthenticatorData + 55 + iAuthenticatorCredentialIdLen,
		pAuthenticatorData + iAuthenticatorDataLen
	};

	BYTE iMajor;
	ULONGLONG iMapCount;
	if (!cert_fido_cbor_head(&tReader, &iMajor, &iMapCount) || iMajor != 5 ||
		iMapCount > (ULONGLONG)(tReader.pEnd - tReader.pData) / 2)
	{
		return FALSE;
	}

	LONG iKeyType = 0, iCoseAlgorithm = 0, iCurve = 0;
	LPCBYTE pX = NULL, pY = NULL;
	size_t iXLen = 0, iYLen = 0;
	BOOL bHaveKeyType = FALSE, bHaveAlgorithm = FALSE, bHaveCurve = FALSE;
	BOOL bHaveX = FALSE, bHaveY = FALSE;

	// Decode required COSE labels without depending on map order.
	for (ULONGLONG i = 0; i < iMapCount; i++)
	{
		LONG iLabel;
		if (!cert_fido_cbor_int(&tReader, &iLabel)) return FALSE;
		switch (iLabel)
		{
		case 1:
			if (bHaveKeyType || !cert_fido_cbor_int(&tReader, &iKeyType)) return FALSE;
			bHaveKeyType = TRUE;
			break;
		case 3:
			if (bHaveAlgorithm || !cert_fido_cbor_int(&tReader, &iCoseAlgorithm)) return FALSE;
			bHaveAlgorithm = TRUE;
			break;
		case -1:
			if (bHaveCurve || !cert_fido_cbor_int(&tReader, &iCurve)) return FALSE;
			bHaveCurve = TRUE;
			break;
		case -2:
			if (bHaveX || !cert_fido_cbor_bytes(&tReader, &pX, &iXLen)) return FALSE;
			bHaveX = TRUE;
			break;
		case -3:
			if (bHaveY || !cert_fido_cbor_bytes(&tReader, &pY, &iYLen)) return FALSE;
			bHaveY = TRUE;
			break;
		default:
			if (!cert_fido_cbor_skip(&tReader, 0)) return FALSE;
			break;
		}
	}

	if (!bHaveKeyType || !bHaveAlgorithm || !bHaveCurve || !bHaveX || iKeyType != pAlgorithm->iCoseKeyType ||
		iCoseAlgorithm != pAlgorithm->iCoseAlgorithm || iCurve != pAlgorithm->iCoseCurve ||
		iXLen != pAlgorithm->iSignaturePartSize ||
		(pAlgorithm->bEd25519 ? bHaveY : (!bHaveY || iYLen != pAlgorithm->iSignaturePartSize)) ||
		!cert_fido_public_key_valid(pAlgorithm, pX, pY))
	{
		return FALSE;
	}

	DWORD iCoordinateCount = pAlgorithm->bEd25519 ? 1 : 2;
	DWORD iPublicKeyLen = sizeof(BCRYPT_ECCKEY_BLOB) + iCoordinateCount * pAlgorithm->iSignaturePartSize;
	if (iPublicKeyLen > sizeof(*pPublicKey)) return FALSE;
	pPublicKey->tHeader.dwMagic = pAlgorithm->iPublicKeyMagic;
	pPublicKey->tHeader.cbKey = pAlgorithm->iSignaturePartSize;
	memcpy(pPublicKey->pCoordinates, pX, iXLen);
	if (!pAlgorithm->bEd25519)
		memcpy(pPublicKey->pCoordinates + iXLen, pY, iYLen);
	*piPublicKeyLen = iPublicKeyLen;
	return TRUE;
}

static BOOL cert_fido_store_credential(LPCWSTR sApplicationId, LPCBYTE pPublicKey, DWORD iPublicKeyLen,
	LPCBYTE pCredentialId, DWORD iCredentialIdLen, DWORD iUserVerification)
{
	if (sApplicationId == NULL || pPublicKey == NULL || pCredentialId == NULL || iCredentialIdLen == 0 ||
		iCredentialIdLen > FIDO_MAX_CREDID_LEN)
	{
		return FALSE;
	}

	BYTE pOldPublicKey[sizeof(fido_public_key_buffer_t)];
	BYTE pOldCredentialId[FIDO_MAX_CREDID_LEN];
	BYTE pOldUserVerification[sizeof(DWORD)];
	struct {
		LPCWSTR sKey;
		DWORD iType, iReadFlags;
		LPCVOID pNewValue;
		DWORD iNewLen;
		LPBYTE pOldValue;
		DWORD iOldLen, iOldCapacity;
		BOOL bPresent;
	} tValues[] = {
		{ FIDO_REG_PUBKEYS, REG_BINARY, RRF_RT_REG_BINARY, pPublicKey, iPublicKeyLen, pOldPublicKey, 0,
			sizeof(pOldPublicKey), FALSE },
		{ FIDO_REG_CREDIDS, REG_BINARY, RRF_RT_REG_BINARY, pCredentialId, iCredentialIdLen, pOldCredentialId, 0,
			sizeof(pOldCredentialId), FALSE },
		{ FIDO_REG_USERVER, REG_DWORD, RRF_RT_REG_DWORD, &iUserVerification, sizeof(DWORD), pOldUserVerification, 0,
			sizeof(pOldUserVerification), FALSE },
	};

	// Snapshot old values so failed updates cannot erase a working credential.
	for (size_t i = 0; i < _countof(tValues); i++)
	{
		tValues[i].iOldLen = tValues[i].iOldCapacity;
		LONG iResult = RegGetValueW(HKEY_CURRENT_USER, tValues[i].sKey, sApplicationId, tValues[i].iReadFlags,
			NULL, tValues[i].pOldValue, &tValues[i].iOldLen);
		if (iResult == ERROR_SUCCESS)
			tValues[i].bPresent = TRUE;
		else if (iResult != ERROR_FILE_NOT_FOUND && iResult != ERROR_PATH_NOT_FOUND)
			return FALSE;
	}

	for (size_t i = 0; i < _countof(tValues); i++)
	{
		if (RegSetKeyValueW(HKEY_CURRENT_USER, tValues[i].sKey, sApplicationId, tValues[i].iType,
			tValues[i].pNewValue, tValues[i].iNewLen) == ERROR_SUCCESS)
		{
			continue;
		}

		// Restore every prior value after a partial persistence failure.
		for (size_t j = 0; j < _countof(tValues); j++)
		{
			if (tValues[j].bPresent)
				RegSetKeyValueW(HKEY_CURRENT_USER, tValues[j].sKey, sApplicationId, tValues[j].iType,
					tValues[j].pOldValue, tValues[j].iOldLen);
			else
				RegDeleteKeyValueW(HKEY_CURRENT_USER, tValues[j].sKey, sApplicationId);
		}
		return FALSE;
	}

	return TRUE;
}

static BYTE* cert_fido_decode_assertion(LPCSTR sAlgorithm,
	LPCBYTE pSignature, DWORD iSignatureLen,
	LPCBYTE pAuthenticatorData, DWORD iAuthenticatorDataLen,
	int* piDecodedSignatureLen, PDWORD piCounter, PBYTE piFlags)
{
	if (piDecodedSignatureLen != NULL) *piDecodedSignatureLen = 0;
	if (piCounter != NULL) *piCounter = 0;
	if (piFlags != NULL) *piFlags = 0;
	if (pSignature == NULL || pAuthenticatorData == NULL ||
		piDecodedSignatureLen == NULL || piCounter == NULL || piFlags == NULL ||
		iAuthenticatorDataLen < 37)
	{
		return NULL;
	}

	const fido_algorithm_details_t* pAlgorithm =
		cert_fido_lookup_algorithm(sAlgorithm);
	if (pAlgorithm == NULL) return NULL;

	BYTE* pDecodedSignature = NULL;
	if (pAlgorithm->bEd25519)
	{
		if (iSignatureLen != 64) return NULL;
		pDecodedSignature = malloc(64);
		if (pDecodedSignature != NULL)
		{
			memcpy(pDecodedSignature, pSignature, 64);
			*piDecodedSignatureLen = 64;
		}
	}
	else
	{
		pDecodedSignature = malloc(2 * pAlgorithm->iSignaturePartSize);
		if (pDecodedSignature != NULL && cert_decode_ecdsa_signature(
			pSignature, iSignatureLen, pAlgorithm->iSignaturePartSize,
			pDecodedSignature))
		{
			*piDecodedSignatureLen =
				2 * pAlgorithm->iSignaturePartSize;
		}
		else
		{
			free(pDecodedSignature);
			pDecodedSignature = NULL;
		}
	}

	if (pDecodedSignature == NULL) return NULL;

	/* Authenticator data is rpIdHash[32], flags[1], signCount[4]. */
	*piFlags = pAuthenticatorData[32];
	*piCounter = ((DWORD)pAuthenticatorData[33] << 24) |
		((DWORD)pAuthenticatorData[34] << 16) |
		((DWORD)pAuthenticatorData[35] << 8) |
		(DWORD)pAuthenticatorData[36];
	return pDecodedSignature;
}

BYTE* cert_fido_sign(struct ssh2_userkey* userkey, LPCBYTE pDataToSign, int iDataToSignLen, int* iSigLen, LPCSTR sHashAlgName, PDWORD iCounter, PBYTE iFlags)
{
	if (userkey == NULL || userkey->comment == NULL || iSigLen == NULL || iCounter == NULL || iFlags == NULL || sHashAlgName == NULL)
	{
		return NULL;
	}
	*iSigLen = 0;

	// sanity check for webauthn support
	if (!LoadDelayLoadedLibaries()) return NULL;

	//  convert to unicode 
	LPSTR szAppId = &userkey->comment[IDEN_FIDO_SIZE];
	WCHAR szAppIdUnicode[FIDO_MAX_APPID_LEN] = L"";
	if (MultiByteToWideChar(CP_UTF8, 0, szAppId, -1, szAppIdUnicode, _countof(szAppIdUnicode)) == 0) return NULL;

	//  determine with algorithm to sign with 
	const fido_algorithm_details_t* pAlgorithm = cert_fido_lookup_algorithm(sHashAlgName);
	if (pAlgorithm == NULL) return NULL;

	// Fetch the complete credential ID for nonresident keys.
	PBYTE pCredentialId = NULL;
	DWORD iCredentialIdLen = 0;
	LONG iCredentialResult = RegGetValueW(HKEY_CURRENT_USER, FIDO_REG_CREDIDS, szAppIdUnicode,
		RRF_RT_REG_BINARY, NULL, NULL, &iCredentialIdLen);
	if (iCredentialResult == ERROR_SUCCESS)
	{
		if (iCredentialIdLen == 0 || iCredentialIdLen > FIDO_MAX_CREDID_LEN)
			return NULL;
		pCredentialId = malloc(iCredentialIdLen);
		if (pCredentialId == NULL || RegGetValueW(HKEY_CURRENT_USER, FIDO_REG_CREDIDS, szAppIdUnicode,
			RRF_RT_REG_BINARY, NULL, pCredentialId, &iCredentialIdLen) != ERROR_SUCCESS)
		{
			free(pCredentialId);
			return NULL;
		}
	}
	else if (iCredentialResult != ERROR_FILE_NOT_FOUND && iCredentialResult != ERROR_PATH_NOT_FOUND)
	{
		return NULL;
	}

	//  fetch user verification id from registry
	DWORD iUserVerification = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
	DWORD iUserVerificationReg = 0;
	DWORD iUserVerificationSize = sizeof(iUserVerificationReg);
	if (RegGetValueW(HKEY_CURRENT_USER, FIDO_REG_USERVER, szAppIdUnicode,
		RRF_RT_REG_DWORD, NULL, &iUserVerificationReg, &iUserVerificationSize) == ERROR_SUCCESS)
	{
		if (iUserVerificationReg == WEBAUTHN_USER_VERIFICATION_OPTIONAL ||
			iUserVerificationReg == WEBAUTHN_USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST)
			iUserVerification = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED;
	}

	//  setup data to sign 
	WEBAUTHN_CLIENT_DATA tClientData = { WEBAUTHN_CLIENT_DATA_CURRENT_VERSION };
	tClientData.cbClientDataJSON = iDataToSignLen;
	tClientData.pbClientDataJSON = (PBYTE)pDataToSign;
	tClientData.pwszHashAlgId = pAlgorithm->sHashAlgorithm;

	//  identify credential list (technically only required for non-resident keys) 
	WEBAUTHN_CREDENTIAL tCredential = { WEBAUTHN_CREDENTIAL_CURRENT_VERSION };
	tCredential.cbId = iCredentialIdLen;
	tCredential.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
	tCredential.pbId = pCredentialId;

	//  setup assertion options 
	BOOL bUtfAppId = FALSE;
	WEBAUTHN_CREDENTIALS tCredList = { 1, &tCredential };
	WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS tAssertionOptions = { WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION };
	if (iCredentialIdLen != 0) tAssertionOptions.CredentialList = tCredList;
	tAssertionOptions.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY;
	tAssertionOptions.dwUserVerificationRequirement = iUserVerification;
	tAssertionOptions.pbU2fAppId = &bUtfAppId;

	//  fetch assertion 
	struct GetAttestationThreadParams pParams = { 0 };
	pParams.hWnd = GetForegroundWindow();
	pParams.pWebAuthNClientData = &tClientData;
	pParams.pWebAuthNGetAssertionOptions = &tAssertionOptions;
	pParams.pwszRpId = szAppIdUnicode;
	HANDLE hThread = CreateThread(NULL, 0, WebAuthNAuthenticatorGetAssertionThread, &pParams, 0, NULL);
	if (hThread == NULL)
	{
		free(pCredentialId);
		return NULL;
	}

	// wait for message to complete
	if (pParams.hWnd != NULL && GetWindowThreadProcessId(pParams.hWnd, NULL) == GetCurrentThreadId())
	{
		for (MSG tMsg; GetMessage(&tMsg, NULL, 0, 0) > 0;)
		{
			if (tMsg.message == WM_USER) break;
			TranslateMessage(&tMsg);
			DispatchMessage(&tMsg);
		}
	}

	// wait for thread to complete
	DWORD iExitCode;
	WaitForSingleObject(hThread, INFINITE);
	GetExitCodeThread(hThread, &iExitCode);
	CloseHandle(hThread);
	if (iExitCode != 0)
	{
		free(pCredentialId);
		return NULL;
	}
	if (pParams.ppWebAuthNAssertion == NULL)
	{
		free(pCredentialId);
		return NULL;
	}

	BYTE* Signature = cert_fido_decode_assertion(sHashAlgName,
		pParams.ppWebAuthNAssertion->pbSignature,
		pParams.ppWebAuthNAssertion->cbSignature,
		pParams.ppWebAuthNAssertion->pbAuthenticatorData,
		pParams.ppWebAuthNAssertion->cbAuthenticatorData,
		iSigLen, iCounter, iFlags);

	//  cleanup 
	WebAuthNFreeAssertion(pParams.ppWebAuthNAssertion);
	free(pCredentialId);
	return Signature;
}

BOOL cert_fido_test_hash(LPCSTR szCert, DWORD iHashRequest)
{
	return TRUE;
}

static BOOL cert_fido_get_cert(PBCRYPT_ECCKEY_BLOB pPubKeyBlob, DWORD iPublicKeyBufferSize,
	LPWSTR sApplicationId, PCERT_CONTEXT* ppCertCtx)
{
	if (ppCertCtx == NULL) return FALSE;
	*ppCertCtx = NULL;
	if (pPubKeyBlob == NULL || sApplicationId == NULL ||
		iPublicKeyBufferSize < sizeof(BCRYPT_ECCKEY_BLOB))
	{
		return FALSE;
	}

	const fido_algorithm_details_t* pAlgorithm = NULL;
	for (size_t i = 0; i < _countof(fido_algorithms); i++)
	{
		if (pPubKeyBlob->dwMagic == fido_algorithms[i].iPublicKeyMagic &&
			pPubKeyBlob->cbKey == fido_algorithms[i].iSignaturePartSize)
		{
			pAlgorithm = &fido_algorithms[i];
			break;
		}
	}
	if (pAlgorithm == NULL) return FALSE;
	DWORD iCoordinateCount = pAlgorithm->bEd25519 ? 1 : 2;

	if (iPublicKeyBufferSize != sizeof(BCRYPT_ECCKEY_BLOB) +
		iCoordinateCount * pPubKeyBlob->cbKey)
	{
		return FALSE;
	}
	LPCBYTE pCoordinates = (LPCBYTE)(pPubKeyBlob + 1);
	if (!cert_fido_public_key_valid(pAlgorithm, pCoordinates,
		pAlgorithm->bEd25519 ? NULL : pCoordinates + pAlgorithm->iSignaturePartSize))
	{
		return FALSE;
	}

	//  determine algorithm for cert creation
	fido_public_key_buffer_t tPublicKeyTemp = { 0 };
	LPSTR sAlgo = NULL;
	if (pPubKeyBlob->dwMagic == BCRYPT_ECDSA_PUBLIC_P256_MAGIC) sAlgo = szOID_ECDSA_SHA256;
	if (pPubKeyBlob->dwMagic == BCRYPT_ECDSA_PUBLIC_P384_MAGIC) sAlgo = szOID_ECDSA_SHA384;
	if (pPubKeyBlob->dwMagic == BCRYPT_ECDSA_PUBLIC_P521_MAGIC) sAlgo = szOID_ECDSA_SHA512;
	if (pPubKeyBlob->dwMagic == BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC)
	{
		// windows does not support eddsa so we mark it ecdsa and adjust in other functions
		sAlgo = szOID_ED25519;
		memcpy(&tPublicKeyTemp, pPubKeyBlob, iPublicKeyBufferSize);
		pPubKeyBlob = &tPublicKeyTemp.tHeader;
		pPubKeyBlob->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
	}

	//  get crypto handle 
	NCRYPT_PROV_HANDLE hProvider = (NCRYPT_PROV_HANDLE)NULL;
	if (NCryptOpenStorageProvider(&hProvider, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS)
	{
		return FALSE;
	}

	//  import key data
	NCRYPT_KEY_HANDLE hKeyHandle = 0;
	DWORD iImportFlags = pAlgorithm->bEd25519 ? BCRYPT_NO_KEY_VALIDATION : 0;
	SECURITY_STATUS iResult = NCryptImportKey(hProvider, (NCRYPT_KEY_HANDLE)NULL, BCRYPT_ECCPUBLIC_BLOB, NULL,
		&hKeyHandle, (PBYTE)pPubKeyBlob, sizeof(BCRYPT_ECCKEY_BLOB) + (pPubKeyBlob->cbKey * 2), iImportFlags);
	if (iResult != ERROR_SUCCESS || hKeyHandle == (NCRYPT_KEY_HANDLE)NULL)
	{
		NCryptFreeObject(hProvider);
		return FALSE;
	}

	// convert the application name to a subject name to store in the cert for identification
	WCHAR szSubjectName[32];
	CERT_NAME_BLOB SubjectName = { sizeof(szSubjectName), (PBYTE)szSubjectName };
	if (CertStrToNameW(X509_ASN_ENCODING, L"CN=PuTTY FIDO", CERT_X500_NAME_STR | CERT_NAME_STR_SEMICOLON_FLAG,
		NULL, SubjectName.pbData, &SubjectName.cbData, NULL) != 0)
	{
		// create the certificate and add to store
		SYSTEMTIME tSystemTime;
		GetSystemTime(&tSystemTime);
		CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm = { sAlgo, 0 };
		*ppCertCtx = CertCreateSelfSignCertificate(hKeyHandle, &SubjectName,
			CERT_CREATE_SELFSIGN_NO_SIGN | CERT_CREATE_SELFSIGN_NO_KEY_INFO, NULL,
			&SignatureAlgorithm, &tSystemTime, &tSystemTime, NULL);

		// store the application id as an attribute on the certificate
		if (*ppCertCtx != NULL)
		{
			CRYPT_DATA_BLOB tAppId = { (wcslen(sApplicationId) + 1) * sizeof(WCHAR), (PBYTE)sApplicationId };
			CertSetCertificateContextProperty(*ppCertCtx, CERT_FRIENDLY_NAME_PROP_ID, 0, (LPVOID)&tAppId);
		}
	}

	// cleanup
	NCryptFreeObject(hKeyHandle);
	NCryptFreeObject(hProvider);
	return (*ppCertCtx != NULL);
}

void cert_fido_load_cert(LPCSTR szCert, PCCERT_CONTEXT* ppCertCtx, HCERTSTORE* phStore)
{
	// default output to cert not found
	*ppCertCtx = NULL;
	*phStore = NULL;

	// split on the hint symbol to get the appid
	LPSTR sApplicationId = IDEN_SPLIT(szCert);

	// convert to unicode in order to 
	WCHAR szAppIdUnicode[FIDO_MAX_APPID_LEN] = L"";
	if (MultiByteToWideChar(CP_UTF8, 0, sApplicationId, -1, szAppIdUnicode, _countof(szAppIdUnicode)) == 0) return;

	// fetch value from registry
	fido_public_key_buffer_t tPublicKey;
	DWORD iPublicKeyBufferSize = sizeof(tPublicKey);
	if (RegGetValueW(HKEY_CURRENT_USER, FIDO_REG_PUBKEYS, szAppIdUnicode, RRF_RT_REG_BINARY,
		NULL, &tPublicKey, &iPublicKeyBufferSize) != ERROR_SUCCESS)
	{
		return;
	}

	// convert public key to a certificate
	cert_fido_get_cert(&tPublicKey.tHeader, iPublicKeyBufferSize, szAppIdUnicode, ppCertCtx);
}


HCERTSTORE cert_fido_get_cert_store()
{
	// open a memory-based cert store to store the certificate context i
	HCERTSTORE hStoreHandle = CertOpenStore(CERT_STORE_PROV_MEMORY,
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
	if (NULL == hStoreHandle)
	{
		return NULL;
	}

	HKEY hEnumKey = NULL;
	if (RegOpenKeyExW(HKEY_CURRENT_USER, FIDO_REG_PUBKEYS, 0, KEY_READ, &hEnumKey) != ERROR_SUCCESS)
	{
		return hStoreHandle;
	}

	// enum over cached keys in registry
	fido_public_key_buffer_t tPublicKey;
	WCHAR sApplicationId[FIDO_MAX_APPID_LEN];
	for (int iIndex = 0; ; iIndex++)
	{
		DWORD iPublicKeyBufferSize = sizeof(tPublicKey);
		DWORD iApplicationIdSize = _countof(sApplicationId);
		if (RegEnumValueW(hEnumKey, iIndex, sApplicationId, &iApplicationIdSize,
			NULL, NULL, (PBYTE)&tPublicKey, &iPublicKeyBufferSize) != ERROR_SUCCESS) break;

		PCCERT_CONTEXT pCertContext = NULL;
		if (cert_fido_get_cert(&tPublicKey.tHeader, iPublicKeyBufferSize, sApplicationId, &pCertContext) == TRUE)
		{
			CertAddCertificateContextToStore(hStoreHandle, pCertContext, CERT_STORE_ADD_ALWAYS, NULL);
			CertFreeCertificateContext(pCertContext);
		}
	}

	RegCloseKey(hEnumKey);
	return hStoreHandle;
}

struct MakeCredentialThreadParams
{
	HWND hWnd;
	PCWEBAUTHN_RP_ENTITY_INFORMATION pRpInformation;
	PCWEBAUTHN_USER_ENTITY_INFORMATION pUserInformation;
	PCWEBAUTHN_COSE_CREDENTIAL_PARAMETERS pPubKeyCredParams;
	PCWEBAUTHN_CLIENT_DATA pWebAuthNClientData;
	PCWEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS pWebAuthNMakeCredentialOptions;
	PWEBAUTHN_CREDENTIAL_ATTESTATION ppWebAuthNCredentialAttestation;
};

DWORD WINAPI WebAuthNAuthenticatorMakeCredentialThread(LPVOID lpParam)
{
	struct MakeCredentialThreadParams* pParams = lpParam;

	HRESULT hMakeResult = WebAuthNAuthenticatorMakeCredential(pParams->hWnd, pParams->pRpInformation,
		pParams->pUserInformation, pParams->pPubKeyCredParams, pParams->pWebAuthNClientData,
		pParams->pWebAuthNMakeCredentialOptions, &pParams->ppWebAuthNCredentialAttestation);
	if (hMakeResult != S_OK)
	{
		if (pParams->hWnd != NULL) PostMessage(pParams->hWnd, WM_USER, 0, 0);
		ExitThread(1);
		return FALSE;
	}

	if (pParams->hWnd != NULL) PostMessage(pParams->hWnd, WM_USER, 0, 0);
	ExitThread(0);
	return TRUE;
}

BOOL fido_create_key(LPCSTR szAlgName, LPCSTR szDisplayName, LPCSTR szApplication, BOOL bResidentKey, BOOL bUserVerification)
{
	// sanity check for webauthn support
	if (!LoadDelayLoadedLibaries()) return FALSE;

	WCHAR szAppIdUnicode[FIDO_MAX_APPID_LEN];
	WCHAR szAppDisplayUnicode[FIDO_MAX_DISPLAY_LEN];

	if (MultiByteToWideChar(CP_UTF8, 0, szApplication, -1, szAppIdUnicode, _countof(szAppIdUnicode)) == 0) return FALSE;
	if (MultiByteToWideChar(CP_UTF8, 0, szDisplayName, -1, szAppDisplayUnicode, _countof(szAppDisplayUnicode)) == 0) return FALSE;

	LONG iWebAuthAlt = 0;
	LPCSTR sSecurityKeyAlgorithm = NULL;
	if (strcmp(szAlgName, "ecdsa-sha2-nistp256") == 0)
	{
		iWebAuthAlt = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256;
		sSecurityKeyAlgorithm = "sk-ecdsa-sha2-nistp256@openssh.com";
	}
	else if (strcmp(szAlgName, "ecdsa-sha2-nistp384") == 0)
	{
		iWebAuthAlt = WEBAUTHN_COSE_ALGORITHM_ECDSA_P384_WITH_SHA384;
		sSecurityKeyAlgorithm = "sk-ecdsa-sha2-nistp384@openssh.com";
	}
	else if (strcmp(szAlgName, "ecdsa-sha2-nistp521") == 0)
	{
		iWebAuthAlt = WEBAUTHN_COSE_ALGORITHM_ECDSA_P521_WITH_SHA512;
		sSecurityKeyAlgorithm = "sk-ecdsa-sha2-nistp521@openssh.com";
	}
	else if (strcmp(szAlgName, "ssh-ed25519") == 0)
	{
		iWebAuthAlt = WEBAUTHN_COSE_ALGORITHM_EDDSA_ED25519;
		sSecurityKeyAlgorithm = "sk-ssh-ed25519@openssh.com";
	}
	else
	{
		return FALSE;
	}
	const fido_algorithm_details_t* pAlgorithm =
		cert_fido_lookup_algorithm(sSecurityKeyAlgorithm);
	if (pAlgorithm == NULL) return FALSE;
	DWORD iSigBytes = pAlgorithm->iSignaturePartSize;

	WEBAUTHN_RP_ENTITY_INFORMATION tEntityInfo = { WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION };
	tEntityInfo.pwszName = szAppIdUnicode;
	tEntityInfo.pwszId = szAppIdUnicode;
	tEntityInfo.pwszIcon = NULL;

	WEBAUTHN_USER_ENTITY_INFORMATION tUserInfo = { WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION };
	tUserInfo.pwszDisplayName = szAppDisplayUnicode;
	tUserInfo.pwszName = szAppDisplayUnicode;
	tUserInfo.cbId = strlen(szDisplayName);
	tUserInfo.pbId = (PBYTE)szDisplayName;
	tUserInfo.pwszIcon = NULL;

	WEBAUTHN_COSE_CREDENTIAL_PARAMETER tCoseParam = { WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION };
	tCoseParam.lAlg = iWebAuthAlt;
	tCoseParam.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;

	WEBAUTHN_COSE_CREDENTIAL_PARAMETERS WebAuthNCredentialParameters = { 0 };
	WebAuthNCredentialParameters.cCredentialParameters = 1;
	WebAuthNCredentialParameters.pCredentialParameters = &tCoseParam;

	BYTE pRandomChallenge[FIDO_MAX_COORDINATE_LEN];
	if (BCryptGenRandom(NULL, pRandomChallenge, iSigBytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG)) return FALSE;

	WEBAUTHN_CLIENT_DATA WebAuthNClientData;
	WebAuthNClientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
	WebAuthNClientData.cbClientDataJSON = iSigBytes;
	WebAuthNClientData.pbClientDataJSON = pRandomChallenge;
	WebAuthNClientData.pwszHashAlgId = pAlgorithm->sHashAlgorithm;

	//  setup general creation options 
	WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS tCredentialOptions = {
		.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION
	};
	tCredentialOptions.bRequireResidentKey = bResidentKey;
	tCredentialOptions.dwUserVerificationRequirement = bUserVerification ? WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED : WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED;

	//  re-enforce user verification requirements 
	WEBAUTHN_CRED_PROTECT_EXTENSION_IN tCredProtect = { 0 };
	tCredProtect.dwCredProtect = bUserVerification ? WEBAUTHN_USER_VERIFICATION_REQUIRED : WEBAUTHN_USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST;
	tCredProtect.bRequireCredProtect = bUserVerification;
	WEBAUTHN_EXTENSION tCredProtectExt = { WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_PROTECT, sizeof(WEBAUTHN_CRED_PROTECT_EXTENSION_IN), &tCredProtect };
	if (bUserVerification)
	{
		tCredentialOptions.Extensions.cExtensions = 1;
		tCredentialOptions.Extensions.pExtensions = &tCredProtectExt;
	}

	//  create new credential on the key on a seperate thread
	struct MakeCredentialThreadParams pParams = { 0 };
	pParams.hWnd = GetForegroundWindow();
	pParams.pPubKeyCredParams = &WebAuthNCredentialParameters;
	pParams.pRpInformation = &tEntityInfo;
	pParams.pUserInformation = &tUserInfo;
	pParams.pWebAuthNClientData = &WebAuthNClientData;
	pParams.pWebAuthNMakeCredentialOptions = &tCredentialOptions;
	HANDLE hThread = CreateThread(NULL, 0, WebAuthNAuthenticatorMakeCredentialThread, &pParams, 0, NULL);
	if (hThread == NULL) return FALSE;

	// wait for message to complete
	if (pParams.hWnd != NULL && GetWindowThreadProcessId(pParams.hWnd, NULL) == GetCurrentThreadId())
	{
		for (MSG tMsg; GetMessage(&tMsg, NULL, 0, 0) > 0; )
		{
			if (tMsg.message == WM_USER) break;
			TranslateMessage(&tMsg);
			DispatchMessage(&tMsg);
		}
	}

	// wait for thread to complete
	DWORD iExitCode;
	WaitForSingleObject(hThread, INFINITE);
	GetExitCodeThread(hThread, &iExitCode);
	CloseHandle(hThread);
	if (iExitCode != 0) return FALSE;

	PWEBAUTHN_CREDENTIAL_ATTESTATION pAttestation = pParams.ppWebAuthNCredentialAttestation;
	if (pAttestation == NULL || pAttestation->pbAuthenticatorData == NULL || pAttestation->pbCredentialId == NULL ||
		pAttestation->cbCredentialId == 0 || pAttestation->cbCredentialId > FIDO_MAX_CREDID_LEN)
	{
		if (pAttestation != NULL)
			WebAuthNFreeCredentialAttestation(pAttestation);
		return FALSE;
	}

	// Decode and persist only a fully validated credential.
	fido_public_key_buffer_t tPublicKey;
	DWORD iPublicKeyLen = 0;
	BOOL bDecoded = cert_fido_decode_credential(sSecurityKeyAlgorithm, pAttestation->pbAuthenticatorData,
		pAttestation->cbAuthenticatorData, pAttestation->pbCredentialId, pAttestation->cbCredentialId,
		&tPublicKey, &iPublicKeyLen);
	BOOL bStored = bDecoded && cert_fido_store_credential(szAppIdUnicode, (LPCBYTE)&tPublicKey, iPublicKeyLen,
		pAttestation->pbCredentialId, pAttestation->cbCredentialId, tCredProtect.dwCredProtect);
	WebAuthNFreeCredentialAttestation(pAttestation);
	return bStored;
}

LPWSTR fido_get_user_id()
{
	// obtain handle to current process to lookup key
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken) == FALSE)
	{
		return NULL;
	}

	// Read the bounded token-user record directly into stack storage.
	LPWSTR sSidString = NULL;
	union {
		TOKEN_USER tUser;
		BYTE pData[TOKEN_USER_MAX_SIZE];
	} tTokenUser;
	DWORD dwBufferSize = sizeof(tTokenUser);
	PTOKEN_USER pTokenUser = (PTOKEN_USER)tTokenUser.pData;
	if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwBufferSize, &dwBufferSize) &&
		IsValidSid(pTokenUser->User.Sid))
	{
		ConvertSidToStringSidW(pTokenUser->User.Sid, &sSidString);
	}

	// cleanup and sanity check results
	CloseHandle(hToken);
	return sSidString;
}

BOOL fido_delete_key(LPCSTR szCert)
{
	// split on the hint symbol to get the appid
	LPSTR sApplicationId = IDEN_SPLIT(szCert);
	WCHAR szAppIdUnicode[FIDO_MAX_APPID_LEN];
	if (MultiByteToWideChar(CP_UTF8, 0, sApplicationId, -1, szAppIdUnicode, _countof(szAppIdUnicode)) == 0) return FALSE;

	// get current user sid
	LPWSTR sSidString = fido_get_user_id();
	if (sSidString == NULL) return FALSE;

	// construct path to puttyimp from the current directory
	WCHAR szProgPath[MAX_PATH];
	GetModuleFileNameW(NULL, szProgPath, MAX_PATH);
	wcsrchr(szProgPath, '\\')[1] = '\0';
	wcscat(szProgPath, L"puttyimp.exe");
	WCHAR szParams[MAX_PATH];
	wsprintfW(szParams, L"--delete-fido \"%s\" \"%s\"", szAppIdUnicode, sSidString);
	LocalFree(sSidString);

	// warn user about elevation prompt user
	MessageBoxW(NULL, L"PuTTY will now launch the PuTTYImp process to delete the " \
		L"selected key. This may result in an elevation prompt depending your current " \
		L"system settings.", L"FIDO Key Delete", MB_SYSTEMMODAL | MB_ICONINFORMATION | MB_OK);

	// launch importer
	if ((INT_PTR)ShellExecuteW(GetForegroundWindow(),
		L"runas", szProgPath, szParams, NULL, SW_SHOW) <= 32)
	{
		// notify user upon error
		MessageBoxW(NULL, L"The PuTTYImp process failed to launch properly. You may "
			L"have not have the appropriate privileges or PuTTYImp was not found. Please "
			L"ensure that PuTTYImp.exe is downloaded in same directory as this executable.",
			L"FIDO Key Importer Failed", MB_SYSTEMMODAL | MB_ICONERROR | MB_OK);
		return FALSE;
	}

	return TRUE;
}

VOID fido_import_keys()
{
	// get current user sid
	LPWSTR sSidString = fido_get_user_id();
	if (sSidString == NULL) return;

	// construct path to puttyimp from the current directory
	WCHAR szProgPath[MAX_PATH];
	GetModuleFileNameW(NULL, szProgPath, MAX_PATH);
	wcsrchr(szProgPath, '\\')[1] = '\0';
	wcscat(szProgPath, L"puttyimp.exe");
	WCHAR szParams[MAX_PATH];
	wsprintfW(szParams, L"--import-fido %s", sSidString);
	LocalFree(sSidString);

	// warn user about elevation prompt user
	MessageBoxW(NULL, L"PuTTY will now launch the PuTTYImp process to search for any FIDO " \
		L"resident keys to import. This requires access to communicate directly with " \
		L" your key(s) and may result in an elevation prompt depending your current " \
		L"system settings.", L"FIDO Key Importer", MB_SYSTEMMODAL | MB_ICONINFORMATION | MB_OK);

	// launch importer
	if ((INT_PTR)ShellExecuteW(GetForegroundWindow(),
		L"runas", szProgPath, szParams, NULL, SW_SHOW) <= 32)
	{
		// notify user upon error
		MessageBoxW(NULL, L"The PuTTYImp process failed to launch properly. You may "
			L"have not have the appropriate privileges or PuTTYImp was not found. Please "
			L"ensure that PuTTYImp.exe is downloaded in same directory as this executable.",
			L"FIDO Key Importer Failed", MB_SYSTEMMODAL | MB_ICONERROR | MB_OK);
	}
}

LPSTR fido_import_openssh_key()
{
	// get the default directory for the file browser
	char* szBaseDir = dupprintf("%s\\.ssh", getenv("USERPROFILE"));
	if (GetFileAttributesA(szBaseDir) == INVALID_FILE_ATTRIBUTES)
	{
		sfree(szBaseDir);
		szBaseDir = NULL;
		szBaseDir = _strdup(getenv("USERPROFILE"));
	}

	// get the file from the user
	char szFile[MAX_PATH + 1] = "\0";
	OPENFILENAME tFileNameInfo = { .lStructSize = sizeof(tFileNameInfo) };
	tFileNameInfo.hwndOwner = GetForegroundWindow();
	tFileNameInfo.lpstrFilter = "SSH Key Files (id_*_sk)\0id_*_sk\0All Files (*)\0*\0\0";
	tFileNameInfo.lpstrTitle = "Please Select SSH Security Key File To Import";
	tFileNameInfo.lpstrInitialDir = szBaseDir;
	tFileNameInfo.Flags = OFN_FORCESHOWHIDDEN | OFN_FILEMUSTEXIST;
	tFileNameInfo.lpstrFile = szFile;
	tFileNameInfo.nMaxFile = _countof(szFile);
	tFileNameInfo.nFilterIndex = 1;
	DWORD iResult = GetOpenFileName(&tFileNameInfo);
	sfree(szBaseDir);
	if (iResult == 0)
	{
		return NULL;
	}

	// attempt to get the key
	Filename* oFile = filename_from_str(szFile);
	ssh2_userkey* pKey = import_ssh2(oFile, SSH_KEYTYPE_OPENSSH_NEW, "", NULL);
	sfree(oFile);

	// Keep the standardized public-key blob in bounded stack storage.
	fido_public_key_buffer_t tPublicKey = { 0 };
	PBCRYPT_ECCKEY_BLOB pPublicKey = &tPublicKey.tHeader;

	char* szAppId = NULL;
	DWORD iFlags = 0;
	ptrlen* tPubKeyRaw = NULL;
	ptrlen* tCredId = NULL;
	ptrlen* szPubKey = NULL;

	// handle ecdsa import
	if (pKey != NULL && pKey->key != NULL && pKey->key->vt != NULL &&
		strstr(pKey->key->vt->ssh_id, "sk-ecdsa-") == pKey->key->vt->ssh_id)
	{
		struct ecdsa_key* ek = container_of(pKey->key, struct ecdsa_key, sshk);
		tPubKeyRaw = &ek->publicKeyRaw;
		tCredId = &ek->credId;
		szAppId = _strdup(ek->appid);
		iFlags = ek->flags;
		pPublicKey->cbKey = ek->publicKeyRaw.len / 2;
		pPublicKey->dwMagic =
			strcmp(pKey->key->vt->ssh_id, "sk-ecdsa-sha2-nistp256@openssh.com") == 0 ? BCRYPT_ECDSA_PUBLIC_P256_MAGIC :
			strcmp(pKey->key->vt->ssh_id, "sk-ecdsa-sha2-nistp384@openssh.com") == 0 ? BCRYPT_ECDSA_PUBLIC_P384_MAGIC :
			strcmp(pKey->key->vt->ssh_id, "sk-ecdsa-sha2-nistp521@openssh.com") == 0 ? BCRYPT_ECDSA_PUBLIC_P521_MAGIC :
			BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC;
	}

	// handle eddsa import
	else if (pKey != NULL && pKey->key != NULL && pKey->key->vt != NULL &&
		strstr(pKey->key->vt->ssh_id, "sk-ssh-ed25519") == pKey->key->vt->ssh_id)
	{
		struct eddsa_key* ek = container_of(pKey->key, struct eddsa_key, sshk);
		tPubKeyRaw = &ek->publicKeyRaw;
		tCredId = &ek->credId;
		szAppId = _strdup(ek->appid);
		iFlags = ek->flags;
		pPublicKey->cbKey = ek->publicKeyRaw.len;
		pPublicKey->dwMagic = BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC;
	}

	const fido_algorithm_details_t* pAlgorithm = pKey != NULL && pKey->key != NULL && pKey->key->vt != NULL ?
		cert_fido_lookup_algorithm(pKey->key->vt->ssh_id) : NULL;
	BOOL bPublicKeyValid = pAlgorithm != NULL && tPubKeyRaw != NULL &&
		tPubKeyRaw->len == pAlgorithm->iSignaturePartSize * (pAlgorithm->bEd25519 ? 1 : 2) &&
		cert_fido_public_key_valid(pAlgorithm, tPubKeyRaw->ptr,
			pAlgorithm->bEd25519 ? NULL : (LPCBYTE)tPubKeyRaw->ptr + pAlgorithm->iSignaturePartSize);

	// key load - upload to cache
	if (szAppId != NULL && bPublicKeyValid)
	{
		// copy public key part into blob
		memcpy(tPublicKey.pCoordinates, tPubKeyRaw->ptr, tPubKeyRaw->len);

		// convert to unicode for storing to registry
		WCHAR szAppIdUnicode[FIDO_MAX_APPID_LEN] = L"";
		BOOL bStored = tCredId != NULL && tCredId->len <= FIDO_MAX_CREDID_LEN && tCredId->len <= MAXDWORD &&
			MultiByteToWideChar(CP_UTF8, 0, szAppId, -1, szAppIdUnicode, _countof(szAppIdUnicode)) != 0;
		if (bStored)
		{
			bStored = cert_fido_store_credential(szAppIdUnicode, (LPCBYTE)pPublicKey,
				(DWORD)(sizeof(BCRYPT_ECCKEY_BLOB) + tPubKeyRaw->len), tCredId->ptr, (DWORD)tCredId->len, iFlags);
		}
		if (!bStored)
		{
			free(szAppId);
			szAppId = NULL;
		}
	}
	else if (szAppId != NULL)
	{
		free(szAppId);
		szAppId = NULL;
	}

	// key cleanup
	if (pKey != NULL)
	{
		if (pKey->key != NULL) ssh_key_free(pKey->key);
		if (pKey->comment != NULL) sfree(pKey->comment);
		sfree(pKey);
	}

	return szAppId;
}

VOID fido_clear_keys()
{
	if (MessageBoxW(NULL, L"This will delete PuTTY's record of any keys. " \
		L"Non-resident keys cannot be restored and resident keys will require " \
		L"local administrative access to import again. Do you wish to continue?",
		L"FIDO Cache Deletion Warning", MB_SYSTEMMODAL | MB_ICONINFORMATION | MB_YESNO) == IDYES)
	{
		RegDeleteTreeW(HKEY_CURRENT_USER, FIDO_REG_PUBKEYS);
		RegDeleteTreeW(HKEY_CURRENT_USER, FIDO_REG_USERVER);
		RegDeleteTreeW(HKEY_CURRENT_USER, FIDO_REG_CREDIDS);
	}
}

#endif

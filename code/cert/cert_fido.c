#ifdef PUTTY_CAC

#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <wincred.h>
#include <sddl.h>
#include <webauthn.h>

#include "ssh.h"

#define DEFINE_VARIABLES
#include "cert_fido.h"
#undef DEFINE_VARIABLES

#include "cert_common.h"

#pragma comment(lib,"crypt32.lib")
#pragma comment(lib,"credui.lib")
#pragma comment(lib,"ncrypt.lib")
#pragma comment(lib,"webauthn.lib")
#pragma comment(lib,"delayimp.lib")

// arbitrarily large limits for certain fido buffers
#define FIDO_MAX_APPID_LEN 256
#define FIDO_MAX_CREDID_LEN 128
#define FIDO_MAX_PUBKEY_LEN 128
#define FIDO_MAX_USERNAME_LEN 128
#define FIDO_MAX_BLOB_SIZE 512

// other arbitrary contacts
#define FIDO_KEY_USERNAME L"PuTTY FIDO User"

// registry key locations for fido
#define FIDO_REG_PUBKEYS L"Software\\SimonTatham\\PuTTY\\Fido\\PubKeyBlobs"
#define FIDO_REG_CREDIDS L"Software\\SimonTatham\\PuTTY\\Fido\\CredIdBlobs"
#define FIDO_REG_USERVER L"Software\\SimonTatham\\PuTTY\\Fido\\UserVerification"

// special define since not currently included in header
#ifndef WEBAUTHN_COSE_ALGORITHM_EDDSA_ED25519
#define WEBAUTHN_COSE_ALGORITHM_EDDSA_ED25519 -8
#endif

#pragma pack(push, 1)
typedef struct _cbor_ecdsa_response_header_t
{
	uint8_t RpHashId[32];
	uint8_t Flags;
	uint32_t Counter;
	uint8_t CredIdLeng[16];
	uint16_t Length;
}
cbor_ecdsa_response_header_t;

typedef struct _cbor_t
{
	uint8_t CountOrVal : 5;
	uint8_t MajorType : 3;
}
cbor_t;

typedef struct _cbor_ecdsa_pubkey_t
{
	// Map Type (5 Pairs) 
	cbor_t MapIden;

	// Map Key Type & Value    Map Value Type & Data 
	cbor_t KeyTypeMapKey;      cbor_t KeyTypeMapValue;
	cbor_t AlgIdMapKey;        cbor_t AlgIdMapValue;
	cbor_t CurveIdMapKey;      cbor_t CurveIdMapValue;
	union
	{
		struct
		{
			// Map Key Type & Value   Map Value Type         Map Value Data 
			cbor_t PubKey1MapKey;     cbor_t Key1ValueType;  uint8_t Key1ValLen; uint8_t Key1Val[32];
			cbor_t PubKey2MapKey;     cbor_t Key2ValueType;  uint8_t Key2ValLen; uint8_t Key2Val[32];
		} Key256;
		struct
		{
			cbor_t PubKey1MapKey;     cbor_t Key1ValueType;  uint8_t Key1ValLen; uint8_t Key1Val[48];
			cbor_t PubKey2MapKey;     cbor_t Key2ValueType;  uint8_t Key2ValLen; uint8_t Key2Val[48];
		} Key384;
		struct
		{
			cbor_t PubKey1MapKey;     cbor_t Key1ValueType;  uint8_t Key1ValLen; uint8_t Key1Val[64];
			cbor_t PubKey2MapKey;     cbor_t Key2ValueType;  uint8_t Key2ValLen; uint8_t Key2Val[64];
		} Key521;
	};

}
cbor_ecdsa_t;

typedef struct _ecdsa_assertion_auth_header_t
{
	uint8_t RelyingPartyHash[32];
	uint8_t Flags;
	uint32_t Counter;
}
ecdsa_assertion_auth_header_t;
#pragma pack(pop)

struct GetAttestationThreadParams
{
	HWND hWnd;
	LPCWSTR pwszRpId;
	PCWEBAUTHN_CLIENT_DATA pWebAuthNClientData;
	PCWEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS pWebAuthNGetAssertionOptions;
	PWEBAUTHN_ASSERTION ppWebAuthNAssertion;
};

BOOL LoadDelayLoadedLibaries()
{
	static BOOL bImported = FALSE;
	if (!bImported)
	{
		bImported = LoadLibrary("webauthn.dll") != NULL;
		if (!bImported)
		{
			// notify if webauthn 
			MessageBoxW(NULL, L"PuTTY CAC FIDO support is not available on this platform.",
				L"FIDO Not Supported", MB_SYSTEMMODAL | MB_ICONERROR | MB_OK);
		}
	}

	return bImported;
}

DWORD WINAPI WebAuthNAuthenticatorGetAssertionThread(LPVOID lpParam)
{
	struct GetAttestationThreadParams* pParams = lpParam;

	HRESULT hMakeResult = WebAuthNAuthenticatorGetAssertion(pParams->hWnd, pParams->pwszRpId,
		pParams->pWebAuthNClientData, pParams->pWebAuthNGetAssertionOptions, &pParams->ppWebAuthNAssertion);
	if (hMakeResult != S_OK)
	{
		ExitThread(1);
		return FALSE;
	}

	if (pParams->hWnd != NULL) PostMessage(pParams->hWnd, WM_USER, 0, 0);
	ExitThread(0);
	return TRUE;
}

BYTE* cert_fido_sign(struct ssh2_userkey* userkey, LPCBYTE pDataToSign, int iDataToSignLen, int* iSigLen, LPCSTR sHashAlgName, PDWORD iCounter, PBYTE iFlags)
{
	// sanity check for webauthn support
	if (!LoadDelayLoadedLibaries()) return NULL;

	//  convert to unicode 
	LPSTR szAppId = &userkey->comment[IDEN_FIDO_SIZE];
	WCHAR szAppIdUnicode[FIDO_MAX_APPID_LEN] = L"";
	if (MultiByteToWideChar(CP_UTF8, 0, szAppId, -1, szAppIdUnicode, _countof(szAppIdUnicode)) == 0) return NULL;

	//  determine with algorithm to sign with 
	LPCWSTR sHashAlg = NULL;
	DWORD iSigPartSize = 0;
	if (strstr(sHashAlgName, "sk-ecdsa-sha2-nistp256") == sHashAlgName)
	{
		sHashAlg = WEBAUTHN_HASH_ALGORITHM_SHA_256;
		iSigPartSize = 0x20;
	}
	else if (strstr(sHashAlgName, "sk-ecdsa-sha2-nistp384") == sHashAlgName)
	{
		sHashAlg = WEBAUTHN_HASH_ALGORITHM_SHA_384;
		iSigPartSize = 0x30;
	}
	else if (strstr(sHashAlgName, "sk-ecdsa-sha2-nistp521") == sHashAlgName)
	{
		sHashAlg = WEBAUTHN_HASH_ALGORITHM_SHA_512;
		iSigPartSize = 0x40;
	}
	else if (strstr(sHashAlgName, "sk-ssh-ed25519") == sHashAlgName)
	{
		sHashAlg = WEBAUTHN_HASH_ALGORITHM_SHA_256;
		iSigPartSize = 0x20;
	}

	//  fetch credential id from registry 
	BYTE sCredIdBuffer[FIDO_MAX_CREDID_LEN] = { 0 };
	DWORD iCredIdBufferSize = sizeof(sCredIdBuffer);
	if (RegGetValueW(HKEY_CURRENT_USER, FIDO_REG_CREDIDS, szAppIdUnicode,
		RRF_RT_REG_BINARY, NULL, sCredIdBuffer, &iCredIdBufferSize) != ERROR_SUCCESS)
	{
		iCredIdBufferSize = 0;
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
	tClientData.pwszHashAlgId = sHashAlg;

	//  identify credential list (technically only required for non-resident keys) 
	WEBAUTHN_CREDENTIAL tCredential = { WEBAUTHN_CREDENTIAL_CURRENT_VERSION };
	tCredential.cbId = iCredIdBufferSize;
	tCredential.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
	tCredential.pbId = sCredIdBuffer;

	//  setup assertion options 
	BOOL bUtfAppId = FALSE;
	WEBAUTHN_CREDENTIALS tCredList = { 1, &tCredential };
	WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS tAssertionOptions = { WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION };
	if (iCredIdBufferSize != 0) tAssertionOptions.CredentialList = tCredList;
	tAssertionOptions.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY;
	tAssertionOptions.dwUserVerificationRequirement = iUserVerification;
	tAssertionOptions.pbU2fAppId = &bUtfAppId;

	//  fetch assertion 
	struct GetAttestationThreadParams pParams;
	pParams.hWnd = GetForegroundWindow();
	pParams.pWebAuthNClientData = &tClientData;
	pParams.pWebAuthNGetAssertionOptions = &tAssertionOptions;
	pParams.pwszRpId = szAppIdUnicode;
	HANDLE hThread = CreateThread(NULL, 0, WebAuthNAuthenticatorGetAssertionThread, &pParams, 0, NULL);
	if (hThread == NULL) return NULL;

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
	if (iExitCode != 0) return NULL;

	//  allocate and copy signature to compressed structure
	BYTE* Signature = NULL;
	if (strstr(sHashAlgName, "sk-ssh-ed25519") == sHashAlgName)
	{
		// eddsa
		Signature = malloc(pParams.ppWebAuthNAssertion->cbSignature);
		if (Signature == NULL) return NULL;
		memcpy(Signature, pParams.ppWebAuthNAssertion->pbSignature, pParams.ppWebAuthNAssertion->cbSignature);
		*iSigLen = pParams.ppWebAuthNAssertion->cbSignature;
	}
	else
	{
		// ecdsa
		const int iSigInitialOffset = 3;
		int iSigPartOffsetR = iSigInitialOffset + 1 + (pParams.ppWebAuthNAssertion->pbSignature[iSigInitialOffset] - iSigPartSize);
		int iSigPartOffsetS = iSigPartOffsetR + 1 + pParams.ppWebAuthNAssertion->pbSignature[iSigPartOffsetR + iSigPartSize + 1] + 1;
		if (iSigPartOffsetR < 0 || iSigPartOffsetS < 0) return NULL;
		Signature = malloc((*iSigLen = iSigPartSize * 2));
		if (Signature == NULL) return NULL;
		memcpy(&Signature[0], &pParams.ppWebAuthNAssertion->pbSignature[iSigPartOffsetR], iSigPartSize);
		memcpy(&Signature[iSigPartSize], &pParams.ppWebAuthNAssertion->pbSignature[iSigPartOffsetS], iSigPartSize);
	}

	//  return counter 
	ecdsa_assertion_auth_header_t* pAuthData = (ecdsa_assertion_auth_header_t*)&pParams.ppWebAuthNAssertion->pbAuthenticatorData[0];
	*iCounter = ntohl(pAuthData->Counter);
	*iFlags = pAuthData->Flags;

	//  cleanup 
	WebAuthNFreeAssertion(pParams.ppWebAuthNAssertion);
	return Signature;
}

BOOL fido_test_hash(LPCSTR szCert, DWORD iHashRequest)
{
	return FALSE;
}

BOOL cert_fido_get_cert(PBCRYPT_ECCKEY_BLOB pPubKeyBlob, DWORD iPublicKeyBufferSize, LPWSTR sApplicationId, PCERT_CONTEXT* ppCertCtx)
{
	//  sanity check 
	if (!(
		(pPubKeyBlob->dwMagic == BCRYPT_ECDSA_PUBLIC_P256_MAGIC && pPubKeyBlob->cbKey == 32) ||
		(pPubKeyBlob->dwMagic == BCRYPT_ECDSA_PUBLIC_P384_MAGIC && pPubKeyBlob->cbKey == 48) ||
		(pPubKeyBlob->dwMagic == BCRYPT_ECDSA_PUBLIC_P521_MAGIC && pPubKeyBlob->cbKey == 66) ||
		(pPubKeyBlob->dwMagic == BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC && pPubKeyBlob->cbKey == 32)))
	{
		return FALSE;
	}

	//  determine algorithm for cert creation
	BYTE pPubKeyBlobTemp[FIDO_MAX_BLOB_SIZE] = { 0 };
	LPSTR sAlgo = NULL;
	if (pPubKeyBlob->dwMagic == BCRYPT_ECDSA_PUBLIC_P256_MAGIC) sAlgo = szOID_ECDSA_SHA256;
	if (pPubKeyBlob->dwMagic == BCRYPT_ECDSA_PUBLIC_P384_MAGIC) sAlgo = szOID_ECDSA_SHA384;
	if (pPubKeyBlob->dwMagic == BCRYPT_ECDSA_PUBLIC_P521_MAGIC) sAlgo = szOID_ECDSA_SHA512;
	if (pPubKeyBlob->dwMagic == BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC)
	{
		// windows does not support eddsa so we mark it ecdsa and adjust in other functions
		pPubKeyBlob->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
		sAlgo = szOID_ED25119;
		memcpy(pPubKeyBlobTemp, pPubKeyBlob, iPublicKeyBufferSize);
		pPubKeyBlob = (PBCRYPT_ECCKEY_BLOB)&pPubKeyBlobTemp[0];
	}

	//  get crypto handle 
	NCRYPT_PROV_HANDLE hProvider = (NCRYPT_PROV_HANDLE)NULL;
	if (NCryptOpenStorageProvider(&hProvider, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS)
	{
		return FALSE;
	}

	//  import key data
	NCRYPT_KEY_HANDLE hKeyHandle = sizeof(BCRYPT_ECCKEY_BLOB) + (NCRYPT_KEY_HANDLE)NULL;
	SECURITY_STATUS iResult = NCryptImportKey(hProvider, (NCRYPT_KEY_HANDLE)NULL, BCRYPT_ECCPUBLIC_BLOB,
		NULL, &hKeyHandle, (PBYTE)pPubKeyBlob, sizeof(BCRYPT_ECCKEY_BLOB) + (pPubKeyBlob->cbKey * 2), BCRYPT_NO_KEY_VALIDATION);
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
	WCHAR szAppIdUnicode[FIDO_MAX_CREDID_LEN] = L"";
	if (MultiByteToWideChar(CP_UTF8, 0, sApplicationId, -1, szAppIdUnicode, _countof(szAppIdUnicode)) == 0) return;

	// fetch value from registry
	BYTE sPublicKeyBuffer[FIDO_MAX_PUBKEY_LEN];
	DWORD iPublicKeyBufferSize = sizeof(sPublicKeyBuffer);
	if (RegGetValueW(HKEY_CURRENT_USER, FIDO_REG_PUBKEYS, szAppIdUnicode, RRF_RT_REG_BINARY, NULL, sPublicKeyBuffer, &iPublicKeyBufferSize) != ERROR_SUCCESS)
	{
		return;
	}

	// convert public key to a certificate
	cert_fido_get_cert((PBCRYPT_ECCKEY_BLOB)sPublicKeyBuffer, iPublicKeyBufferSize, szAppIdUnicode, ppCertCtx);
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
	BYTE sPublicKeyBuffer[FIDO_MAX_PUBKEY_LEN];
	DWORD iPublicKeyBufferSize = sizeof(sPublicKeyBuffer);
	WCHAR sApplicationId[FIDO_MAX_APPID_LEN];
	DWORD iApplicationIdSize = _countof(sApplicationId);
	for (int iIndex = 0; RegEnumValueW(hEnumKey, iIndex, sApplicationId, &iApplicationIdSize,
		NULL, NULL, sPublicKeyBuffer, &iPublicKeyBufferSize) != ERROR_NO_MORE_ITEMS;
		iIndex++, iPublicKeyBufferSize = sizeof(sPublicKeyBuffer), iApplicationIdSize = _countof(sApplicationId))
	{
		PCCERT_CONTEXT pCertContext = NULL;
		if (cert_fido_get_cert((PBCRYPT_ECCKEY_BLOB)sPublicKeyBuffer, iPublicKeyBufferSize, sApplicationId, &pCertContext) == TRUE)
		{
			CertAddCertificateContextToStore(hStoreHandle, pCertContext, CERT_STORE_ADD_ALWAYS, NULL);
		}
	}

	CloseHandle(hEnumKey);
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
		ExitThread(1);
		return FALSE;
	}

	if (pParams->hWnd != NULL) PostMessage(pParams->hWnd, WM_USER, 0, 0);
	ExitThread(0);
	return TRUE;
}

BOOL fido_create_key(LPCSTR szAlgName, LPCSTR szApplication, BOOL bResidentKey, BOOL bUserVerification)
{
	// sanity check for webauthn support
	if (!LoadDelayLoadedLibaries()) return FALSE;

	WCHAR szAppIdUnicode[FIDO_MAX_APPID_LEN];
	if (MultiByteToWideChar(CP_UTF8, 0, szApplication, -1, szAppIdUnicode, _countof(szAppIdUnicode)) == 0) return FALSE;

	LONG iWebAuthAlt = 0;
	LONG iSigBytes = 0;
	LPCWSTR sWebAuthHashAlg = NULL;
	if (strcmp(szAlgName, "ecdsa-sha2-nistp256") == 0)
	{
		iWebAuthAlt = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256;
		sWebAuthHashAlg = WEBAUTHN_HASH_ALGORITHM_SHA_256;
		iSigBytes = 32;
	}
	else if (strcmp(szAlgName, "ecdsa-sha2-nistp384") == 0)
	{
		iWebAuthAlt = WEBAUTHN_COSE_ALGORITHM_ECDSA_P384_WITH_SHA384;
		sWebAuthHashAlg = WEBAUTHN_HASH_ALGORITHM_SHA_384;
		iSigBytes = 48;
	}
	else if (strcmp(szAlgName, "ecdsa-sha2-nistp521") == 0)
	{
		iWebAuthAlt = WEBAUTHN_COSE_ALGORITHM_ECDSA_P521_WITH_SHA512;
		sWebAuthHashAlg = WEBAUTHN_HASH_ALGORITHM_SHA_512;
		iSigBytes = 64;
	}
	else if (strcmp(szAlgName, "ssh-ed25519") == 0)
	{
		iWebAuthAlt = WEBAUTHN_COSE_ALGORITHM_EDDSA_ED25519;
		sWebAuthHashAlg = WEBAUTHN_HASH_ALGORITHM_SHA_256;
		iSigBytes = 32;
	}
	else
	{
		return FALSE;
	}

	WEBAUTHN_RP_ENTITY_INFORMATION tEntityInfo = { WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION };
	tEntityInfo.pwszName = szAppIdUnicode;
	tEntityInfo.pwszId = szAppIdUnicode;
	tEntityInfo.pwszIcon = NULL;

	WEBAUTHN_USER_ENTITY_INFORMATION tUserInfo = { WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION };
	tUserInfo.pwszDisplayName = FIDO_KEY_USERNAME;
	tUserInfo.pwszName = FIDO_KEY_USERNAME;
	tUserInfo.cbId = wcslen(FIDO_KEY_USERNAME) * 2;
	tUserInfo.pbId = (PBYTE)FIDO_KEY_USERNAME;
	tUserInfo.pwszIcon = NULL;

	WEBAUTHN_COSE_CREDENTIAL_PARAMETER tCoseParam = { WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION };
	tCoseParam.lAlg = iWebAuthAlt;
	tCoseParam.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;

	WEBAUTHN_COSE_CREDENTIAL_PARAMETERS WebAuthNCredentialParameters = { 0 };
	WebAuthNCredentialParameters.cCredentialParameters = 1;
	WebAuthNCredentialParameters.pCredentialParameters = &tCoseParam;

	BYTE pRandomChallenge[FIDO_MAX_PUBKEY_LEN];
	if (BCryptGenRandom(NULL, pRandomChallenge, iSigBytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG)) return FALSE;

	WEBAUTHN_CLIENT_DATA WebAuthNClientData;
	WebAuthNClientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
	WebAuthNClientData.cbClientDataJSON = iSigBytes;
	WebAuthNClientData.pbClientDataJSON = pRandomChallenge;
	WebAuthNClientData.pwszHashAlgId = sWebAuthHashAlg;

	//  setup general creation options 
	WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS tCredentialOptions;
	ZeroMemory(&tCredentialOptions, sizeof(tCredentialOptions));
	tCredentialOptions.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION;
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

	//  determine start of public key area 
	PBYTE pAuthData = pParams.ppWebAuthNCredentialAttestation->pbAuthenticatorData;
	cbor_ecdsa_response_header_t* pHeader = (cbor_ecdsa_response_header_t*)&pAuthData[0];
	const int iPubKeyOffset = sizeof(cbor_ecdsa_response_header_t) + htons(pHeader->Length);

	//  get pubic key area information 
	cbor_ecdsa_t* pPubKey = (cbor_ecdsa_t*)&pAuthData[iPubKeyOffset];

	//  allocate key blob and populate headers
	LONG iPubKeySize = iSigBytes * 2;
	PBCRYPT_ECCKEY_BLOB pPublicKey = calloc(sizeof(BCRYPT_ECCKEY_BLOB) + iPubKeySize, 1);
	PBYTE pPublicKeyParts = &((PBYTE)pPublicKey)[sizeof(BCRYPT_ECCKEY_BLOB)];
	pPublicKey->cbKey = iSigBytes;

	//  sanity checks and copy over key parts 
	if (iWebAuthAlt == WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256 &&
		pPubKey->Key256.Key1ValLen == iSigBytes && pPubKey->Key256.Key2ValLen == iSigBytes)
	{
		memcpy(&pPublicKeyParts[0], &pPubKey->Key256.Key1Val, iSigBytes);
		memcpy(&pPublicKeyParts[iSigBytes], &pPubKey->Key256.Key2Val, iSigBytes);
		pPublicKey->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
	}
	else if (iWebAuthAlt == WEBAUTHN_COSE_ALGORITHM_ECDSA_P384_WITH_SHA384 &&
		pPubKey->Key384.Key1ValLen == iSigBytes && pPubKey->Key384.Key2ValLen == iSigBytes)
	{
		memcpy(&pPublicKeyParts[0], &pPubKey->Key384.Key1Val, iSigBytes);
		memcpy(&pPublicKeyParts[iSigBytes], &pPubKey->Key384.Key2Val, iSigBytes);
		pPublicKey->dwMagic = BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
	}
	else if (iWebAuthAlt == WEBAUTHN_COSE_ALGORITHM_ECDSA_P521_WITH_SHA512 &&
		pPubKey->Key521.Key1ValLen == iSigBytes && pPubKey->Key521.Key2ValLen == iSigBytes)
	{
		memcpy(&pPublicKeyParts[0], &pPubKey->Key521.Key1Val, iSigBytes);
		memcpy(&pPublicKeyParts[iSigBytes], &pPubKey->Key521.Key2Val, iSigBytes);
		pPublicKey->dwMagic = BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
	}
	else if (iWebAuthAlt == WEBAUTHN_COSE_ALGORITHM_EDDSA_ED25519 &&
		pPubKey->Key256.Key1ValLen == iSigBytes)
	{
		iPubKeySize = iSigBytes;
		memcpy(&pPublicKeyParts[0], &pPubKey->Key256.Key1Val, iSigBytes);
		pPublicKey->dwMagic = BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC;
	}

	// commit data to registry
	RegSetKeyValueW(HKEY_CURRENT_USER, FIDO_REG_PUBKEYS, szAppIdUnicode, REG_BINARY,
		pPublicKey, iPubKeySize + sizeof(BCRYPT_ECCKEY_BLOB));
	RegSetKeyValueW(HKEY_CURRENT_USER, FIDO_REG_CREDIDS, szAppIdUnicode, REG_BINARY,
		pParams.ppWebAuthNCredentialAttestation->pbCredentialId, (DWORD)pParams.ppWebAuthNCredentialAttestation->cbCredentialId);
	RegSetKeyValueW(HKEY_CURRENT_USER, FIDO_REG_USERVER, szAppIdUnicode, REG_DWORD,
		&tCredProtect.dwCredProtect, sizeof(DWORD));

	// cleanup
	WebAuthNFreeCredentialAttestation(pParams.ppWebAuthNCredentialAttestation);
	return TRUE;
}

LPWSTR fido_get_user_id()
{
	// obtain handle to current process to lookup key
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken) == FALSE)
	{
		return NULL;
	}

	// lookup process information size
	LPWSTR sSidString = NULL;
	DWORD dwBufferSize = 0;
	GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize);
	if (dwBufferSize > 0)
	{
		// lookup process information
		PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwBufferSize);
		if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwBufferSize, &dwBufferSize) && IsValidSid(pTokenUser->User.Sid))
		{
			// acquire key name using 
			ConvertSidToStringSidW(pTokenUser->User.Sid, &sSidString);
		}
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
	if ((INT_PTR) ShellExecuteW(GetForegroundWindow(), 
		L"runas", szProgPath, szParams, NULL, SW_SHOW) <= 32)
	{
		// notify user upon error
		MessageBoxW(NULL, L"The PuTTYImp process failed to launch properly. You may "
			L"have not have the appropriate privileges or PuTTYImp was not found. Please "
			L"ensure that PuTTYImp.exe is downloaded in same directory as this executable.",
			L"FIDO Key Importer Failed", MB_SYSTEMMODAL | MB_ICONERROR | MB_OK);
		return;
	}
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
#ifdef PUTTY_CAC

#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>

#include "ssh.h"

#include "cert_common.h"

#define DEFINE_VARIABLES
#include "cert_capi.h"
#undef DEFINE_VARIABLES

#pragma comment(lib,"crypt32.lib")
#pragma comment(lib,"cryptui.lib")
#pragma comment(lib,"ncrypt.lib")

static BOOL cert_capi_ncrypt_key_matches(PCCERT_CONTEXT pCertCtx, NCRYPT_KEY_HANDLE hKey)
{
	DWORD iPublicKeyInfoSize = 0;
	if (!CryptExportPublicKeyInfo(hKey, 0, X509_ASN_ENCODING, NULL, &iPublicKeyInfoSize) || iPublicKeyInfoSize == 0)
	{
		return FALSE;
	}

	PCERT_PUBLIC_KEY_INFO pPublicKeyInfo = (PCERT_PUBLIC_KEY_INFO)snewn(iPublicKeyInfoSize, BYTE);
	BOOL bMatches = CryptExportPublicKeyInfo(hKey, 0, X509_ASN_ENCODING, pPublicKeyInfo, &iPublicKeyInfoSize) &&
		CertComparePublicKeyInfo(X509_ASN_ENCODING, pPublicKeyInfo, &pCertCtx->pCertInfo->SubjectPublicKeyInfo);
	sfree(pPublicKeyInfo);
	return bMatches;
}

// Open the matching private key through the named KSP or Microsoft bridges.
static BOOL cert_capi_open_ncrypt_key(PCCERT_CONTEXT pCertCtx, PCRYPT_KEY_PROV_INFO pProviderInfo,
	NCRYPT_PROV_HANDLE* phProvider, NCRYPT_KEY_HANDLE* phKey)
{
	*phProvider = 0;
	*phKey = 0;

	LPCWSTR szProviders[] = {
		pProviderInfo->pwszProvName,
		MS_SMART_CARD_KEY_STORAGE_PROVIDER,
		MS_KEY_STORAGE_PROVIDER
	};
	DWORD iOpenFlags = (pProviderInfo->dwFlags & CRYPT_MACHINE_KEYSET) ? NCRYPT_MACHINE_KEY_FLAG : 0;
	// Normalize CNG's provider-info sentinel to NCryptOpenKey's native value.
	DWORD iKeySpec = pProviderInfo->dwKeySpec == CERT_NCRYPT_KEY_SPEC ? 0 : pProviderInfo->dwKeySpec;
	for (size_t iProvider = 0; iProvider < ARRAYSIZE(szProviders); iProvider++)
	{
		if (NCryptOpenStorageProvider(phProvider, szProviders[iProvider], 0) == ERROR_SUCCESS &&
			NCryptOpenKey(*phProvider, phKey, pProviderInfo->pwszContainerName, iKeySpec, iOpenFlags) == ERROR_SUCCESS &&
			cert_capi_ncrypt_key_matches(pCertCtx, *phKey))
		{
			return TRUE;
		}

		// release partial handles before trying the next provider
		if (*phKey != 0) { NCryptFreeObject(*phKey); *phKey = 0; }
		if (*phProvider != 0) { NCryptFreeObject(*phProvider); *phProvider = 0; }
	}

	return FALSE;
}

void cert_capi_load_cert(LPCSTR szCert, PCCERT_CONTEXT* ppCertCtx, HCERTSTORE* phStore)
{
	HCERTSTORE hStore = cert_capi_get_cert_store();
	if (hStore == NULL)
	{
		return;
	}

	// convert the sha1 string from hex to binary
	BYTE pbThumb[SHA1_BINARY_SIZE];
	if (!cert_parse_sha1_selector(szCert, IDEN_CAPI, '\0', pbThumb, NULL))
	{
		CertCloseStore(hStore, 0);
		return;
	}

	// enumerate the store looking for the certificate
	PCCERT_CONTEXT pFindCertContext = NULL;
	while ((pFindCertContext = CertEnumCertificatesInStore(
		hStore, pFindCertContext)) != NULL)
	{
		if (cert_context_matches_sha1(pFindCertContext, pbThumb))
		{
			// we found a matching cert, return its context and owning store
			*phStore = hStore;
			*ppCertCtx = pFindCertContext;
			return;
		}
	}

	// cleanup
	CertCloseStore(hStore, 0);
}

BOOL cert_capi_test_hash(LPCSTR szCert, DWORD iHashRequest)
{
	// use flags to determine requested signature hash algorithm
	DWORD iHashAlg;
	LPCWSTR sHashAlgId;
	if (!cert_hash_alg(NULL, iHashRequest, &iHashAlg, &sHashAlgId))
		return FALSE;

	// get a handle to the certificate
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT pCertCtx = NULL;
	cert_capi_load_cert(szCert, &pCertCtx, &hCertStore);

	// sanity check
	if (hCertStore == NULL || pCertCtx == NULL)
	{
		return FALSE;
	}

	// stores whether the provider is capable of performing the hashing
	BOOL bHashSuccess = FALSE;

	// pull provider information from certificate
	PCRYPT_KEY_PROV_INFO pProviderInfo = NULL;
	DWORD iProviderInfoSize = 0;
	if (CertGetCertificateContextProperty(pCertCtx, CERT_KEY_PROV_INFO_PROP_ID, NULL, &iProviderInfoSize) != FALSE &&
		CertGetCertificateContextProperty(pCertCtx, CERT_KEY_PROV_INFO_PROP_ID,
			(pProviderInfo = (PCRYPT_KEY_PROV_INFO)snewn(iProviderInfoSize, BYTE)), &iProviderInfoSize) != FALSE)
	{
		HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProv = 0;
		NCRYPT_PROV_HANDLE hNCryptProv = 0;
		NCRYPT_KEY_HANDLE hNCryptKey = 0;

		if (cert_capi_open_ncrypt_key(pCertCtx, pProviderInfo, &hNCryptProv, &hNCryptKey))
		{
			// key is serviced through cng; report whether cng supports the hash
			BCRYPT_ALG_HANDLE hAlg = NULL;
			bHashSuccess = BCryptOpenAlgorithmProvider(&hAlg, sHashAlgId, NULL, 0) == 0;
			if (hAlg != NULL) BCryptCloseAlgorithmProvider(hAlg, 0);
		}
		else if (CryptAcquireContextW(&hCryptProv, pProviderInfo->pwszContainerName,
			pProviderInfo->pwszProvName, pProviderInfo->dwProvType,
			(pProviderInfo->dwFlags & CRYPT_MACHINE_KEYSET) ? CRYPT_MACHINE_KEYSET : 0) != FALSE)
		{
			// check if legacy csp can create a hash of this type
			HCRYPTHASH hHash = (ULONG_PTR)NULL;
			bHashSuccess = CryptCreateHash((HCRYPTPROV)hCryptProv, (ALG_ID)iHashAlg, 0, 0, &hHash) != FALSE;
			if (hHash != (ULONG_PTR)NULL) { CryptDestroyHash(hHash); }
		}

		// cleanup crypto structures and intermediate signing data
		if (hCryptProv != 0) CryptReleaseContext(hCryptProv, 0);
		if (hNCryptKey != 0) NCryptFreeObject(hNCryptKey);
		if (hNCryptProv != 0) NCryptFreeObject(hNCryptProv);
	}

	// cleanup certificate handles and return
	if (pCertCtx != NULL) { CertFreeCertificateContext(pCertCtx); }
	if (hCertStore != NULL) { CertCloseStore(hCertStore, 0); }
	if (pProviderInfo != NULL) sfree(pProviderInfo);
	return bHashSuccess;
}

BYTE* cert_capi_sign(struct ssh2_userkey* userkey, LPCBYTE pDataToSign, int iDataToSignLen, int* iSigLen, LPCSTR sHashAlgName)
{
	// use flags to determine requested signature hash algorithm
	DWORD iHashAlg;
	LPCWSTR sHashAlgId;
	if (!cert_hash_alg(sHashAlgName, 0, &iHashAlg, &sHashAlgId))
		return NULL;

	// get a handle to the certificate
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT pCertCtx = NULL;
	cert_capi_load_cert(userkey->comment, &pCertCtx, &hCertStore);

	// sanity check
	if (hCertStore == NULL || pCertCtx == NULL)
	{
		return NULL;
	}

	// stores the address to the final signed data
	LPBYTE pSignedData = NULL;
	PCRYPT_KEY_PROV_INFO pProviderInfo = NULL;
	DWORD iProviderInfoSize = 0;
	if (CertGetCertificateContextProperty(pCertCtx, CERT_KEY_PROV_INFO_PROP_ID, NULL, &iProviderInfoSize) != FALSE &&
		CertGetCertificateContextProperty(pCertCtx, CERT_KEY_PROV_INFO_PROP_ID,
			(pProviderInfo = (PCRYPT_KEY_PROV_INFO)snewn(iProviderInfoSize, BYTE)), &iProviderInfoSize) != FALSE)
	{
		LPBYTE pSig = NULL;
		DWORD iSig = 0;

		HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProv = 0;
		NCRYPT_KEY_HANDLE hNCryptKey = 0;
		NCRYPT_PROV_HANDLE hNCryptProv = 0;

		if (cert_capi_open_ncrypt_key(pCertCtx, pProviderInfo, &hNCryptProv, &hNCryptKey))
		{
			// set pin prompt
			WCHAR* szPin = NULL;
			if (cert_cache_enabled(CERT_QUERY) &&
				(szPin = cert_pin(userkey->comment, TRUE, NULL)) != NULL)
			{
				DWORD iLength = (1 + wcslen(szPin)) * sizeof(WCHAR);
				(void)NCryptSetProperty(hNCryptKey, NCRYPT_PIN_PROPERTY, (PBYTE)szPin, iLength, 0);
			}

			// setup structure padding 
			DWORD iPadFlag = 0;
			BCRYPT_PKCS1_PADDING_INFO tInfo = { 0 };
			PVOID pPadInfo = NULL;
			if (cert_keyalg_is_rsa(userkey->key->vt))
			{
				tInfo.pszAlgId = sHashAlgId;
				iPadFlag = BCRYPT_PAD_PKCS1;
				pPadInfo = &tInfo;
			}

			// hash and sign
			DWORD iHashDataSize = 0;
			LPBYTE pHashData = cert_get_hash(sHashAlgName, pDataToSign, iDataToSignLen, &iHashDataSize, FALSE);
			if (pHashData != NULL &&
				NCryptSignHash(hNCryptKey, pPadInfo, pHashData, iHashDataSize, NULL, 0, &iSig, iPadFlag) == ERROR_SUCCESS &&
				NCryptSignHash(hNCryptKey, pPadInfo, pHashData, iHashDataSize, pSig = snewn(iSig, BYTE), iSig, &iSig, iPadFlag) == ERROR_SUCCESS)
			{
				pSignedData = pSig;
				*iSigLen = iSig;
				pSig = NULL;

				// add pin to cache if cache is enabled
				if (cert_cache_enabled(CERT_QUERY))
				{
					cert_pin(userkey->comment, TRUE, szPin);
				}
			}

			// cleanup hash structure and pin 
			if (szPin != NULL) { SecureZeroMemory(szPin, (1 + wcslen(szPin)) * sizeof(WCHAR)); free(szPin); }
			if (pHashData != NULL) { sfree(pHashData); }
		}
		else if (CryptAcquireContextW(&hCryptProv, pProviderInfo->pwszContainerName,
			pProviderInfo->pwszProvName, pProviderInfo->dwProvType,
			(pProviderInfo->dwFlags & CRYPT_MACHINE_KEYSET) ? CRYPT_MACHINE_KEYSET : 0) != FALSE)
		{
			// set pin prompt
			LPSTR szPin = NULL;
			if (cert_cache_enabled(CERT_QUERY) &&
				(szPin = cert_pin(userkey->comment, FALSE, NULL)) != NULL)
			{
				CryptSetProvParam(hCryptProv, (pProviderInfo->dwKeySpec ==
					AT_SIGNATURE) ? PP_SIGNATURE_PIN : PP_KEYEXCHANGE_PIN, (LPCBYTE)szPin, 0);
			}

			// CSP implementation
			HCRYPTHASH hHash = (ULONG_PTR)NULL;
			if (CryptCreateHash((HCRYPTPROV)hCryptProv, (ALG_ID)iHashAlg, 0, 0, &hHash) != FALSE &&
				CryptHashData(hHash, (LPBYTE)pDataToSign, iDataToSignLen, 0) != FALSE &&
				CryptSignHash(hHash, pProviderInfo->dwKeySpec, NULL, 0, NULL, &iSig) != FALSE &&
				CryptSignHash(hHash, pProviderInfo->dwKeySpec, NULL, 0, pSig = snewn(iSig, BYTE), &iSig) != FALSE)
			{
				cert_reverse_array(pSig, iSig);
				pSignedData = pSig;
				*iSigLen = iSig;
				pSig = NULL;

				// add pin to cache if cache is enabled
				if (cert_cache_enabled(CERT_QUERY))
				{
					cert_pin(userkey->comment, FALSE, szPin);
				}
			}

			// cleanup hash structure 
			if (szPin != NULL) { SecureZeroMemory(szPin, (strlen(szPin) + 1) * sizeof(CHAR)); free(szPin); }
			if (hHash != (ULONG_PTR)NULL) { CryptDestroyHash(hHash); }
		}

		// cleanup crypto structures and intermediate signing data
		if (hCryptProv != 0) CryptReleaseContext(hCryptProv, 0);
		if (hNCryptKey != 0) NCryptFreeObject(hNCryptKey);
		if (hNCryptProv != 0) NCryptFreeObject(hNCryptProv);
		if (pSig != NULL) sfree(pSig);
	}

	// cleanup certificate handles and return
	if (pCertCtx != NULL) { CertFreeCertificateContext(pCertCtx); }
	if (hCertStore != NULL) { CertCloseStore(hCertStore, 0); }
	if (pProviderInfo != NULL) sfree(pProviderInfo);
	return pSignedData;
}

HCERTSTORE cert_capi_get_cert_store()
{
	return CertOpenStore(CERT_STORE_PROV_SYSTEM_W, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0,
		CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_ENUM_ARCHIVED_FLAG, L"MY");
}

BOOL cert_capi_delete_key(LPCSTR szCert)
{
	// get a handle to the certificate
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT pCertCtx = NULL;
	cert_capi_load_cert(szCert, &pCertCtx, &hCertStore);
	if (pCertCtx == NULL) return FALSE;

	BOOL bSuccess = FALSE;
	PCRYPT_KEY_PROV_INFO pProviderInfo = NULL;
	DWORD iProviderInfoSize = 0;
	if (CertGetCertificateContextProperty(pCertCtx, CERT_KEY_PROV_INFO_PROP_ID, NULL, &iProviderInfoSize) != FALSE &&
		CertGetCertificateContextProperty(pCertCtx, CERT_KEY_PROV_INFO_PROP_ID,
			(pProviderInfo = (PCRYPT_KEY_PROV_INFO)snewn(iProviderInfoSize, BYTE)), &iProviderInfoSize) != FALSE)
	{
		HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProv = 0;
		NCRYPT_KEY_HANDLE hNCryptKey = 0;
		NCRYPT_PROV_HANDLE hNCryptProv = 0;

		if (cert_capi_open_ncrypt_key(pCertCtx, pProviderInfo, &hNCryptProv, &hNCryptKey))
		{
			bSuccess = NCryptDeleteKey(hNCryptKey, 0) == ERROR_SUCCESS;
			if (bSuccess) hNCryptKey = 0;
		}
		else if (CryptAcquireContextW(&hCryptProv, pProviderInfo->pwszContainerName,
			pProviderInfo->pwszProvName, pProviderInfo->dwProvType, CRYPT_DELETEKEYSET |
			((pProviderInfo->dwFlags & CRYPT_MACHINE_KEYSET) ? CRYPT_MACHINE_KEYSET : 0)) != FALSE)
		{
			bSuccess = TRUE;
		}

		// cleanup crypto structures and intermediate signing data
		if (hCryptProv != 0) CryptReleaseContext(hCryptProv, 0);
		if (hNCryptKey != 0) NCryptFreeObject(hNCryptKey);
		if (hNCryptProv != 0) NCryptFreeObject(hNCryptProv);
	}

	// cleanup certificate handles and return
	if (bSuccess) CertDeleteCertificateFromStore(pCertCtx);
	else if (pCertCtx != NULL) { CertFreeCertificateContext(pCertCtx); }
	if (hCertStore != NULL) { CertCloseStore(hCertStore, 0); }
	if (pProviderInfo != NULL) sfree(pProviderInfo);
	return bSuccess;
}

#endif // PUTTY_CAC

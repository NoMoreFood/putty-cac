#ifdef PUTTY_CAC

#pragma comment(lib,"crypt32.lib")
#pragma comment(lib,"cryptui.lib")
#pragma comment(lib,"ncrypt.lib")

#include <windows.h>
#include <wincrypt.h>
#include <cryptuiapi.h>
#include <cryptdlg.h>
#include <bcrypt.h>

#include "cert_common.h"

#define DEFINE_VARIABLES
#include "cert_capi.h"
#undef DEFINE_VARIABLES

BYTE * cert_capi_sign(struct ssh2_userkey * userkey, LPCBYTE pDataToSign, int iDataToSignLen, int * iSigLen, HWND hWnd)
{
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

		if (CryptAcquireContextW(&hCryptProv, pProviderInfo->pwszContainerName,
			pProviderInfo->pwszProvName, pProviderInfo->dwProvType,
			(pProviderInfo->dwFlags & CRYPT_MACHINE_KEYSET) ? CRYPT_MACHINE_KEYSET : 0) != FALSE)
		{
			// set window for any client 
			if (hWnd != NULL)
			{
				CryptSetProvParam(hCryptProv, PP_CLIENT_HWND, (LPBYTE)&hWnd, 0);
			}

			// set pin prompt
			LPSTR szPin = NULL;
			if (cert_cache_enabled((DWORD)-1) &&
				(szPin = cert_pin(userkey->comment, FALSE, NULL, hWnd)) != NULL)
			{
				CryptSetProvParam(hCryptProv, (pProviderInfo->dwKeySpec ==
					AT_SIGNATURE) ? PP_SIGNATURE_PIN : PP_KEYEXCHANGE_PIN, (LPCBYTE)szPin, 0);
			}

			// CSP implementation
			HCRYPTHASH hHash = (ULONG_PTR)NULL;
			if (CryptCreateHash((HCRYPTPROV)hCryptProv, CALG_SHA1, 0, 0, &hHash) != FALSE &&
				CryptHashData(hHash, (LPBYTE)pDataToSign, iDataToSignLen, 0) != FALSE &&
				CryptSignHash(hHash, pProviderInfo->dwKeySpec, NULL, 0, NULL, &iSig) != FALSE &&
				CryptSignHash(hHash, pProviderInfo->dwKeySpec, NULL, 0, pSig = snewn(iSig, BYTE), &iSig) != FALSE)
			{
				cert_reverse_array(pSig, iSig);
				pSignedData = pSig;
				*iSigLen = iSig;
				pSig = NULL;

				// add pin to cache if cache is enabled
				if (cert_cache_enabled((DWORD)-1))
				{
					cert_pin(userkey->comment, FALSE, szPin, hWnd);
				}
			}

			// cleanup hash structure 
			if (szPin != NULL) { SecureZeroMemory(szPin, strlen(szPin) * sizeof(CHAR)); free(szPin); }
			if (hHash != (ULONG_PTR)NULL) { CryptDestroyHash(hHash); }
		}
		else if (NCryptOpenStorageProvider(&hNCryptProv, pProviderInfo->pwszProvName, 0) == ERROR_SUCCESS &&
			NCryptOpenKey(hNCryptProv, &hNCryptKey, pProviderInfo->pwszContainerName, pProviderInfo->dwKeySpec, 0) == ERROR_SUCCESS)
		{
			// set window for any client
			if (hWnd != NULL)
			{
				NCryptSetProperty(hNCryptKey, NCRYPT_WINDOW_HANDLE_PROPERTY, (LPBYTE)&hWnd, sizeof(HWND), 0);
			}

			// set pin prompt
			WCHAR * szPin = NULL;
			if (cert_cache_enabled((DWORD)-1) &&
				(szPin = cert_pin(userkey->comment, TRUE, NULL, hWnd)) != NULL)
			{
				DWORD iLength = (1 + wcslen(szPin)) * sizeof(WCHAR);
				NCryptSetProperty(hNCryptKey, NCRYPT_PIN_PROPERTY, (PBYTE)szPin, iLength, 0);
			}

			// setup structure padding 
			DWORD iPadFlag = 0;
			BCRYPT_PKCS1_PADDING_INFO tInfo = { 0 };
			PVOID pPadInfo = NULL;
			if (strcmp(userkey->alg->name, "ssh-rsa") == 0)
			{
				tInfo.pszAlgId = NCRYPT_SHA1_ALGORITHM;
				iPadFlag = BCRYPT_PAD_PKCS1;
				pPadInfo = &tInfo;
			}

			// hash and sign
			DWORD iHashDataSize = 0;
			LPBYTE pHashData = cert_get_hash(userkey->alg->name, pDataToSign, iDataToSignLen, &iHashDataSize, FALSE);
			if (pHashData != NULL &&
				NCryptSignHash(hNCryptKey, pPadInfo, pHashData, iHashDataSize, NULL, 0, &iSig, iPadFlag) == ERROR_SUCCESS &&
				NCryptSignHash(hNCryptKey, pPadInfo, pHashData, iHashDataSize, pSig = snewn(iSig, BYTE), iSig, &iSig, iPadFlag) == ERROR_SUCCESS)
			{
				pSignedData = pSig;
				*iSigLen = iSig;
				pSig = NULL;

				// add pin to cache if cache is enabled
				if (cert_cache_enabled((DWORD)-1))
				{
					cert_pin(userkey->comment, TRUE, szPin, hWnd);
				}
			}

			// cleanup hash structure and pin 
			if (szPin != NULL) { SecureZeroMemory(szPin, wcslen(szPin) * sizeof(WCHAR)); free(szPin); }
			if (pHashData != NULL) { free(pHashData); }
		}

		// cleanup crypto structures and intermediate signing data
		if (hCryptProv != 0) CryptReleaseContext(hCryptProv, 0);
		if (hNCryptProv != 0) NCryptFreeObject(hNCryptProv);
		if (hNCryptKey != 0) NCryptFreeObject(hNCryptKey);
		if (pSig != NULL) sfree(pSig);
		if (pProviderInfo != NULL) sfree(pProviderInfo);
	}

	// cleanup certificate handles and return
	if (pCertCtx != NULL) { CertFreeCertificateContext(pCertCtx); }
	if (hCertStore != NULL) { CertCloseStore(hCertStore, 0); }
	return pSignedData;
}

HCERTSTORE cert_capi_get_cert_store(LPCSTR * szHint, HWND hWnd)
{
	UNREFERENCED_PARAMETER(hWnd);

	if (szHint != NULL) *szHint = NULL;
	return CertOpenStore(CERT_STORE_PROV_SYSTEM_W, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0,
		CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_ENUM_ARCHIVED_FLAG, L"MY");
}

void cert_capi_load_cert(LPCSTR szCert, PCCERT_CONTEXT* ppCertCtx, HCERTSTORE* phStore)
{
	HCERTSTORE hStore = cert_capi_get_cert_store(NULL, NULL);
	if (hStore == NULL)
	{
		return;
	}

	// more forward in the cert string to just have the cert hash
	LPCSTR szThumb = &szCert[IDEN_CAPI_SIZE];

	// convert the sha1 string from hex to binary 
	BYTE pbThumb[SHA1_BINARY_SIZE];
	CRYPT_HASH_BLOB cryptHashBlob;
	cryptHashBlob.cbData = SHA1_BINARY_SIZE;
	cryptHashBlob.pbData = pbThumb;
	CryptStringToBinary(szThumb, SHA1_HEX_SIZE, CRYPT_STRING_HEXRAW, cryptHashBlob.pbData,
		&cryptHashBlob.cbData, NULL, NULL);

	// enumerate the store looking for the certificate
	PCCERT_CONTEXT pFindCertContext = NULL;
	while ((pFindCertContext = CertFindCertificateInStore(hStore, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
		0, CERT_FIND_SHA1_HASH, &cryptHashBlob, pFindCertContext)) != NULL)
	{
		// we found a matching cert, return a copy of it 
		*phStore = hStore;
		*ppCertCtx = pFindCertContext;
		return;
	}

	// cleanup
	CertCloseStore(hStore, 0);
}

#endif // PUTTY_CAC
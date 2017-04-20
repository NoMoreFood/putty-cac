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

BYTE * cert_capi_sign(struct ssh2_userkey * userkey, const char* data, int datalen, int * siglen, HWND hWnd)
{
	// get a handle to the certificate
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT pCertCtx = NULL;
	cert_capi_load_cert(userkey->comment, &pCertCtx, &hCertStore);

	// sanity check
	if (hCertStore == NULL || pCertCtx == NULL)
	{
		return bignum_from_long(0);
	}

	BYTE * pSignedData = NULL;
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCrypt = (ULONG_PTR)NULL;
	DWORD dwKeySpec = 0;
	BOOL bMustFreeProvier = FALSE;

	if (CryptAcquireCertificatePrivateKey(pCertCtx, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG , NULL, &hCrypt, &dwKeySpec, &bMustFreeProvier) != FALSE)
	{
		PBYTE pbSig = NULL;
		DWORD cbSig = 0;

		// calculate hashed data 
		if (dwKeySpec == AT_KEYEXCHANGE || dwKeySpec == AT_SIGNATURE)
		{
			// set window for any client 
			CryptSetProvParam(hCrypt, PP_CLIENT_HWND, (PBYTE) &hWnd, 0);

			// CSP implementation
			HCRYPTHASH hHash = (ULONG_PTR)NULL;
			if (CryptCreateHash((HCRYPTPROV)hCrypt, CALG_SHA1, 0, 0, &hHash) != FALSE &&
				CryptHashData(hHash, (PBYTE)data, datalen, 0) != FALSE &&
				CryptSignHash(hHash, dwKeySpec, NULL, 0, NULL, &cbSig) != FALSE &&
				CryptSignHash(hHash, dwKeySpec, NULL, 0, pbSig = snewn(cbSig, BYTE), &cbSig) != FALSE)
			{
				cert_reverse_array(pbSig, cbSig);
				pSignedData = pbSig;
				*siglen = cbSig;
				pbSig = NULL;
			}

			// cleanup hash structure
			if (hHash != (ULONG_PTR)NULL) { CryptDestroyHash(hHash); }
		}
		else if (dwKeySpec == CERT_NCRYPT_KEY_SPEC)
		{
			// set window for any client 
			NCryptSetProperty(hCrypt, NCRYPT_WINDOW_HANDLE_PROPERTY, (PBYTE) &hWnd, sizeof(HWND), 0);

			// create a hash of the data to be signed
			ALG_ID iHashAlg = CALG_SHA1;
			if (strstr(userkey->alg->name, "ecdsa-") == userkey->alg->name) 
			{
				if (strcmp(userkey->alg->name, "ecdsa-sha2-nistp256") == 0) iHashAlg = CALG_SHA_256;
				if (strcmp(userkey->alg->name, "ecdsa-sha2-nistp384") == 0) iHashAlg = CALG_SHA_384;
				if (strcmp(userkey->alg->name, "ecdsa-sha2-nistp521") == 0) iHashAlg = CALG_SHA_512;
			}

			HCRYPTPROV hHashProv = (ULONG_PTR) NULL;
			HCRYPTHASH hHash = (ULONG_PTR) NULL;
			unsigned char pHashData[512 / 8];
			DWORD iHashDataSize = sizeof(pHashData);
			if (CryptAcquireContext(&hHashProv, NULL, NULL, PROV_RSA_AES, 0) != FALSE &&
				CryptCreateHash(hHashProv, iHashAlg, 0, 0, &hHash) != FALSE &&
				CryptHashData(hHash, (PBYTE)data, datalen, 0) != FALSE &&
				CryptGetHashParam(hHash, HP_HASHVAL, pHashData, &iHashDataSize, 0) != FALSE);
			{
				if (NCryptSignHash(hCrypt, NULL, pHashData, iHashDataSize, NULL, 0, &cbSig, 0) == ERROR_SUCCESS &&
					NCryptSignHash(hCrypt, NULL, pHashData, iHashDataSize, pbSig = snewn(cbSig, BYTE), cbSig, &cbSig, 0) == ERROR_SUCCESS)
				{
					// shift the r and s integers down one to make a leading zero
					pSignedData = pbSig;
					*siglen = cbSig;
					pbSig = NULL;
				}
			}

			// cleanup hash structure
			if (hHash != (ULONG_PTR)NULL) { CryptDestroyHash(hHash); }
			if (hHashProv != (ULONG_PTR)NULL) { CryptDestroyHash(hHashProv); }
		}

		// cleanup intermediate signing data
		if (pbSig != NULL) { sfree(pbSig); }
	}

	// cleanup certificate handles and return
	if (pCertCtx != NULL) { CertFreeCertificateContext(pCertCtx); }
	if (hCertStore != NULL) { CertCloseStore(hCertStore, CERT_CLOSE_STORE_FORCE_FLAG); }
	return pSignedData;
}

HCERTSTORE cert_capi_get_cert_store(LPCSTR * szHint, HWND hWnd)
{
	UNREFERENCED_PARAMETER(hWnd);

	szHint = NULL;
	return CertOpenStore(CERT_STORE_PROV_SYSTEM_W, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0,
		CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_ENUM_ARCHIVED_FLAG, L"MY");
}

void cert_capi_load_cert(LPCSTR szCert, PCCERT_CONTEXT* ppCertCtx, HCERTSTORE* phStore)
{
	HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0,
		CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_ENUM_ARCHIVED_FLAG, L"MY");
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
	CertCloseStore(hStore, CERT_CLOSE_STORE_FORCE_FLAG);
}

#endif // PUTTY_CAC
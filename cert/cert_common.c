#ifdef PUTTY_CAC

#define UMDF_USING_NTSTATUS
#include <ntstatus.h>

#include <windows.h>
#include <wincrypt.h>
#include <cryptdlg.h>
#include <cryptuiapi.h>

#include "cert_pkcs.h"
#include "cert_capi.h"

#define DEFINE_VARIABLES
#include "cert_common.h"
#undef DEFINE_VARIABLES

#ifndef SSH_AGENT_SUCCESS
#include "ssh.h"
#endif

void cert_reverse_array(LPBYTE pb, DWORD cb)
{
	for (DWORD i = 0, j = cb - 1; i < cb / 2; i++, j--)
	{
		BYTE b = pb[i];
		pb[i] = pb[j];
		pb[j] = b;
	}
}

LPSTR cert_get_cert_hash(LPCSTR szIden, PCCERT_CONTEXT pCertContext, LPCSTR szHint)
{
	BYTE pbThumbBinary[SHA1_BINARY_SIZE];
	DWORD cbThumbBinary = SHA1_BINARY_SIZE;
	if (CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID, pbThumbBinary, &cbThumbBinary) == FALSE)
	{
		return NULL;
	}

	LPSTR szThumbHex[SHA1_HEX_SIZE + 1];
	DWORD iThumbHexSize = _countof(szThumbHex);
	CryptBinaryToStringA(pbThumbBinary, cbThumbBinary,
		CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, (LPSTR)szThumbHex, &iThumbHexSize);
	return dupcat(szIden, szThumbHex, (szHint != NULL) ? "=" : "", (szHint != NULL) ? szHint : "", NULL);
}

void cert_prompt_cert(HCERTSTORE hStore, HWND hWnd, LPSTR * szCert, LPCSTR szIden, LPCSTR szHint)
{
	HMODULE hCertDialogLibrary = LoadLibrary("cryptdlg.dll");
	if (hCertDialogLibrary == NULL) return;

	// import the address to the certificate selections dialog
	typedef BOOL(WINAPI *PCertSelectCertificateW)(
		__inout  PCERT_SELECT_STRUCT_W pCertSelectInfo);
	PCertSelectCertificateW CertSelectCertificate = (PCertSelectCertificateW)
		GetProcAddress(hCertDialogLibrary, "CertSelectCertificateW");

	// setup the structure to control which certificates 
	// we want the user to be able to select from
	PCERT_CONTEXT * ppCertContext = calloc(1, sizeof(CERT_CONTEXT*));
	CERT_SELECT_STRUCT_W tCertSelect;
	ZeroMemory(&tCertSelect, sizeof(tCertSelect));
	tCertSelect.dwSize = sizeof(CERT_SELECT_STRUCT_W);
	tCertSelect.hwndParent = hWnd;
	tCertSelect.szTitle = L"PuTTY: Select Certificate for Authentication";
	tCertSelect.cCertStore = 1;
	tCertSelect.arrayCertStore = &hStore;
	tCertSelect.szPurposeOid = szOID_PKIX_KP_CLIENT_AUTH;
	tCertSelect.cCertContext = 1;
	tCertSelect.arrayCertContext = ppCertContext;

	// display the certificate selection dialog
	if (CertSelectCertificate(&tCertSelect) == TRUE && tCertSelect.cCertContext == 1)
	{
		BYTE pbThumbBinary[SHA1_BINARY_SIZE];
		DWORD cbThumbBinary = SHA1_BINARY_SIZE;
		if (CertGetCertificateContextProperty(*ppCertContext, CERT_HASH_PROP_ID, pbThumbBinary, &cbThumbBinary) == TRUE)
		{
			*szCert = cert_get_cert_hash(szIden, *ppCertContext, szHint);
		}

		// cleanup
		CertFreeCertificateContext(*ppCertContext);
	}

	// cleanup 
	free(ppCertContext);
	FreeLibrary(hCertDialogLibrary);
}

LPSTR cert_prompt(LPCSTR szIden, HWND hWnd)
{
	HCERTSTORE hStore = NULL;
	LPCSTR szHint = NULL;

	if (cert_is_capipath(szIden))
	{
		hStore = cert_capi_get_cert_store(&szHint, hWnd);
	}

	if (cert_is_pkcspath(szIden))
	{
		hStore = cert_pkcs_get_cert_store(&szHint, hWnd);
	}

	if (hStore != NULL)
	{
		LPSTR szCert = NULL;
		cert_prompt_cert(hStore, hWnd, &szCert, szIden, szHint);
		return szCert;
	}

	return NULL;
}

LPBYTE cert_sign(struct ssh2_userkey * userkey, LPCBYTE pDataToSign, int iDataToSignLen, int * iWrappedSigLen, HWND hWnd)
{
	LPBYTE pRawSig = NULL;
	int iRawSigLen = 0;
	*iWrappedSigLen = 0;

	// sanity check
	if (userkey->comment == NULL) return NULL;

	if (cert_is_capipath(userkey->comment))
	{
		pRawSig = cert_capi_sign(userkey, pDataToSign, iDataToSignLen, &iRawSigLen, hWnd);
	}

	if (cert_is_pkcspath(userkey->comment))
	{
		pRawSig = cert_pkcs_sign(userkey, pDataToSign, iDataToSignLen, &iRawSigLen, hWnd);
	}

	// sanity check
	if (pRawSig == NULL) return NULL;

	// used to hold wrapped signature to return to server
	LPBYTE pWrappedSig = NULL;

	if (strstr(userkey->alg->name, "ecdsa-") == userkey->alg->name)
	{
		// the full ecdsa ssh blob is as follows:
		//
		// size of algorithm name (4 bytes in big endian)
		// algorithm name
		// size of padded 'r' and 's' values from windows blob (4 bytes in big endian)
		// size of padded 'r' value from signed structure (4 bytes in big endian)
		// 1 byte of 0 padding in order to ensure the 'r' value is represented as positive
		// the 'r' value (first half of the blob signature returned from windows)
		// 1 byte of 0 padding in order to ensure the 's' value is represented as positive
		// the 's' value (first half of the blob signature returned from windows)
		const BYTE iZero = 0;
		int iAlgName = strlen(userkey->alg->name);
		*iWrappedSigLen = 4 + iAlgName + 4 + 4 + 1 + (iRawSigLen / 2) + 4 + 1 + (iRawSigLen / 2);
		pWrappedSig = snewn(*iWrappedSigLen, unsigned char);
		unsigned char * pWrappedPos = pWrappedSig;
		PUT_32BIT(pWrappedPos, iAlgName); pWrappedPos += 4;
		memcpy(pWrappedPos, userkey->alg->name, iAlgName); pWrappedPos += iAlgName;
		PUT_32BIT(pWrappedPos, iRawSigLen + 4 + 4 + 1 + 1); pWrappedPos += 4;
		PUT_32BIT(pWrappedPos, 1 + iRawSigLen / 2); pWrappedPos += 4;
		memcpy(pWrappedPos, &iZero, 1); pWrappedPos += 1;
		memcpy(pWrappedPos, pRawSig, iRawSigLen / 2); pWrappedPos += iRawSigLen / 2;
		PUT_32BIT(pWrappedPos, 1 + iRawSigLen / 2); pWrappedPos += 4;
		memcpy(pWrappedPos, &iZero, 1); pWrappedPos += 1;
		memcpy(pWrappedPos, pRawSig + iRawSigLen / 2, iRawSigLen / 2); pWrappedPos += iRawSigLen / 2;
	}
	else
	{
		// the full rsa ssh blob is as follows:
		//
		// size of algorithm name (4 bytes in big endian)
		// algorithm name
		// size of binary signature (4 bytes in big endian)
		// binary signature
		int iAlgoNameLen = strlen(userkey->alg->name);
		*iWrappedSigLen = 4 + iAlgoNameLen + 4 + iRawSigLen;
		pWrappedSig = snewn(*iWrappedSigLen, unsigned char);
		unsigned char * pWrappedPos = pWrappedSig;
		PUT_32BIT(pWrappedPos, iAlgoNameLen); pWrappedPos += 4;
		memcpy(pWrappedPos, userkey->alg->name, iAlgoNameLen); pWrappedPos += iAlgoNameLen;
		PUT_32BIT(pWrappedPos, iRawSigLen); pWrappedPos += 4;
		memcpy(pWrappedPos, pRawSig, iRawSigLen);
	}

	// cleanup
	sfree(pRawSig);
	return pWrappedSig;
}

struct ssh2_userkey * cert_get_ssh_userkey(LPCSTR szCert, PCERT_CONTEXT pCertContext)
{
	struct ssh2_userkey * pUserKey = NULL;

	// allocate and fetch key provider information
	WCHAR sAlgoId[16] = L"";
	DWORD iAlgoIdSize = sizeof(sAlgoId);
	CertGetCertificateContextProperty(pCertContext, CERT_SIGN_HASH_CNG_ALG_PROP_ID, &sAlgoId, &iAlgoIdSize);

	// Handle RSA Keys
	if (wcsstr(sAlgoId, L"RSA/") == sAlgoId)
	{
		// get the size of the space required
		PCRYPT_BIT_BLOB pKeyData = _ADDRESSOF(pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey);

		DWORD cbPublicKeyBlob = 0;
		LPBYTE pbPublicKeyBlob = NULL;
		if (CryptDecodeObject(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, pKeyData->pbData,
			pKeyData->cbData, 0, NULL, &cbPublicKeyBlob) != FALSE && cbPublicKeyBlob != 0 &&
			CryptDecodeObject(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, pKeyData->pbData,
				pKeyData->cbData, 0, pbPublicKeyBlob = malloc(cbPublicKeyBlob), &cbPublicKeyBlob) != FALSE)
		{
			// create a new putty rsa structure fill out all non-private params
			RSAPUBKEY * pPublicKey = (RSAPUBKEY *)(pbPublicKeyBlob + sizeof(BLOBHEADER));
			struct RSAKey * rsa = snew(struct RSAKey);
			rsa->bits = pPublicKey->bitlen;
			rsa->bytes = pPublicKey->bitlen / 8;
			rsa->exponent = bignum_from_long(pPublicKey->pubexp);
			cert_reverse_array((BYTE *)(pPublicKey)+sizeof(RSAPUBKEY), rsa->bytes);
			rsa->modulus = bignum_from_bytes((BYTE *)(pPublicKey)+sizeof(RSAPUBKEY), rsa->bytes);
			rsa->comment = dupstr(szCert);
			rsa->private_exponent = bignum_from_long(0);
			rsa->p = bignum_from_long(0);
			rsa->q = bignum_from_long(0);
			rsa->iqmp = bignum_from_long(0);

			// fill out the user key
			pUserKey = snew(struct ssh2_userkey);
			pUserKey->alg = find_pubkey_alg("ssh-rsa");
			pUserKey->data = rsa;
			pUserKey->comment = dupstr(szCert);
		}

		if (pbPublicKeyBlob != NULL) free(pbPublicKeyBlob);
	}

	// Handle ECC Keys
	else if (wcsstr(sAlgoId, L"ECDSA/") == sAlgoId)
	{
		BCRYPT_KEY_HANDLE hBCryptKey = NULL;
		if (CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, _ADDRESSOF(pCertContext->pCertInfo->SubjectPublicKeyInfo),
			0, NULL, &hBCryptKey) != FALSE)
		{
			DWORD iKeyLength = 0;
			ULONG iKeyLengthSize = sizeof(DWORD);
			LPBYTE pEccKey = NULL;
			ULONG iKeyBlobSize = 0;
			if (BCryptGetProperty(hBCryptKey, BCRYPT_KEY_LENGTH, (PUCHAR)&iKeyLength, iKeyLengthSize, &iKeyLength, 0) == STATUS_SUCCESS &&
				BCryptExportKey(hBCryptKey, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, iKeyBlobSize, &iKeyBlobSize, 0) == STATUS_SUCCESS && iKeyBlobSize != 0 &&
				BCryptExportKey(hBCryptKey, NULL, BCRYPT_ECCPUBLIC_BLOB, pEccKey = malloc(iKeyBlobSize), iKeyBlobSize, &iKeyBlobSize, 0) == STATUS_SUCCESS)
			{
				struct ec_key *ec = snew(struct ec_key);
				ZeroMemory(ec, sizeof(struct ec_key));
				ec_nist_alg_and_curve_by_bits(iKeyLength, &(ec->publicKey.curve), &(ec->signalg));
				ec->publicKey.infinity = 0;
				int iKeyBytes = (iKeyLength + 7) / 8; // round up
				ec->publicKey.x = bignum_from_bytes(pEccKey + sizeof(BCRYPT_ECCKEY_BLOB), iKeyBytes);
				ec->publicKey.y = bignum_from_bytes(pEccKey + sizeof(BCRYPT_ECCKEY_BLOB) + iKeyBytes, iKeyBytes);

				// fill out the user key
				pUserKey = snew(struct ssh2_userkey);
				pUserKey->alg = ec->signalg;
				pUserKey->data = ec;
				pUserKey->comment = dupstr(szCert);
			}

			// cleanup
			if (pEccKey != NULL) free(pEccKey);
		}

		// cleanup
		BCryptDestroyKey(hBCryptKey);
	}

	return pUserKey;
}

struct ssh2_userkey * cert_load_key(LPCSTR szCert)
{
	// sanity check
	if (szCert == NULL) return NULL;

	PCERT_CONTEXT pCertContext = NULL;
	HCERTSTORE hCertStore = NULL;

	if (cert_is_capipath(szCert))
	{
		cert_capi_load_cert(szCert, &pCertContext, &hCertStore);
	}

	if (cert_is_pkcspath(szCert))
	{
		cert_pkcs_load_cert(szCert, &pCertContext, &hCertStore);
	}

	// ensure a valid cert was found
	if (pCertContext == NULL) return NULL;

	// get the public key data
	return cert_get_ssh_userkey(szCert, pCertContext);
}

LPSTR cert_key_string(LPCSTR szCert)
{
	// sanity check
	if (szCert == NULL || !cert_is_certpath(szCert))
	{
		return NULL;
	}

	PCERT_CONTEXT pCertContext = NULL;
	HCERTSTORE hCertStore = NULL;

	// if capi, get the capi cert
	if (cert_is_capipath(szCert))
	{
		cert_capi_load_cert(szCert, &pCertContext, &hCertStore);
	}

	// if pkcs, get the pkcs cert
	if (cert_is_pkcspath(szCert))
	{
		cert_pkcs_load_cert(szCert, &pCertContext, &hCertStore);
	}

	// sanity check
	if (pCertContext == NULL) return NULL;

	// get the open ssh ekys trings
	struct ssh2_userkey * pUserKey = cert_get_ssh_userkey(szCert, pCertContext);
	char * szKey = ssh2_pubkey_openssh_str(pUserKey);

	// clean and return
	free(pUserKey->comment);
	pUserKey->alg->freekey(pUserKey->data);
	sfree(pUserKey);
	CertFreeCertificateContext(pCertContext);
	CertCloseStore(hCertStore, 0);
	return szKey;
}

VOID cert_display_cert(LPCSTR szCert, HWND hWnd)
{
	PCERT_CONTEXT pCertContext = NULL;
	HCERTSTORE hCertStore = NULL;

	// if capi, get the capi cert
	if (cert_is_capipath(szCert))
	{
		cert_capi_load_cert(szCert, &pCertContext, &hCertStore);
	}

	// if pkcs, get the pkcs cert
	if (cert_is_pkcspath(szCert))
	{
		cert_pkcs_load_cert(szCert, &pCertContext, &hCertStore);
	}

	// sanity check
	if (pCertContext == NULL) return;

	// display cert ui
	CryptUIDlgViewContext(CERT_STORE_CERTIFICATE_CONTEXT,
		pCertContext, hWnd, L"PuTTY Certificate Display", 0, NULL);

	// cleanup
	CertFreeCertificateContext(pCertContext);
	CertCloseStore(hCertStore, 0);
}

int cert_all_certs(LPSTR ** pszCert)
{
	// get a hangle to the cert store
	LPCSTR szHint = NULL;
	HCERTSTORE hCertStore = cert_capi_get_cert_store(&szHint, NULL);

	// enumerate all certs
	CTL_USAGE tItem;
	CHAR * sUsage[] = { szOID_PKIX_KP_CLIENT_AUTH };
	tItem.cUsageIdentifier = 1;
	tItem.rgpszUsageIdentifier = sUsage;
	PCCERT_CONTEXT pCertContext = NULL;

	// first count the number of certs for allocation
	int iCertNum = 0;
	while ((pCertContext = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		CERT_FIND_VALID_ENHKEY_USAGE_FLAG, CERT_FIND_ENHKEY_USAGE, &tItem, pCertContext)) != NULL) iCertNum++;

	// allocate memory and populate it
	*pszCert = snewn(iCertNum, LPSTR);
	LPSTR * pszCertPos = *pszCert;
	while ((pCertContext = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		CERT_FIND_VALID_ENHKEY_USAGE_FLAG, CERT_FIND_ENHKEY_USAGE, &tItem, pCertContext)) != NULL)
	{
		*(pszCertPos++) = cert_get_cert_hash(IDEN_CAPI, pCertContext, NULL);
	}

	// cleanup and return
	CertCloseStore(hCertStore, 0);
	return iCertNum;
}

void cert_convert_legacy(LPSTR szCert)
{
	// search for 'User\MY\' and replace with 'CAPI:'
	LPSTR szIdenLegacyUsr = "User\\MY\\";
	if (strstr(szCert, szIdenLegacyUsr) == szCert)
	{
		strcpy(szCert, IDEN_CAPI);
		strcpy(&szCert[IDEN_CAPI_SIZE], &szCert[strlen(szIdenLegacyUsr)]);
		strlwr(&szCert[IDEN_CAPI_SIZE]);
	}

	// search for 'System\MY\' and replace with 'CAPI:'
	LPSTR szIdenLegacySys = "System\\MY\\";
	if (strstr(szCert, szIdenLegacySys) == szCert)
	{
		strcpy(szCert, IDEN_CAPI);
		strcpy(&szCert[IDEN_CAPI_SIZE], &szCert[strlen(szIdenLegacySys)]);
		strlwr(&szCert[IDEN_CAPI_SIZE]);
	}
}

LPBYTE cert_get_hash(LPCSTR szAlgo, LPCBYTE pDataToHash, DWORD iDataToHashSize, DWORD * iHashedDataSize, BOOL bPrependDigest)
{
	// id-sha1 OBJECT IDENTIFIER 
	const BYTE OID_SHA1[] = {
		0x30, 0x21, /* type Sequence, length 0x21 (33) */
		0x30, 0x09, /* type Sequence, length 0x09 */
		0x06, 0x05, /* type OID, length 0x05 */
		0x2b, 0x0e, 0x03, 0x02, 0x1a, /* id-sha1 OID */
		0x05, 0x00, /* NULL */
		0x04, 0x14  /* Octet string, length 0x14 (20), followed by sha1 hash */
	};

	HCRYPTPROV hHashProv = (ULONG_PTR)NULL;
	HCRYPTHASH hHash = (ULONG_PTR)NULL;
	LPBYTE pHashData = NULL;
	*iHashedDataSize = 0;

	// determine algo to use for hashing
	ALG_ID iHashAlg = CALG_SHA1;
	if (strcmp(szAlgo, "ecdsa-sha2-nistp256") == 0) iHashAlg = CALG_SHA_256;
	if (strcmp(szAlgo, "ecdsa-sha2-nistp384") == 0) iHashAlg = CALG_SHA_384;
	if (strcmp(szAlgo, "ecdsa-sha2-nistp521") == 0) iHashAlg = CALG_SHA_512;

	// for sha1, prepend the hash digest if requested
	// this is necessary for some signature algorithms
	DWORD iDigestSize = 0;
	LPBYTE pDigest = NULL;
	if (iHashAlg == CALG_SHA1 && bPrependDigest)
	{
		iDigestSize = sizeof(OID_SHA1);
		pDigest = (LPBYTE)OID_SHA1;
	}

	// acquire crytpo provider, hash data, and export hashed binary data
	if (CryptAcquireContext(&hHashProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) == FALSE ||
		CryptCreateHash(hHashProv, iHashAlg, 0, 0, &hHash) == FALSE ||
		CryptHashData(hHash, pDataToHash, iDataToHashSize, 0) == FALSE ||
		CryptGetHashParam(hHash, HP_HASHVAL, NULL, iHashedDataSize, 0) == FALSE ||
		CryptGetHashParam(hHash, HP_HASHVAL, (pHashData = snewn(*iHashedDataSize +
			iDigestSize, BYTE)) + iDigestSize, iHashedDataSize, 0) == FALSE)
	{
		// something failed
		if (pHashData != NULL)
		{
			sfree(pHashData);
			pHashData = NULL;
		}
	}

	// prepend the digest
	*iHashedDataSize += iDigestSize;
	memcpy(pHashData, pDigest, iDigestSize);

	// cleanup and return
	if (hHash != (ULONG_PTR)NULL) CryptDestroyHash(hHash);
	if (hHashProv != (ULONG_PTR)NULL) CryptReleaseContext(hHashProv, 0);
	return pHashData;
}

#endif // PUTTY_CAC
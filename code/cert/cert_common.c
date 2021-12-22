#ifdef PUTTY_CAC

#define UMDF_USING_NTSTATUS
#include <ntstatus.h>

#include <windows.h>
#include <wincrypt.h>
#include <cryptuiapi.h>
#include <wincred.h>

#include "cert_pkcs.h"
#include "cert_capi.h"

#define DEFINE_VARIABLES
#include "cert_common.h"
#undef DEFINE_VARIABLES

#ifndef PUTTY_REG_POS
#define PUTTY_REG_POS "Software\\SimonTatham\\PuTTY"
#endif

#ifndef SSH_AGENT_SUCCESS
#include "ssh.h"
#endif
#include "mpint.h"
#include "ecc.h"

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
	return dupcat(szIden, szThumbHex, (szHint != NULL) ? "=" : "", (szHint != NULL) ? szHint : "");
}

LPSTR cert_prompt(LPCSTR szIden, HWND hWnd, BOOL bAutoSelect)
{
	HCERTSTORE hCertStore = NULL;
	LPCSTR szHint = NULL;

	if (cert_is_capipath(szIden))
	{
		hCertStore = cert_capi_get_cert_store(&szHint, hWnd);
	}

	if (cert_is_pkcspath(szIden))
	{
		hCertStore = cert_pkcs_get_cert_store(&szHint, hWnd);
	}

	// return if store could not be loaded
	if (hCertStore == NULL) return NULL;

	// create a memory store so we can proactively filter certificates
	HCERTSTORE hMemoryStore = CertOpenStore(CERT_STORE_PROV_MEMORY,
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		0, CERT_STORE_CREATE_NEW_FLAG, NULL);

	// enumerate all certs
	PCCERT_CONTEXT pCertContext = NULL;
	int iCertCount = 0;
	while ((pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) != NULL)
	{
		// ignore invalid cert sbased on settings
		if (!cert_check_valid(pCertContext)) continue;

		CertAddCertificateContextToStore(hMemoryStore, pCertContext, CERT_STORE_ADD_ALWAYS, NULL);
		iCertCount++;
	}

	// select certificate from store
	LPSTR szCert = NULL;
	if (iCertCount == 1 && bAutoSelect)
	{
		// auto select if only single certificate specified
		CertFindCertificateInStore(hMemoryStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_ANY, NULL, pCertContext);
	}
	else
	{
		// display the certificate selection dialog
		pCertContext = CryptUIDlgSelectCertificateFromStore(hMemoryStore, hWnd,
			L"PuTTY: Select Certificate for Authentication",
			L"Please select the certificate that you would like to use for authentication to the remote system.",
			CRYPTUI_SELECT_LOCATION_COLUMN, 0, NULL);
	}

	// get the certificate hash to pass back
	if (pCertContext != NULL)
	{
		BYTE pbThumbBinary[SHA1_BINARY_SIZE];
		DWORD cbThumbBinary = SHA1_BINARY_SIZE;
		if (CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID, pbThumbBinary, &cbThumbBinary) == TRUE)
		{
			szCert = cert_get_cert_hash(IDEN_PREFIX(szIden), pCertContext, szHint);
		}

		// cleanup
		CertFreeCertificateContext(pCertContext);
	}

	// cleanup and return
	CertCloseStore(hMemoryStore, CERT_CLOSE_STORE_FORCE_FLAG);
	return szCert;
}

BOOL cert_load_cert(LPCSTR szCert, PCERT_CONTEXT * ppCertContext, HCERTSTORE * phCertStore)
{
	// if capi, get the capi cert
	if (cert_is_capipath(szCert))
	{
		cert_capi_load_cert(szCert, ppCertContext, phCertStore);
	}

	// if pkcs, get the pkcs cert
	if (cert_is_pkcspath(szCert))
	{
		cert_pkcs_load_cert(szCert, ppCertContext, phCertStore);
	}

	// sanity check
	return (*ppCertContext != NULL);
}

BOOL cert_test_hash(LPCSTR szCert, DWORD iHashRequest)
{
	// if capi, get the capi cert
	if (cert_is_capipath(szCert))
	{
		return cert_capi_test_hash(szCert, iHashRequest);
	}

	if (cert_is_pkcspath(szCert))
	{
		return cert_pkcs_test_hash(szCert, iHashRequest);
	}

	return TRUE;
}

BOOL cert_confirm_signing(LPCSTR sFingerPrint, LPCSTR sComment)
{
	// prompt if usage prompting is enabled
	if (!cert_auth_prompting((DWORD)-1)) return TRUE;

	// prompt user
	BOOL bIsCert = cert_is_certpath(sComment);
	LPSTR sDescription = bIsCert ? cert_subject_string(sComment) : sComment;
	LPSTR sMessage = dupprintf("%s\r\n\r\n%s: %s\r\n%s: %s\r\n\r\n % s",
		"An application is attempting to authenticate using a certificate or key with the following details:",
		bIsCert ? "Subject" : "Comment", sDescription,
		"Fingerprint", sFingerPrint,
		"Would you like to permit this signing operation?");
	int iResponse = MessageBox(NULL, sMessage, "Certificate & Key Usage Confirmation - Pageant",
		MB_SYSTEMMODAL | MB_ICONQUESTION | MB_YESNO);
	sfree(sMessage);
	sfree(sDescription);

	// return true if user allowed
	return (iResponse == IDYES);
}

LPBYTE cert_sign(struct ssh2_userkey * userkey, LPCBYTE pDataToSign, int iDataToSignLen, int * iWrappedSigLen, int iAgentFlags)
{
	LPBYTE pRawSig = NULL;
	int iRawSigLen = 0;
	*iWrappedSigLen = 0;

	// sanity check
	if (userkey->comment == NULL) return NULL;
	
	// determine hashing algorithm for signing
	LPCSTR sHashAlgName = userkey->key->vt->ssh_id;
	if (strstr(userkey->key->vt->ssh_id, "ssh-rsa") && (iAgentFlags & SSH_AGENT_RSA_SHA2_256) && cert_test_hash(userkey->comment, SSH_AGENT_RSA_SHA2_256)) {
		sHashAlgName = "rsa-sha2-256";
	}
	if (strstr(userkey->key->vt->ssh_id, "ssh-rsa") && (iAgentFlags & SSH_AGENT_RSA_SHA2_512) && cert_test_hash(userkey->comment, SSH_AGENT_RSA_SHA2_512)) {
		sHashAlgName = "rsa-sha2-512";
	}

	// if capi, sign data using capi
	if (cert_is_capipath(userkey->comment))
	{
		pRawSig = cert_capi_sign(userkey, pDataToSign, iDataToSignLen, &iRawSigLen, sHashAlgName);
	}

	// if pkcs, sign data using capi
	if (cert_is_pkcspath(userkey->comment))
	{
		pRawSig = cert_pkcs_sign(userkey, pDataToSign, iDataToSignLen, &iRawSigLen, sHashAlgName);
	}

	// sanity check
	if (pRawSig == NULL) return NULL;

	// used to hold wrapped signature to return to server
	LPBYTE pWrappedSig = NULL;

	if (strstr(userkey->key->vt->ssh_id, "ecdsa-") == userkey->key->vt->ssh_id)
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
		int iAlgName = strlen(sHashAlgName);
		*iWrappedSigLen = 4 + iAlgName + 4 + 4 + 1 + (iRawSigLen / 2) + 4 + 1 + (iRawSigLen / 2);
		pWrappedSig = snewn(*iWrappedSigLen, unsigned char);
		unsigned char * pWrappedPos = pWrappedSig;
		PUT_32BIT_MSB_FIRST(pWrappedPos, iAlgName); pWrappedPos += 4;
		memcpy(pWrappedPos, sHashAlgName, iAlgName); pWrappedPos += iAlgName;
		PUT_32BIT_MSB_FIRST(pWrappedPos, iRawSigLen + 4 + 4 + 1 + 1); pWrappedPos += 4;
		PUT_32BIT_MSB_FIRST(pWrappedPos, 1 + iRawSigLen / 2); pWrappedPos += 4;
		memcpy(pWrappedPos, &iZero, 1); pWrappedPos += 1;
		memcpy(pWrappedPos, pRawSig, iRawSigLen / 2); pWrappedPos += iRawSigLen / 2;
		PUT_32BIT_MSB_FIRST(pWrappedPos, 1 + iRawSigLen / 2); pWrappedPos += 4;
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
		int iAlgoNameLen = strlen(sHashAlgName);
		*iWrappedSigLen = 4 + iAlgoNameLen + 4 + iRawSigLen;
		pWrappedSig = snewn(*iWrappedSigLen, unsigned char);
		unsigned char * pWrappedPos = pWrappedSig;
		PUT_32BIT_MSB_FIRST(pWrappedPos, iAlgoNameLen); pWrappedPos += 4;
		memcpy(pWrappedPos, sHashAlgName, iAlgoNameLen); pWrappedPos += iAlgoNameLen;
		PUT_32BIT_MSB_FIRST(pWrappedPos, iRawSigLen); pWrappedPos += 4;
		memcpy(pWrappedPos, pRawSig, iRawSigLen);
	}

	// cleanup
	sfree(pRawSig);
	return pWrappedSig;
}

struct ssh2_userkey * cert_get_ssh_userkey(LPCSTR szCert, PCERT_CONTEXT pCertContext)
{
	struct ssh2_userkey * pUserKey = NULL;

	// get a convenience pointer to the algorithm identifier 
	LPCSTR sAlgoId = pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;

	// Handle RSA Keys
	if (strstr(sAlgoId, _CRT_CONCATENATE(szOID_RSA, ".")) == sAlgoId)
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
			struct RSAKey * rsa = snew(struct RSAKey);
			ZeroMemory(rsa, sizeof(struct eddsa_key));
			rsa->sshk.vt = find_pubkey_alg("ssh-rsa");

			RSAPUBKEY * pPublicKey = (RSAPUBKEY *)(pbPublicKeyBlob + sizeof(BLOBHEADER));
			rsa->bits = pPublicKey->bitlen;
			rsa->bytes = pPublicKey->bitlen / 8;
			rsa->exponent = mp_from_integer(pPublicKey->pubexp);
			cert_reverse_array((BYTE *)(pPublicKey)+sizeof(RSAPUBKEY), rsa->bytes);
			rsa->modulus = mp_from_bytes_be(make_ptrlen((BYTE *)(pPublicKey)+sizeof(RSAPUBKEY), rsa->bytes));
			rsa->comment = dupstr(szCert);
			rsa->private_exponent = mp_from_integer(0);
			rsa->p = mp_from_integer(0);
			rsa->q = mp_from_integer(0);
			rsa->iqmp = mp_from_integer(0);

			// fill out the user key
			pUserKey = snew(struct ssh2_userkey);
			pUserKey->key = &rsa->sshk;
			pUserKey->comment = dupstr(szCert);
		}

		if (pbPublicKeyBlob != NULL) free(pbPublicKeyBlob);
	}

	// Handle ECC Keys
	else if (strstr(sAlgoId, szOID_ECC_PUBLIC_KEY) == sAlgoId)
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
				// create a new putty ecc structure fill out all non-private params
				struct ecdsa_key *ec = snew(struct ecdsa_key);
				ZeroMemory(ec, sizeof(struct eddsa_key));
				ec_nist_alg_and_curve_by_bits(iKeyLength, &(ec->curve), &(ec->sshk.vt));

				int iKeyBytes = (iKeyLength + 7) / 8; // round up
				ec->publicKey = ecc_weierstrass_point_new(ec->curve->w.wc,
					mp_from_bytes_be(make_ptrlen(pEccKey + sizeof(BCRYPT_ECCKEY_BLOB), iKeyBytes)),
					mp_from_bytes_be(make_ptrlen(pEccKey + sizeof(BCRYPT_ECCKEY_BLOB) + iKeyBytes, iKeyBytes)));
				ec->privateKey = mp_from_integer(0);

				// fill out the user key
				pUserKey = snew(struct ssh2_userkey);
				pUserKey->key = &ec->sshk;
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

struct ssh2_userkey * cert_load_key(LPCSTR szCert, HWND hWnd)
{
	// sanity check
	if (szCert == NULL) return NULL;

	// if asterisk is specified, then prompt for certificate
	BOOL bDynamicLookup = strcmp(IDEN_SPLIT(szCert), "*") == 0;
	BOOL bDynamicLookupAutoSelect = strcmp(IDEN_SPLIT(szCert), "**") == 0;
	if (bDynamicLookup || bDynamicLookupAutoSelect)
	{
		szCert = cert_prompt(szCert, hWnd, bDynamicLookupAutoSelect);
		if (szCert == NULL) return NULL;
	}

	// load certificate context
	PCERT_CONTEXT pCertContext = NULL;
	HCERTSTORE hCertStore = NULL;
	if (cert_load_cert(szCert, &pCertContext, &hCertStore) == FALSE) return NULL;

	// get the public key data
	struct ssh2_userkey * pUserKey = cert_get_ssh_userkey(szCert, pCertContext);
	CertFreeCertificateContext(pCertContext);
	CertCloseStore(hCertStore, 0);
	return pUserKey;
}

LPSTR cert_key_string(LPCSTR szCert)
{
	// sanity check
	if (szCert == NULL || !cert_is_certpath(szCert))
	{
		return NULL;
	}

	// load certificate context
	PCERT_CONTEXT pCertContext = NULL;
	HCERTSTORE hCertStore = NULL;
	if (cert_load_cert(szCert, &pCertContext, &hCertStore) == FALSE) return NULL;

	// obtain the key and destroy the comment since we are going to customize it
	struct ssh2_userkey * pUserKey = cert_get_ssh_userkey(szCert, pCertContext);
	sfree(pUserKey->comment);
	pUserKey->comment = "";

	// fetch the elements of the string
	LPSTR szKey = ssh2_pubkey_openssh_str(pUserKey);
	LPSTR szName = cert_subject_string(szCert);
	LPSTR szHash = cert_get_cert_hash(cert_iden(szCert), pCertContext, NULL);

	// append the ssh string, identifier:thumbprint, and certificate subject
	LPSTR szKeyWithComment = dupprintf("%s %s %s", szKey, szHash, szName);

	// clean and return
	pUserKey->key->vt->freekey(pUserKey->key);
	sfree(pUserKey);
	sfree(szKey);
	sfree(szName);
	sfree(szHash);
	CertFreeCertificateContext(pCertContext);
	CertCloseStore(hCertStore, 0);
	return szKeyWithComment;
}

LPSTR cert_subject_string(LPCSTR szCert)
{
	// sanity check
	if (szCert == NULL || !cert_is_certpath(szCert))
	{
		return NULL;
	}

	// load certificate context
	PCERT_CONTEXT pCertContext = NULL;
	HCERTSTORE hCertStore = NULL;
	if (cert_load_cert(szCert, &pCertContext, &hCertStore) == FALSE) return NULL;

	// get name size
	DWORD iSize = 0;
	iSize = CertNameToStr(X509_ASN_ENCODING, &pCertContext->pCertInfo->Subject,
		CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, NULL, iSize);

	// allocate and retrieve name
	LPSTR szName = snewn(iSize, CHAR);
	CertNameToStr(X509_ASN_ENCODING, &pCertContext->pCertInfo->Subject,
		CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, szName, iSize);

	// clean and return
	CertFreeCertificateContext(pCertContext);
	CertCloseStore(hCertStore, 0);
	return szName;
}

VOID cert_display_cert(LPCSTR szCert, HWND hWnd)
{
	// load certificate context
	PCERT_CONTEXT pCertContext = NULL;
	HCERTSTORE hCertStore = NULL;
	if (cert_load_cert(szCert, &pCertContext, &hCertStore) == FALSE) return;

	// display cert ui
	CryptUIDlgViewContext(CERT_STORE_CERTIFICATE_CONTEXT,
		pCertContext, hWnd, L"PuTTY Certificate Display", 0, NULL);

	// cleanup
	CertFreeCertificateContext(pCertContext);
	CertCloseStore(hCertStore, 0);
}

BOOL cert_check_valid(PCCERT_CONTEXT pCertContext)
{
	// if user has enabled hidden option, just allow the certificate
	if (cert_allow_any_cert((DWORD)-1))
	{
		return TRUE;
	}

	// minimally very digital signature key usage
	BYTE tUsageInfo[2] = { 0, 0 };
	DWORD iUsageInfo = 2;
	if (CertGetIntendedKeyUsage(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pCertContext->pCertInfo, tUsageInfo, sizeof(tUsageInfo)))
	{
		if ((tUsageInfo[0] & CERT_DIGITAL_SIGNATURE_KEY_USAGE) == 0)
		{
			return FALSE;
		}
	}

	// if certificate has eku, then it should be client auth or smartcard logon
	BOOL bFoundSmartCardLogon = FALSE;
	BOOL bFoundClientAuth = FALSE;
	PCERT_EXTENSION pEnhancedKeyUsage = CertFindExtension(szOID_ENHANCED_KEY_USAGE, 
		pCertContext->pCertInfo->cExtension, pCertContext->pCertInfo->rgExtension);
	if (pEnhancedKeyUsage != NULL)
	{
		// fetch list of usages
		PCERT_ENHKEY_USAGE pUsage;
		DWORD iUsageSize = sizeof(iUsageSize);
		if (CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, pEnhancedKeyUsage->Value.pbData,
			pEnhancedKeyUsage->Value.cbData, CRYPT_DECODE_ALLOC_FLAG, NULL, &pUsage, &iUsageSize) == FALSE)
		{
			return FALSE;
		}

		// loop through usages, looking for match
		for (DWORD iUsage = 0; iUsage < pUsage->cUsageIdentifier; iUsage++)
		{
			bFoundClientAuth |= strcmp(pUsage->rgpszUsageIdentifier[iUsage], szOID_PKIX_KP_CLIENT_AUTH) == 0;
			bFoundSmartCardLogon |= strcmp(pUsage->rgpszUsageIdentifier[iUsage], szOID_KP_SMARTCARD_LOGON) == 0;
		}

		// return false if no match found
		LocalFree(pUsage);
		if (!bFoundClientAuth && !bFoundSmartCardLogon) return FALSE;
	}

	// verify only smartcard card eku if requested
	if (cert_smartcard_certs_only((DWORD)-1))
	{
		if (!bFoundSmartCardLogon) return FALSE;
	}

	// verify time validity if requested
	DWORD iFlags = CERT_STORE_TIME_VALIDITY_FLAG;
	if (cert_ignore_expired_certs((DWORD)-1))
	{
		if (CertVerifySubjectCertificateContext(pCertContext, NULL, &iFlags) == TRUE && iFlags != 0)
			return FALSE;
	}

	// build and validate certificate chain
	if (cert_trusted_certs_only((DWORD)-1))
	{
		// attempt to chain the chain
		CERT_CHAIN_PARA tChainParams;
		ZeroMemory(&tChainParams, sizeof(tChainParams));
		tChainParams.cbSize = sizeof(tChainParams);
		PCCERT_CHAIN_CONTEXT pChainContext = NULL;
		BOOL bChainResult = CertGetCertificateChain(NULL, pCertContext, NULL, NULL, &tChainParams, 
			CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, NULL, &pChainContext);
		if (bChainResult == false) return FALSE;

		// concider trusted if the only error was account offline crls
		BOOL bTrusted = (pChainContext->TrustStatus.dwErrorStatus
			& ~(CERT_TRUST_IS_OFFLINE_REVOCATION | CERT_TRUST_REVOCATION_STATUS_UNKNOWN)) == 0;
		CertFreeCertificateChain(pChainContext);
		if (!bTrusted) return FALSE;
	}

	return TRUE;
}

int cert_all_certs(LPSTR ** pszCert)
{
	// get a handle to the cert store
	LPCSTR szHint = NULL;
	HCERTSTORE hCertStore = cert_capi_get_cert_store(&szHint, NULL);

	// find certificates matching our criteria
	size_t iCertNum = 0;
	PCCERT_CONTEXT pCertContext = NULL;
	while ((pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) != NULL)
	{
		// ignore invalid cert sbased on settings
		if (!cert_check_valid(pCertContext)) continue;

		// count cert and [re]allocate the return string array
		*pszCert = snrealloc(*pszCert, iCertNum + 1, sizeof(LPSTR));
		(*pszCert)[iCertNum++] = cert_get_cert_hash(IDEN_CAPI, pCertContext, NULL);
	}

	// cleanup and return
	CertCloseStore(hCertStore, 0);
	return iCertNum;
}

void cert_convert_legacy(LPSTR szCert)
{
	// sanity check
	if (szCert == NULL)
	{
		return;
	}

	// advance string pass 'CAPI:' if already present
	LPSTR sCompare = szCert;
	if (strstr(szCert, "CAPI:") == szCert)
	{
		sCompare = &szCert[IDEN_CAPI_SIZE];
	}

	// search for 'User\MY\' and replace with 'CAPI:'
	LPSTR szIdenLegacyUsr = "User\\MY\\";
	if (strstr(sCompare, szIdenLegacyUsr) == sCompare)
	{
		strcpy(szCert, IDEN_CAPI);
		strcpy(&szCert[IDEN_CAPI_SIZE], &sCompare[strlen(szIdenLegacyUsr)]);
		strlwr(&szCert[IDEN_CAPI_SIZE]);
	}

	// search for 'Machine\MY\' and replace with 'CAPI:'
	LPSTR szIdenLegacySys = "Machine\\MY\\";
	if (strstr(sCompare, szIdenLegacySys) == sCompare)
	{
		strcpy(szCert, IDEN_CAPI);
		strcpy(&szCert[IDEN_CAPI_SIZE], &sCompare[strlen(szIdenLegacySys)]);
		strlwr(&szCert[IDEN_CAPI_SIZE]);
	}
}

LPBYTE cert_get_hash(LPCSTR szAlgo, LPCBYTE pDataToHash, DWORD iDataToHashSize, DWORD * iHashedDataSize, BOOL bRequestDigest)
{
	const BYTE OID_SHA1[] = {
		0x30, 0x21, /* type Sequence, length 0x21 (33) */
		0x30, 0x09, /* type Sequence, length 0x09 (9) */
		0x06, 0x05, /* type OID, length 0x05 (5) */
		0x2b, 0x0e, 0x03, 0x02, 0x1a, /* id-sha1 OID */
		0x05, 0x00, /* type NULL, length 0x0 (0) */
		0x04, 0x14  /* type Octet string, length 0x14 (20), followed by sha1 hash */
	};
	const BYTE OID_SHA256[] = {
		0x30, 0x31, /* type Sequence, length 0x31 (49) */
		0x30, 0x0d, /* type Sequence, length 0x0d (13) */
		0x06, 0x09, /* type OID, length 0x09 (9) */
		0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, /* id-sha256 OID */
		0x05, 0x00, /* type NULL, length 0x0 (0) */
		0x04, 0x20  /* type Octet string, length 0x20 (32), followed by sha256 hash */
	};
	const BYTE OID_SHA512[] = {
		0x30, 0x51, /* type Sequence, length 0x51 (81) */
		0x30, 0x0d, /* type Sequence, length 0x0d (13) */
		0x06, 0x09, /* type OID, length 0x09 (9) */
		0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, /* id-sha512 OID */
		0x05, 0x00, /* type NULL, length 0x0 (0) */
		0x04, 0x40  /* type Octet string, length 0x40 (64), followed by sha512 hash */
	};

	// for rsa, prepend the hash digest if requested
	size_t iDigestSize = 0;
	LPBYTE pDigest = NULL;
	LPWSTR sNCryptAlg = NULL;

	const BOOL bNeedsDigest = bRequestDigest && (strstr(szAlgo, "rsa") != NULL);
	if (strcmp(szAlgo, "rsa-sha2-256") == 0 || strcmp(szAlgo, "ecdsa-sha2-nistp256") == 0)
	{
		sNCryptAlg = BCRYPT_SHA256_ALGORITHM;
		if (bNeedsDigest)
		{
			iDigestSize = sizeof(OID_SHA256);
			pDigest = (LPBYTE)OID_SHA256;
		}
	}
	else if (strcmp(szAlgo, "rsa-sha2-512") == 0 || strcmp(szAlgo, "ecdsa-sha2-nistp521") == 0)
	{
		sNCryptAlg = BCRYPT_SHA512_ALGORITHM;
		if (bNeedsDigest)
		{
			iDigestSize = sizeof(OID_SHA512);
			pDigest = (LPBYTE)OID_SHA512;
		}
	}
	else
	{
		pDigest = (LPBYTE)OID_SHA1;
		sNCryptAlg = BCRYPT_SHA1_ALGORITHM;
		if (bNeedsDigest)
		{
			iDigestSize = sizeof(OID_SHA1);
			pDigest = (LPBYTE)OID_SHA1;
		}
	}

	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	DWORD iPropSize = 0;
	LPBYTE pHashData = NULL;
	*iHashedDataSize = 0;

	// acquire crypto provider, hash data, and export hashed binary data
	if (BCryptOpenAlgorithmProvider(&hAlg, sNCryptAlg, NULL, 0) != STATUS_SUCCESS ||
		BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE) iHashedDataSize, sizeof(DWORD), &iPropSize, 0) != STATUS_SUCCESS ||
		(pHashData = snewn(*iHashedDataSize + iDigestSize, BYTE)) == NULL ||
		BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != STATUS_SUCCESS ||
		BCryptHashData(hHash, (PBYTE) pDataToHash, iDataToHashSize, 0) != STATUS_SUCCESS ||
		BCryptFinishHash(hHash, pHashData + iDigestSize, (ULONG) *iHashedDataSize, 0) != STATUS_SUCCESS)
	{
		// something failed
		if (pHashData != NULL)
		{
			sfree(pHashData);
			pHashData = NULL;
		}
	}

	// prepend the digest if necessary
	if (bNeedsDigest)
	{
		*iHashedDataSize += iDigestSize;
		memcpy(pHashData, pDigest, iDigestSize);
	}

	// cleanup and return
	if (hAlg != NULL) BCryptCloseAlgorithmProvider(hAlg, 0);
	if (hHash != NULL) BCryptDestroyHash(hHash);
	return pHashData;
}

PVOID cert_pin(LPSTR szCert, BOOL bUnicode, LPVOID szPin)
{
	typedef struct CACHE_ITEM
	{
		struct CACHE_ITEM * NextItem;
		LPSTR szCert;
		VOID * szPin;
		DWORD iLength;
		BOOL bUnicode;
		DWORD iSize;
	}
	CACHE_ITEM;

	static CACHE_ITEM * PinCacheList = NULL;

	// attempt to locate the item in the pin cache
	for (CACHE_ITEM * hCurItem = PinCacheList; hCurItem != NULL; hCurItem = hCurItem->NextItem)
	{
		if (strcmp(hCurItem->szCert, szCert) == 0)
		{
			VOID * pEncrypted = memcpy(malloc(hCurItem->iLength), hCurItem->szPin, hCurItem->iLength);
			CryptUnprotectMemory(pEncrypted, hCurItem->iLength, CRYPTPROTECTMEMORY_SAME_PROCESS);
			return pEncrypted;
		}
	}

	// request to add item to pin cache
	if (szPin != NULL)
	{
		// determine length of storage (round up to block size)
		DWORD iLength = ((bUnicode) ? sizeof(WCHAR) : sizeof(CHAR)) *
			(1 + ((bUnicode) ? wcslen(szPin) : strlen(szPin)));
		DWORD iCryptLength = CRYPTPROTECTMEMORY_BLOCK_SIZE *
			((iLength / CRYPTPROTECTMEMORY_BLOCK_SIZE) + 1);
		VOID * pEncrypted = memcpy(malloc(iCryptLength), szPin, iLength);

		// encrypt memory
		CryptProtectMemory(pEncrypted, iCryptLength,
			CRYPTPROTECTMEMORY_SAME_PROCESS);

		// allocate new item in cache and commit the change
		CACHE_ITEM * hItem = (CACHE_ITEM *)calloc(1, sizeof(struct CACHE_ITEM));
		hItem->szCert = strdup(szCert);
		hItem->szPin = pEncrypted;
		hItem->iLength = iCryptLength;
		hItem->bUnicode = bUnicode;
		hItem->NextItem = PinCacheList;
		PinCacheList = hItem;
		return NULL;
	}

	// prompt the user to enter the pin
	CREDUI_INFOW tCredInfo;
	ZeroMemory(&tCredInfo, sizeof(CREDUI_INFO));
	tCredInfo.cbSize = sizeof(tCredInfo);
	tCredInfo.pszCaptionText = L"PuTTY Authentication";
	tCredInfo.pszMessageText = L"Please Enter Your Smart Card Credentials";
	WCHAR szUserName[CREDUI_MAX_USERNAME_LENGTH + 1] = L"<Using Smart Card>";
	WCHAR szPassword[CREDUI_MAX_PASSWORD_LENGTH + 1] = L"";
	if (CredUIPromptForCredentialsW(&tCredInfo, L"Smart Card", NULL, 0, szUserName,
		_countof(szUserName), szPassword, _countof(szPassword), NULL,
		CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_KEEP_USERNAME) != ERROR_SUCCESS)
	{
		return NULL;
	}

	PVOID szReturn = NULL;
	if (bUnicode)
	{
		szReturn = wcsdup(szPassword);
	}
	else
	{
		CHAR szPasswordAscii[CREDUI_MAX_PASSWORD_LENGTH + 1] = "";
		WideCharToMultiByte(CP_ACP, 0, szPassword, -1, szPasswordAscii, sizeof(szPasswordAscii), NULL, NULL);
		szReturn = strdup(szPasswordAscii);
	}

	SecureZeroMemory(szPassword, sizeof(szPassword));
	return szReturn;
}

VOID cert_registry_setting_set(LPCSTR sSetting, DWORD iSetting)
{
	RegSetKeyValue(HKEY_CURRENT_USER, PUTTY_REG_POS, sSetting, REG_DWORD, &iSetting, sizeof(DWORD));
}

BOOL cert_registry_setting_load(LPCSTR sSetting, DWORD iDefault)
{
	DWORD iSetting = 0;
	DWORD iSettingSize = sizeof(iSetting);
	if (RegGetValue(HKEY_CURRENT_USER, PUTTY_REG_POS, sSetting,
		RRF_RT_REG_DWORD, NULL, &iSetting, &iSettingSize) == ERROR_SUCCESS)
	{
		return iSetting != 0;
	}
	else return iDefault;
}

BOOL cert_trusted_certs_only(DWORD bEnable)
{
	const LPSTR sSetting = "TrustedCertsOnly";
	if (bEnable != -1) cert_registry_setting_set(sSetting, bEnable);
	return cert_registry_setting_load(sSetting, FALSE);
}

BOOL cert_save_cert_list_enabled(DWORD bEnable)
{
	const LPSTR sSetting = "SaveCertListEnabled";
	if (bEnable != -1) cert_registry_setting_set(sSetting, bEnable);
	return cert_registry_setting_load(sSetting, FALSE);
}

BOOL cert_cache_enabled(DWORD bEnable)
{
	const LPSTR sSetting = "ForcePinCaching";
	if (bEnable != -1) cert_registry_setting_set(sSetting, bEnable);
	return cert_registry_setting_load(sSetting, FALSE);
}

BOOL cert_auth_prompting(DWORD bEnable)
{
	const LPSTR sSetting = "CertAuthPrompting";
	if (bEnable != -1) cert_registry_setting_set(sSetting, bEnable);
	return cert_registry_setting_load(sSetting, FALSE);
}

BOOL cert_smartcard_certs_only(DWORD bEnable)
{
	const LPSTR sSetting = "SmartCardLogonCertsOnly";
	if (bEnable != -1) cert_registry_setting_set(sSetting, bEnable);
	return cert_registry_setting_load(sSetting, FALSE);
}

BOOL cert_ignore_expired_certs(DWORD bEnable)
{
	const LPSTR sSetting = "IgnoreExpiredCerts";
	if (bEnable != -1) cert_registry_setting_set(sSetting, bEnable);
	return cert_registry_setting_load(sSetting, FALSE);
}

BOOL cert_allow_any_cert(DWORD bEnable)
{
	const LPSTR sSetting = "AllowAnyCert";
	if (bEnable != -1) cert_registry_setting_set(sSetting, bEnable);
	return cert_registry_setting_load(sSetting, FALSE);
}

BOOL cert_auto_load_certs(DWORD bEnable)
{
	const LPSTR sSetting = "AutoloadCerts";
	if (bEnable != -1) cert_registry_setting_set(sSetting, bEnable);
	return cert_registry_setting_load(sSetting, FALSE);
}

BOOL cert_cmdline_parse(LPCSTR sCommand)
{
	if (!strcmp(sCommand, "-autoload") || !strcmp(sCommand, "-autoloadoff")) 
	{
		cert_auto_load_certs((!strcmp(sCommand, "-autoload")) ? 1 : 0);
	}
	else if (!strcmp(sCommand, "-savecertlist") || !strcmp(sCommand, "-savecertlistoff")) 
	{
		cert_save_cert_list_enabled((!strcmp(sCommand, "-savecertlist")) ? 1 : 0);
	}
	else if (!strcmp(sCommand, "-forcepincache") || !strcmp(sCommand, "-forcepincacheoff")) 
	{
		cert_cache_enabled((!strcmp(sCommand, "-forcepincache")) ? 1 : 0);
	}
	else if (!strcmp(sCommand, "-certauthprompting") || !strcmp(sCommand, "-certauthpromptingoff")) 
	{
		cert_auth_prompting((!strcmp(sCommand, "-certauthprompting")) ? 1 : 0);
	}
	else if (!strcmp(sCommand, "-smartcardlogoncertsonly") || !strcmp(sCommand, "-smartcardlogoncertsonlyoff")) 
	{
		cert_smartcard_certs_only((!strcmp(sCommand, "-smartcardlogoncertsonly")) ? 1 : 0);
	}
	else if (!strcmp(sCommand, "-trustedcertsonly") || !strcmp(sCommand, "-trustedcertsonlyoff")) 
	{
		cert_trusted_certs_only((!strcmp(sCommand, "-trustedcertsonly")) ? 1 : 0);
	}
	else if (!strcmp(sCommand, "-ignoreexpiredcerts") || !strcmp(sCommand, "-ignoreexpiredcertsoff")) 
	{
		cert_ignore_expired_certs((!strcmp(sCommand, "-ignoreexpiredcerts")) ? 1 : 0);
	}
	else if (!strcmp(sCommand, "-allowanycert") || !strcmp(sCommand, "-allowanycertoff")) 
	{
		cert_allow_any_cert((!strcmp(sCommand, "-allowanycert")) ? 1 : 0);
	}
	else
	{
		return FALSE;
	}
	
	return TRUE;
}

#endif // PUTTY_CAC
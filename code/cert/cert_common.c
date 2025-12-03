#ifdef PUTTY_CAC

#define UMDF_USING_NTSTATUS
#include <ntstatus.h>

#include <windows.h>
#include <wincrypt.h>
#include <cryptuiapi.h>
#include <wincred.h>

#include "marshal.h"
#include "ssh.h"
#include "mpint.h"
#include "ecc.h"

#define DEFINE_VARIABLES
#include "cert_common.h"
#undef DEFINE_VARIABLES

#include "cert_pkcs.h"
#include "cert_capi.h"
#include "cert_fido.h"

#ifndef PUTTY_REG_POS
#define PUTTY_REG_POS "Software\\SimonTatham\\PuTTY"
#endif

VOID cert_reverse_array(LPBYTE pb, DWORD cb)
{
	for (DWORD i = 0, j = cb - 1; i < cb / 2; i++, j--)
	{
		BYTE b = pb[i];
		pb[i] = pb[j];
		pb[j] = b;
	}
}

LPSTR cert_get_cert_thumbprint(LPCSTR szIden, PCCERT_CONTEXT pCertContext)
{
	// sanity check
	if (szIden == NULL || pCertContext == NULL) return NULL;

	BYTE pbThumbBinary[SHA1_BINARY_SIZE];
	DWORD cbThumbBinary = SHA1_BINARY_SIZE;
	if (CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID, pbThumbBinary, &cbThumbBinary) == FALSE)
	{
		return NULL;
	}

	CHAR szThumbHex[SHA1_HEX_SIZE + 1];
	DWORD iThumbHexSize = _countof(szThumbHex);
	CryptBinaryToStringA(pbThumbBinary, cbThumbBinary,
		CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, szThumbHex, &iThumbHexSize);

	LPSTR szThumb = NULL;
	if (cert_is_capipath(szIden))
	{
		szThumb = dupprintf("CAPI:%s", szThumbHex);
	}
	else if (cert_is_pkcspath((LPSTR)szIden))
	{
		// retrieve the pkcs library that was stashed in the custom cert property
		WCHAR szFileName[MAX_PATH + 1];
		DWORD cbFileName = sizeof(szFileName);
		if (CertGetCertificateContextProperty(pCertContext, CERT_PVK_FILE_PROP_ID, szFileName, &cbFileName) == TRUE)
		{
			szThumb = dupprintf("PKCS:%s=%S", szThumbHex, szFileName);
		}
	}
	else if (cert_is_fidopath(szIden))
	{
		// retrieve the application id that was stashed in the custom cert property
		LPWSTR szCertData = NULL;
		DWORD iAppIdSize = 1000;
		CertGetCertificateContextProperty(pCertContext, CERT_FRIENDLY_NAME_PROP_ID, NULL, &iAppIdSize);
		if (iAppIdSize > 0 && (szCertData = malloc(iAppIdSize)) && CertGetCertificateContextProperty(
			pCertContext, CERT_FRIENDLY_NAME_PROP_ID, szCertData, &iAppIdSize) == TRUE)
		{
			szThumb = dupprintf("FIDO:%S", szCertData);
		}
		free(szCertData);
	}

	return szThumb;
}

LPSTR cert_prompt(LPCSTR szIden, BOOL bAutoSelect, LPCWSTR sCustomPrompt)
{
	HCERTSTORE hCertStore = NULL;
	LPCSTR szHint = NULL;

	if (cert_is_capipath(szIden))
	{
		hCertStore = cert_capi_get_cert_store();
	}
	else if (cert_is_pkcspath(szIden))
	{
		hCertStore = cert_pkcs_get_cert_store();
	}
	else if (cert_is_fidopath(szIden))
	{
		hCertStore = cert_fido_get_cert_store();
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
		// ignore invalid certs based on settings
		if (!cert_check_valid(szIden, pCertContext)) continue;

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
		pCertContext = CryptUIDlgSelectCertificateFromStore(hMemoryStore, GetForegroundWindow(),
			L"PuTTY: Select Certificate Or Key",
			sCustomPrompt != NULL ? sCustomPrompt : (
				L"Please select the certificate or key identifier that you would like " \
				L"to use for authentication to the remote system. For FIDO keys, PuTTY has " \
				L"generated a dynamic certificate to represent the key within PuTTY."),
			CRYPTUI_SELECT_LOCATION_COLUMN, 0, NULL);
	}

	// get the certificate hash to pass back
	if (pCertContext != NULL)
	{
		BYTE pbThumbBinary[SHA1_BINARY_SIZE];
		DWORD cbThumbBinary = SHA1_BINARY_SIZE;
		if (CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID, pbThumbBinary, &cbThumbBinary) == TRUE)
		{
			szCert = cert_get_cert_thumbprint(IDEN_PREFIX(szIden), pCertContext);
		}

		// cleanup
		CertFreeCertificateContext(pCertContext);
	}

	// cleanup and return
	CertCloseStore(hMemoryStore, CERT_CLOSE_STORE_FORCE_FLAG);
	return szCert;
}

BOOL cert_load_cert(LPCSTR szCert, PCERT_CONTEXT* ppCertContext, HCERTSTORE* phCertStore)
{
	if (cert_is_capipath(szCert))
	{
		cert_capi_load_cert(szCert, ppCertContext, phCertStore);
	}
	else if (cert_is_pkcspath(szCert))
	{
		cert_pkcs_load_cert(szCert, ppCertContext, phCertStore);
	}
	else if (cert_is_fidopath(szCert))
	{
		cert_fido_load_cert(szCert, ppCertContext, phCertStore);
	}

	// sanity check
	return (*ppCertContext != NULL);
}

BOOL cert_test_hash(LPCSTR szCert, DWORD iHashRequest)
{
	if (cert_is_capipath(szCert))
	{
		return cert_capi_test_hash(szCert, iHashRequest);
	}
	else if (cert_is_pkcspath(szCert))
	{
		return cert_pkcs_test_hash(szCert, iHashRequest);
	}
	else if (cert_is_fidopath(szCert))
	{
		return cert_pkcs_test_hash(szCert, iHashRequest);
	}

	return TRUE;
}

BOOL cert_confirm_signing(LPCSTR sFingerPrint, LPCSTR sComment)
{
	// prompt if usage prompting is enabled
	if (!cert_auth_prompting(CERT_QUERY)) return TRUE;

	// prompt user
	BOOL bIsCert = cert_is_certpath(sComment);
	LPSTR sDescription = bIsCert ? cert_subject_string(sComment) : dupstr(sComment);
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

BOOL cert_sign(struct ssh2_userkey* userkey, LPCBYTE pDataToSign, int iDataToSignLen, int iAgentFlags, struct strbuf * pSignature)
{
	LPBYTE pRawSig = NULL;
	DWORD iCounter = 0;
	BYTE iFlags = 0;
	int iRawSigLen = 0;

	// sanity check
	if (userkey->comment == NULL) return FALSE;

	// determine hashing algorithm for signing - upgrade to sha2 if possible
	LPCSTR sHashAlgName = userkey->key->vt->ssh_id;
	if (strstr(userkey->key->vt->ssh_id, "ssh-rsa") && (iAgentFlags & SSH_AGENT_RSA_SHA2_256) && cert_test_hash(userkey->comment, SSH_AGENT_RSA_SHA2_256)) {
		sHashAlgName = "rsa-sha2-256";
	}
	if (strstr(userkey->key->vt->ssh_id, "ssh-rsa") && (iAgentFlags & SSH_AGENT_RSA_SHA2_512) && cert_test_hash(userkey->comment, SSH_AGENT_RSA_SHA2_512)) {
		sHashAlgName = "rsa-sha2-512";
	}

	// sign data
	{
		if (cert_is_capipath(userkey->comment))
		{
			pRawSig = cert_capi_sign(userkey, pDataToSign, iDataToSignLen, &iRawSigLen, sHashAlgName);
		}
		else if (cert_is_pkcspath(userkey->comment))
		{
			pRawSig = cert_pkcs_sign(userkey, pDataToSign, iDataToSignLen, &iRawSigLen, sHashAlgName);
		}
		else if (cert_is_fidopath(userkey->comment))
		{
			pRawSig = cert_fido_sign(userkey, pDataToSign, iDataToSignLen, &iRawSigLen, sHashAlgName, &iCounter, &iFlags);
		}

		// sanity check signature
		if (pRawSig == NULL) return FALSE;
	}

	// create full wrapped signature payload
	if (strstr(userkey->key->vt->ssh_id, "ecdsa-") == userkey->key->vt->ssh_id ||
		strstr(userkey->key->vt->ssh_id, "sk-ecdsa-") == userkey->key->vt->ssh_id)
	{
		// For ECDSA keys the signature is encoded:
		// 
		// 	string     "sk-ecdsa-sha2-nistpXXX@openssh.com"
		// 	string	   ecdsa_signature (wrapped)
		//    mpint    r
		//    mpint    s
		// 	byte       flags (sk-only)
		// 	uint32     counter (sk-only)

		// append algorithm
		put_stringz(pSignature, userkey->key->vt->ssh_id);

		// append signatures
		strbuf* pRawSigWrapped = strbuf_new();
		mp_int* r = mp_from_bytes_be(make_ptrlen(&pRawSig[0], iRawSigLen / 2));
		mp_int* s = mp_from_bytes_be(make_ptrlen(&pRawSig[iRawSigLen / 2], iRawSigLen / 2));
		put_mp_ssh2(pRawSigWrapped, r);
		put_mp_ssh2(pRawSigWrapped, s);
		put_stringpl(pSignature, ptrlen_from_strbuf(pRawSigWrapped));
		strbuf_free(pRawSigWrapped);
		mp_free(r);
		mp_free(s);

		if (cert_is_fidopath(userkey->comment))
		{
			put_byte(pSignature, iFlags);
			put_uint32(pSignature, iCounter);
		}
	}
	else if (strstr(userkey->key->vt->ssh_id, "sk-ssh-ed25519") == userkey->key->vt->ssh_id)
	{
		// For Ed25519 keys the signature is encoded as:
		// 
		// string    "sk-ssh-ed25519@openssh.com"
		// string    signature
		// byte      flags (sk-only)
		// uint32    counter (sk-only)

		// append algorithm
		put_stringz(pSignature, userkey->key->vt->ssh_id);

		// append signatures
		put_stringpl(pSignature, make_ptrlen(&pRawSig[0], iRawSigLen));

		if (cert_is_fidopath(userkey->comment))
		{
			put_byte(pSignature, iFlags);
			put_uint32(pSignature, iCounter);
		}
	}
	else
	{
		// For RSA keys the signature is encoded as:
		// 
		// string    algorithm
		// string    signature

		// append algorithm
		put_stringz(pSignature, sHashAlgName);

		// append signatures
		put_string(pSignature, pRawSig, iRawSigLen);
	}

	// cleanup
	sfree(pRawSig);
	return TRUE;
}

struct ssh2_userkey* cert_get_ssh_userkey(LPCSTR szCert, PCERT_CONTEXT pCertContext)
{
	struct ssh2_userkey* pUserKey = NULL;

	// get a convenience pointer to the algorithm identifier 
	LPCSTR sAlgoId = pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
	LPCSTR sSigAlgId = pCertContext->pCertInfo->SignatureAlgorithm.pszObjId;

	// get convenience pointer to public key blob
	PCRYPT_BIT_BLOB pPubKey = _ADDRESSOF(pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey);

	// Handle RSA Keys
	if (strstr(sAlgoId, _CRT_CONCATENATE(szOID_RSA, ".")) == sAlgoId)
	{
		DWORD cbPublicKeyBlob = 0;
		LPBYTE pbPublicKeyBlob = NULL;
		if (CryptDecodeObject(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, pPubKey->pbData,
			pPubKey->cbData, 0, NULL, &cbPublicKeyBlob) != FALSE && cbPublicKeyBlob != 0 &&
			CryptDecodeObject(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, pPubKey->pbData,
				pPubKey->cbData, 0, pbPublicKeyBlob = malloc(cbPublicKeyBlob), &cbPublicKeyBlob) != FALSE)
		{
			// create a new putty rsa structure fill out all non-private params
			struct RSAKey* rsa = snew(struct RSAKey);
			ZeroMemory(rsa, sizeof(struct RSAKey));
			rsa->sshk.vt = find_pubkey_alg("ssh-rsa");

			RSAPUBKEY* pPublicKey = (RSAPUBKEY*)(pbPublicKeyBlob + sizeof(BLOBHEADER));
			rsa->bits = pPublicKey->bitlen;
			rsa->bytes = pPublicKey->bitlen / 8;
			rsa->exponent = mp_from_integer(pPublicKey->pubexp);
			cert_reverse_array((BYTE*)(pPublicKey)+sizeof(RSAPUBKEY), rsa->bytes);
			rsa->modulus = mp_from_bytes_be(make_ptrlen((BYTE*)(pPublicKey)+sizeof(RSAPUBKEY), rsa->bytes));
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

	// Handle EDDSA Keys
	else if (strstr(sAlgoId, szOID_ECC_PUBLIC_KEY) == sAlgoId && strcmp(sSigAlgId, szOID_ED25119) == 0)
	{
		// calculate key bit and byte lengths (ignore leading byte)
		int iKeyLength = ((pPubKey->cbData - 1) * 8 - pPubKey->cUnusedBits) / 2;
		const int iKeyBytes = (iKeyLength + 7) / 8;
		LPBYTE pPubKeyData = &pPubKey->pbData[1];

		// create eddsa struture to hold our key params
		struct eddsa_key* ec = snew(struct eddsa_key);
		ZeroMemory(ec, sizeof(struct eddsa_key));
		ec_ed_alg_and_curve_by_bits(iKeyLength, &(ec->curve), &(ec->sshk.vt));
		ec->privateKey = mp_from_integer(0);

		// translate v-tables for fido keys
		if (cert_is_fidopath(szCert))
		{
			if (ec->sshk.vt == &ssh_ecdsa_ed25519) ec->sshk.vt = &ssh_ecdsa_ed25519_sk;
			ec->appid = dupstr(IDEN_SPLIT(szCert));
		}

		// calculate public key
		mp_int* y = mp_from_bytes_le(make_ptrlen(pPubKeyData, iKeyBytes));
		unsigned desired_x_parity = mp_get_bit(y, ec->curve->fieldBytes * 8 - 1);
		mp_set_bit(y, ec->curve->fieldBytes * 8 - 1, 0);
		ec->publicKey = ecc_edwards_point_new_from_y(ec->curve->e.ec, y, desired_x_parity);
		mp_free(y);

		// fill out the user key
		pUserKey = snew(struct ssh2_userkey);
		pUserKey->key = &ec->sshk;
		pUserKey->comment = dupstr(szCert);
	}

	// Handle ECDSA Keys
	else if (strstr(sAlgoId, szOID_ECC_PUBLIC_KEY) == sAlgoId)
	{
		// fetch lengths
		DWORD iKeyLength = 0;
		DWORD iKeyLengthSize = sizeof(DWORD);
		BCRYPT_KEY_HANDLE hBCryptKey = NULL;
		if (CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, _ADDRESSOF(pCertContext->pCertInfo->SubjectPublicKeyInfo), 0, NULL, &hBCryptKey) == FALSE) return NULL;
		BCryptGetProperty(hBCryptKey, BCRYPT_KEY_LENGTH, (PUCHAR)&iKeyLength, iKeyLengthSize, &iKeyLengthSize, 0);
		const int iKeyBytes = (iKeyLength + 7) / 8;

		// create ecdsa struture to hold our key params
		struct ecdsa_key* ec = snew(struct ecdsa_key);
		ZeroMemory(ec, sizeof(struct ecdsa_key));
		ec_nist_alg_and_curve_by_bits(iKeyLength, &(ec->curve), &(ec->sshk.vt));
		ec->privateKey = mp_from_integer(0);

		// translate v-tables for fido keys
		if (cert_is_fidopath(szCert))
		{
			if (ec->sshk.vt == &ssh_ecdsa_nistp256) ec->sshk.vt = &ssh_ecdsa_nistp256_sk;
			if (ec->sshk.vt == &ssh_ecdsa_nistp384) ec->sshk.vt = &ssh_ecdsa_nistp384_sk;
			if (ec->sshk.vt == &ssh_ecdsa_nistp521) ec->sshk.vt = &ssh_ecdsa_nistp521_sk;
			ec->appid = dupstr(IDEN_SPLIT(szCert));
		}

		// calculate public key
		LPBYTE pPubKeyData = &pPubKey->pbData[1];
		ec->publicKey = ecc_weierstrass_point_new(ec->curve->w.wc,
			mp_from_bytes_be(make_ptrlen(&pPubKeyData[0], iKeyBytes)),
			mp_from_bytes_be(make_ptrlen(&pPubKeyData[iKeyBytes], iKeyBytes)));

		// fill out the user key
		pUserKey = snew(struct ssh2_userkey);
		pUserKey->key = &ec->sshk;
		pUserKey->comment = dupstr(szCert);
	}

	return pUserKey;
}

struct ssh2_userkey* cert_load_key(LPCSTR szCert)
{
	// sanity check
	if (szCert == NULL) return NULL;

	// if asterisk is specified, then prompt for certificate
	BOOL bDynamicLookup = strcmp(IDEN_SPLIT(szCert), "*") == 0;
	BOOL bDynamicLookupAutoSelect = strcmp(IDEN_SPLIT(szCert), "**") == 0;
	if (bDynamicLookup || bDynamicLookupAutoSelect)
	{
		szCert = cert_prompt(szCert, bDynamicLookupAutoSelect, NULL);
		if (szCert == NULL) return NULL;
	}

	// load certificate context
	PCERT_CONTEXT pCertContext = NULL;
	HCERTSTORE hCertStore = NULL;
	if (cert_load_cert(szCert, &pCertContext, &hCertStore) == FALSE) return NULL;

	// get the public key data
	struct ssh2_userkey* pUserKey = cert_get_ssh_userkey(szCert, pCertContext);
	CertFreeCertificateContext(pCertContext);
	CertCloseStore(hCertStore, 0);
	return pUserKey;
}

LPSTR cert_key_string(LPCSTR szCert)
{
	// sanity check
	if (szCert == NULL)
	{
		return NULL;
	}

	// load certificate context
	PCERT_CONTEXT pCertContext = NULL;
	HCERTSTORE hCertStore = NULL;
	if (cert_load_cert(szCert, &pCertContext, &hCertStore) == FALSE) return NULL;

	// obtain the key and destroy the comment since we are going to customize it
	struct ssh2_userkey* pUserKey = cert_get_ssh_userkey(szCert, pCertContext);
	if (pUserKey == NULL) return NULL;
	sfree(pUserKey->comment);
	pUserKey->comment = "";

	// fetch the elements of the string
	LPSTR szKey = ssh2_pubkey_openssh_str(pUserKey);
	LPSTR szName = cert_subject_string(szCert);
	LPSTR szHash = cert_get_cert_thumbprint(cert_iden(szCert), pCertContext);

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

	// for fido, just return the appid from the comment
	if (cert_is_fidopath(szCert))
	{
		return dupstr(&szCert[IDEN_FIDO_SIZE]);
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

BOOL cert_check_valid(LPCSTR szIden, PCCERT_CONTEXT pCertContext)
{
	// if user has enabled hidden option, just allow the certificate
	if (cert_allow_any_cert(CERT_QUERY))
	{
		return TRUE;
	}

	// since they are automatically generated consider all fido valid
	if (cert_is_fidopath(szIden))
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
		BOOL bFoundClientAuth = FALSE;
		for (DWORD iUsage = 0; iUsage < pUsage->cUsageIdentifier; iUsage++)
		{
			bFoundClientAuth |= strcmp(pUsage->rgpszUsageIdentifier[iUsage], szOID_PKIX_KP_CLIENT_AUTH) == 0;
			bFoundSmartCardLogon |= strcmp(pUsage->rgpszUsageIdentifier[iUsage], szOID_KP_SMARTCARD_LOGON) == 0;
		}

		// return false if no match found
		LocalFree(pUsage);
		if (!bFoundClientAuth && !bFoundSmartCardLogon) return FALSE;
	}

	// verify any excluded certificates are ignored
	LPCSTR sIgnoredCertName = cert_ignore_cert_name(NULL);
	BOOL bIgnoredCertNameMatch = FALSE;
	if (strlen(sIgnoredCertName) > 0)
	{
		DWORD iSize = CertNameToStr(X509_ASN_ENCODING, &pCertContext->pCertInfo->Subject, CERT_X500_NAME_STR, NULL, 0);
		if (iSize > 0)
		{
			LPCSTR sSubjectName = malloc(iSize);
			if (CertNameToStr(X509_ASN_ENCODING, &pCertContext->pCertInfo->Subject, CERT_X500_NAME_STR, sSubjectName, iSize) == iSize)
			{
				bIgnoredCertNameMatch = strstr(_strupr(sSubjectName), _strupr(sIgnoredCertName)) != NULL;
			}
			free(sSubjectName);
		}
	}
	free(sIgnoredCertName);
	if (bIgnoredCertNameMatch) return FALSE;

	// verify only smartcard card eku if requested
	if (cert_smartcard_certs_only(CERT_QUERY))
	{
		if (!bFoundSmartCardLogon) return FALSE;
	}

	// verify time validity if requested
	DWORD iFlags = CERT_STORE_TIME_VALIDITY_FLAG;
	if (cert_ignore_expired_certs(CERT_QUERY))
	{
		if (CertVerifySubjectCertificateContext(pCertContext, NULL, &iFlags) == TRUE && iFlags != 0)
			return FALSE;
	}

	// build and validate certificate chain
	if (cert_trusted_certs_only(CERT_QUERY))
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

int cert_all_certs(LPSTR** pszCert)
{
	// get a handle to the cert store
	LPCSTR sStoreType[2] = { IDEN_CAPI, IDEN_FIDO };
	HCERTSTORE hCertStore[2] =
	{
		cert_capi_get_cert_store(),
		cert_fido_get_cert_store()
	};

	// find certificates matching our criteria
	size_t iCertNum = 0;
	for (int iStore = 0; iStore < _countof(hCertStore); iStore++)
	{
		PCCERT_CONTEXT pCertContext = NULL;
		while ((pCertContext = CertEnumCertificatesInStore(hCertStore[iStore], pCertContext)) != NULL)
		{
			// ignore invalid certs based on settings
			if (!cert_check_valid(sStoreType[iStore], pCertContext)) continue;

			// count cert and [re]allocate the return string array
			*pszCert = snrealloc(*pszCert, iCertNum + 1, sizeof(LPSTR));
			(*pszCert)[iCertNum++] = cert_get_cert_thumbprint(sStoreType[iStore], pCertContext);
		}

		// cleanup and return
		CertCloseStore(hCertStore[iStore], 0);
	}

	return (int)iCertNum;
}

LPBYTE cert_get_hash(LPCSTR szAlgo, LPCBYTE pDataToHash, DWORD iDataToHashSize, DWORD* iHashedDataSize, BOOL bRequestDigest)
{
	const BYTE OID_SHA1[] = {
		0x30, 0x21, //  type Sequence, length 0x21 (33) 
		0x30, 0x09, //  type Sequence, length 0x09 (9) 
		0x06, 0x05, //  type OID, length 0x05 (5) 
		0x2b, 0x0e, 0x03, 0x02, 0x1a, //  id-sha1 OID 
		0x05, 0x00, //  type NULL, length 0x0 (0) 
		0x04, 0x14  //  type Octet string, length 0x14 (20), followed by sha1 hash 
	};
	const BYTE OID_SHA256[] = {
		0x30, 0x31, //  type Sequence, length 0x31 (49) 
		0x30, 0x0d, //  type Sequence, length 0x0d (13) 
		0x06, 0x09, //  type OID, length 0x09 (9) 
		0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, //  id-sha256 OID 
		0x05, 0x00, //  type NULL, length 0x0 (0) 
		0x04, 0x20  //  type Octet string, length 0x20 (32), followed by sha256 hash 
	};
	const BYTE OID_SHA384[] = {
		0x30, 0x41, //  type Sequence, length 0x41 (65) 
		0x30, 0x0d, //  type Sequence, length 0x0d (13) 
		0x06, 0x09, //  type OID, length 0x09 (9) 
		0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, //  id-sha384 OID 
		0x05, 0x00, //  type NULL, length 0x0 (0) 
		0x04, 0x30  //  type Octet string, length 0x30 (48), followed by sha384 hash 
	};
	const BYTE OID_SHA512[] = {
		0x30, 0x51, //  type Sequence, length 0x51 (81) 
		0x30, 0x0d, //  type Sequence, length 0x0d (13) 
		0x06, 0x09, //  type OID, length 0x09 (9) 
		0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, //  id-sha512 OID 
		0x05, 0x00, //  type NULL, length 0x0 (0) 
		0x04, 0x40  //  type Octet string, length 0x40 (64), followed by sha512 hash 
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
	else if (strcmp(szAlgo, "ecdsa-sha2-nistp384") == 0)
	{
		sNCryptAlg = BCRYPT_SHA384_ALGORITHM;
		if (bNeedsDigest)
		{
			iDigestSize = sizeof(OID_SHA384);
			pDigest = (LPBYTE)OID_SHA384;
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
		BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)iHashedDataSize, sizeof(DWORD), &iPropSize, 0) != STATUS_SUCCESS ||
		(pHashData = snewn(*iHashedDataSize + iDigestSize, BYTE)) == NULL ||
		BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != STATUS_SUCCESS ||
		BCryptHashData(hHash, (PBYTE)pDataToHash, iDataToHashSize, 0) != STATUS_SUCCESS ||
		BCryptFinishHash(hHash, pHashData + iDigestSize, (ULONG)*iHashedDataSize, 0) != STATUS_SUCCESS)
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

PVOID cert_pin(LPSTR szCert, BOOL bWide, LPVOID szPin)
{
	typedef struct CACHE_ITEM
	{
		struct CACHE_ITEM* NextItem;
		LPSTR szCert;
		VOID* szPin;
		DWORD iLength;
		BOOL bWide;
		DWORD iSize;
	}
	CACHE_ITEM;

	static CACHE_ITEM* PinCacheList = NULL;

	// attempt to locate the item in the pin cache
	for (CACHE_ITEM* hCurItem = PinCacheList; hCurItem != NULL; hCurItem = hCurItem->NextItem)
	{
		if (strcmp(hCurItem->szCert, szCert) == 0 && hCurItem->bWide == bWide)
		{
			VOID* pEncrypted = memcpy(malloc(hCurItem->iLength), hCurItem->szPin, hCurItem->iLength);
			CryptUnprotectMemory(pEncrypted, hCurItem->iLength, CRYPTPROTECTMEMORY_SAME_PROCESS);
			return pEncrypted;
		}
	}

	// request to add item to pin cache
	if (szPin != NULL)
	{
		// determine length of storage (round up to block size)
		const DWORD iLength = ((bWide) ? sizeof(WCHAR) : sizeof(CHAR)) *
			(1 + ((bWide) ? wcslen(szPin) : strlen(szPin)));
		const DWORD iCryptLength = CRYPTPROTECTMEMORY_BLOCK_SIZE *
			((iLength / CRYPTPROTECTMEMORY_BLOCK_SIZE) + 1);
		VOID* pEncrypted = memcpy(malloc(iCryptLength), szPin, iLength);

		// encrypt memory
		CryptProtectMemory(pEncrypted, iCryptLength,
			CRYPTPROTECTMEMORY_SAME_PROCESS);

		// allocate new item in cache and commit the change
		CACHE_ITEM* hItem = (CACHE_ITEM*)calloc(1, sizeof(struct CACHE_ITEM));
		hItem->szCert = _strdup(szCert);
		hItem->szPin = pEncrypted;
		hItem->iLength = iCryptLength;
		hItem->bWide = bWide;
		hItem->NextItem = PinCacheList;
		PinCacheList = hItem;
		return NULL;
	}

	// prompt the user to enter the pin
	CREDUI_INFOW tCredInfo;
	ZeroMemory(&tCredInfo, sizeof(CREDUI_INFOW));
	tCredInfo.cbSize = sizeof(tCredInfo);
	tCredInfo.pszCaptionText = L"PuTTY Authentication";
	tCredInfo.pszMessageText = L"Please Enter Your Smart Card Credentials";
	tCredInfo.hwndParent = GetDesktopWindow();
	WCHAR szUserName[CREDUI_MAX_USERNAME_LENGTH + 1] = L"<Using Smart Card>";
	WCHAR szPassword[CREDUI_MAX_PASSWORD_LENGTH + 1] = L"";
	if (CredUIPromptForCredentialsW(&tCredInfo, L"Smart Card", NULL, 0, szUserName,
		_countof(szUserName), szPassword, _countof(szPassword), NULL,
		CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_KEEP_USERNAME) != ERROR_SUCCESS)
	{
		return NULL;
	}

	PVOID szReturn = NULL;
	if (bWide)
	{
		szReturn = _wcsdup(szPassword);
	}
	else
	{
		CHAR szPasswordUtf8[CREDUI_MAX_PASSWORD_LENGTH + 1] = "";
		if (WideCharToMultiByte(CP_UTF8, 0, szPassword, -1, szPasswordUtf8, sizeof(szPasswordUtf8), NULL, NULL) > 0)
		{
			szReturn = _strdup(szPasswordUtf8);
		}
	}

	SecureZeroMemory(szPassword, sizeof(szPassword));
	return szReturn;
}

VOID cert_registry_setting_set(LPCSTR sSetting, CERT_SETCMD iCommand)
{
	const DWORD iSetting = (iCommand == CERT_SET) ? TRUE : FALSE;
	RegSetKeyValue(HKEY_CURRENT_USER, PUTTY_REG_POS, sSetting, REG_DWORD, &iSetting, sizeof(DWORD));
}

BOOL cert_registry_setting_load(LPCSTR sSetting, DWORD iDefault, CERT_SETCMD bPolicy)
{
	DWORD iSetting = 0;
	DWORD iSettingSize = sizeof(iSetting);
	if (RegGetValue(HKEY_LOCAL_MACHINE, PUTTY_REG_POS, sSetting,
		RRF_RT_REG_DWORD, NULL, &iSetting, &iSettingSize) == ERROR_SUCCESS)
	{
		if (bPolicy == CERT_ENFORCED) return TRUE;
		return iSetting;
	}
	if (bPolicy == CERT_ENFORCED) return FALSE;

	if (RegGetValue(HKEY_CURRENT_USER, PUTTY_REG_POS, sSetting,
		RRF_RT_REG_DWORD, NULL, &iSetting, &iSettingSize) == ERROR_SUCCESS)
	{
		return iSetting != 0;
	}
	return iDefault;
}

VOID cert_registry_setting_set_str(LPCSTR sSetting, LPCSTR sValue)
{
	RegSetKeyValue(HKEY_CURRENT_USER, PUTTY_REG_POS, sSetting, REG_SZ, sValue, strlen(sValue) + 1);
}

LPCSTR cert_registry_setting_load_str(LPCSTR sSetting, LPCSTR sDefault)
{
	LPCSTR sReturn = NULL;
	DWORD iReturnSize = 0;
	if (RegGetValue(HKEY_CURRENT_USER, PUTTY_REG_POS, sSetting,
			RRF_RT_REG_SZ, NULL, NULL, &iReturnSize) == ERROR_SUCCESS &&
		RegGetValue(HKEY_CURRENT_USER, PUTTY_REG_POS, sSetting,
			RRF_RT_REG_SZ, NULL, (sReturn = malloc(iReturnSize)), &iReturnSize) == ERROR_SUCCESS)
	{
		return sReturn;
	}
	else return _strdup(sDefault);
}

BOOL cert_trusted_certs_only(CERT_SETCMD iCommand)
{
	const LPSTR sSetting = "TrustedCertsOnly";
	if (iCommand & CERT_SET) cert_registry_setting_set(sSetting, iCommand);
	return cert_registry_setting_load(sSetting, FALSE, iCommand);
}

BOOL cert_save_cert_list_enabled(CERT_SETCMD iCommand)
{
	const LPSTR sSetting = "SaveCertListEnabled";
	if (iCommand & CERT_SET) cert_registry_setting_set(sSetting, iCommand);
	return cert_registry_setting_load(sSetting, FALSE, iCommand);
}

BOOL cert_cache_enabled(CERT_SETCMD iCommand)
{
	const LPSTR sSetting = "ForcePinCaching";
	if (iCommand & CERT_SET) cert_registry_setting_set(sSetting, iCommand);
	return cert_registry_setting_load(sSetting, FALSE, iCommand);
}

BOOL cert_auth_prompting(CERT_SETCMD iCommand)
{
	const LPSTR sSetting = "CertAuthPrompting";
	if (iCommand & CERT_SET) cert_registry_setting_set(sSetting, iCommand);
	return cert_registry_setting_load(sSetting, FALSE, iCommand);
}

BOOL cert_smartcard_certs_only(CERT_SETCMD iCommand)
{
	const LPSTR sSetting = "SmartCardLogonCertsOnly";
	if (iCommand & CERT_SET) cert_registry_setting_set(sSetting, iCommand);
	return cert_registry_setting_load(sSetting, FALSE, iCommand);
}

BOOL cert_ignore_expired_certs(CERT_SETCMD iCommand)
{
	const LPSTR sSetting = "IgnoreExpiredCerts";
	if (iCommand & CERT_SET) cert_registry_setting_set(sSetting, iCommand);
	return cert_registry_setting_load(sSetting, FALSE, iCommand);
}

BOOL cert_allow_any_cert(CERT_SETCMD iCommand)
{
	const LPSTR sSetting = "AllowAnyCert";
	if (iCommand & CERT_SET) cert_registry_setting_set(sSetting, iCommand);
	return cert_registry_setting_load(sSetting, FALSE, iCommand);
}

BOOL cert_auto_load_certs(CERT_SETCMD iCommand)
{
	const LPSTR sSetting = "AutoloadCerts";
	if (iCommand & CERT_SET) cert_registry_setting_set(sSetting, iCommand);
	return cert_registry_setting_load(sSetting, FALSE, iCommand);
}

DWORD cert_menu_flags(BOOL(*func)(CERT_SETCMD iCommand))
{
	DWORD flags = func(CERT_QUERY) ? MF_CHECKED : MF_UNCHECKED;
	flags |= func(CERT_ENFORCED) ? MF_GRAYED : MF_ENABLED;
	return flags;
}

LPCSTR cert_ignore_cert_name(LPCSTR sValue)
{
	const LPSTR sSetting = "IgnoreCertName";
	if (sValue != NULL) cert_registry_setting_set_str(sSetting, sValue);
	return cert_registry_setting_load_str(sSetting, "");
}

BOOL cert_cmdline_parse(LPCSTR sCommand)
{
	if (!strcmp(sCommand, "-autoload") || !strcmp(sCommand, "-autoloadoff"))
	{
		cert_auto_load_certs((!strcmp(sCommand, "-autoload")) ? CERT_SET : CERT_UNSET);
	}
	else if (!strcmp(sCommand, "-savecertlist") || !strcmp(sCommand, "-savecertlistoff"))
	{
		cert_save_cert_list_enabled((!strcmp(sCommand, "-savecertlist")) ? CERT_SET : CERT_UNSET);
	}
	else if (!strcmp(sCommand, "-forcepincache") || !strcmp(sCommand, "-forcepincacheoff"))
	{
		cert_cache_enabled((!strcmp(sCommand, "-forcepincache")) ? CERT_SET : CERT_UNSET);
	}
	else if (!strcmp(sCommand, "-certauthprompting") || !strcmp(sCommand, "-certauthpromptingoff"))
	{
		cert_auth_prompting((!strcmp(sCommand, "-certauthprompting")) ? CERT_SET : CERT_UNSET);
	}
	else if (!strcmp(sCommand, "-smartcardlogoncertsonly") || !strcmp(sCommand, "-smartcardlogoncertsonlyoff"))
	{
		cert_smartcard_certs_only((!strcmp(sCommand, "-smartcardlogoncertsonly")) ? CERT_SET : CERT_UNSET);
	}
	else if (!strcmp(sCommand, "-trustedcertsonly") || !strcmp(sCommand, "-trustedcertsonlyoff"))
	{
		cert_trusted_certs_only((!strcmp(sCommand, "-trustedcertsonly")) ? CERT_SET : CERT_UNSET);
	}
	else if (!strcmp(sCommand, "-ignoreexpiredcerts") || !strcmp(sCommand, "-ignoreexpiredcertsoff"))
	{
		cert_ignore_expired_certs((!strcmp(sCommand, "-ignoreexpiredcerts")) ? CERT_SET : CERT_UNSET);
	}
	else if (!strcmp(sCommand, "-allowanycert") || !strcmp(sCommand, "-allowanycertoff"))
	{
		cert_allow_any_cert((!strcmp(sCommand, "-allowanycert")) ? CERT_SET : CERT_UNSET);
	}
	else
	{
		return FALSE;
	}

	return TRUE;
}

#endif // PUTTY_CAC
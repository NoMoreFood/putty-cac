#ifdef PUTTY_CAC

#define UMDF_USING_NTSTATUS
#include <ntstatus.h>

#include "putty.h"

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

static BOOL cert_keyalg_is_x509(const ssh_keyalg* vt)
{
	return vt != NULL && vt->ssh_id != NULL && strstartswith(vt->ssh_id, "x509v3-");
}

BOOL cert_keyalg_is_rsa(const ssh_keyalg* vt)
{
	return vt == &ssh_rsa || vt == &ssh_rsa_sha256 || vt == &ssh_rsa_sha512 ||
		vt == &ssh_x509v3_ssh_rsa || vt == &ssh_x509v3_rsa2048_sha256;
}

BOOL cert_keyalg_is_ecdsa(const ssh_keyalg* vt)
{
	return vt == &ssh_ecdsa_nistp256 || vt == &ssh_ecdsa_nistp384 ||
		vt == &ssh_ecdsa_nistp521 || vt == &ssh_x509v3_ecdsa_nistp256 ||
		vt == &ssh_x509v3_ecdsa_nistp384 || vt == &ssh_x509v3_ecdsa_nistp521 ||
		vt == &ssh_ecdsa_nistp256_sk || vt == &ssh_ecdsa_nistp384_sk ||
		vt == &ssh_ecdsa_nistp521_sk;
}

/*
 * A certificate selector can resolve to a different key between loads. Only
 * substitute vtables which operate on exactly the same allocation layout.
 * In particular, raw/X.509 and FIDO/non-FIDO keys are not interchangeable.
 */
static BOOL cert_keyalgs_compatible(const ssh_keyalg* actual_vt, const ssh_keyalg* requested_vt)
{
	if (actual_vt == requested_vt) return TRUE;
	if (actual_vt == NULL || requested_vt == NULL) return FALSE;

	return cert_keyalg_is_rsa(actual_vt) && cert_keyalg_is_rsa(requested_vt) &&
		cert_keyalg_is_x509(actual_vt) == cert_keyalg_is_x509(requested_vt);
}

static void cert_free_loaded_userkey(struct ssh2_userkey* userkey, const ssh_keyalg* actual_vt)
{
	if (userkey == NULL) return;

	if (userkey->key != NULL)
	{
		/* Always dispatch destruction through the vtable matching the allocation. */
		if (actual_vt != NULL) userkey->key->vt = actual_vt;
		if (userkey->key->vt != NULL) ssh_key_free(userkey->key);
	}

	sfree(userkey->comment);
	sfree(userkey);
}

static struct ssh2_userkey* cert_load_compatible_key(
	LPCSTR szCert, const ssh_keyalg* requested_vt,
	const ssh_keyalg** actual_vt_out)
{
	struct ssh2_userkey* userkey = cert_load_key_with_x509(
		szCert, cert_keyalg_is_x509(requested_vt));

	if (userkey == NULL || userkey->key == NULL || userkey->key->vt == NULL)
	{
		cert_free_loaded_userkey(userkey, NULL);
		return NULL;
	}

	const ssh_keyalg* actual_vt = userkey->key->vt;
	if (requested_vt != NULL && !cert_keyalgs_compatible(actual_vt, requested_vt))
	{
		cert_free_loaded_userkey(userkey, actual_vt);
		return NULL;
	}

	if (requested_vt != NULL)
	{
		/* Retain a compatible alias (for example, an RSA hash variant). */
		userkey->key->vt = requested_vt;
		char* invalid = ssh_key_invalid(userkey->key, 0);
		if (invalid != NULL)
		{
			sfree(invalid);
			cert_free_loaded_userkey(userkey, actual_vt);
			return NULL;
		}
	}
	if (actual_vt_out != NULL) *actual_vt_out = actual_vt;

	return userkey;
}

struct ssh2_userkey* cert_load_key_for_keyalg(
	LPCSTR szCert, const ssh_keyalg* requested_vt)
{
	return cert_load_compatible_key(szCert, requested_vt, NULL);
}

BOOL cert_sign_for_keyalg(LPCSTR szCert, const ssh_keyalg* requested_vt,
	const void* expected_blob, size_t expected_blob_len,
	LPCBYTE pDataToSign, int iDataToSignLen, int iAgentFlags, struct strbuf* pSignature)
{
	const ssh_keyalg* actual_vt = NULL;
	struct ssh2_userkey* userkey = cert_load_compatible_key(
		szCert, requested_vt, &actual_vt);
	if (userkey == NULL) return FALSE;

	BOOL bSigned = cert_sign(userkey, expected_blob, expected_blob_len,
		pDataToSign, iDataToSignLen, iAgentFlags, pSignature);

	cert_free_loaded_userkey(userkey, actual_vt);
	return bSigned;
}

VOID cert_reverse_array(LPBYTE pb, DWORD cb)
{
	if (cb < 2) return;
	for (DWORD i = 0, j = cb - 1; i < cb / 2; i++, j--)
	{
		BYTE b = pb[i];
		pb[i] = pb[j];
		pb[j] = b;
	}
}

static BOOL cert_parse_sha1_thumbprint(LPCSTR szThumb, LPBYTE pbThumb)
{
	if (szThumb == NULL || pbThumb == NULL) return FALSE;

	/*
	 * Validate the fixed-width text before passing an explicit length to
	 * CryptStringToBinary. This also prevents a short string from making that
	 * API read beyond its terminating null.
	 */
	for (size_t i = 0; i < SHA1_HEX_SIZE; i++)
	{
		CHAR ch = szThumb[i];
		if (!((ch >= '0' && ch <= '9') ||
			(ch >= 'a' && ch <= 'f') ||
			(ch >= 'A' && ch <= 'F')))
		{
			return FALSE;
		}
	}

	DWORD cbThumb = SHA1_BINARY_SIZE;
	return CryptStringToBinaryA(szThumb, SHA1_HEX_SIZE,
		CRYPT_STRING_HEXRAW, pbThumb, &cbThumb, NULL, NULL) &&
		cbThumb == SHA1_BINARY_SIZE;
}

BOOL cert_parse_sha1_selector(LPCSTR szSelector, LPCSTR szPrefix,
	CHAR chSeparator, LPBYTE pbThumb, LPCSTR* pszPayload)
{
	if (szSelector == NULL || szPrefix == NULL || pbThumb == NULL)
		return FALSE;

	size_t iPrefixLen = strlen(szPrefix);
	if (_strnicmp(szSelector, szPrefix, iPrefixLen) != 0)
		return FALSE;

	LPCSTR szThumb = szSelector + iPrefixLen;
	if (!cert_parse_sha1_thumbprint(szThumb, pbThumb) ||
		szThumb[SHA1_HEX_SIZE] != chSeparator)
	{
		return FALSE;
	}

	if (chSeparator != '\0')
	{
		LPCSTR szPayload = &szThumb[SHA1_HEX_SIZE + 1];
		if (*szPayload == '\0') return FALSE;
		if (pszPayload != NULL) *pszPayload = szPayload;
	}
	else if (pszPayload != NULL)
	{
		*pszPayload = NULL;
	}

	return TRUE;
}

BOOL cert_context_matches_sha1(PCCERT_CONTEXT pCertContext,
	LPCBYTE pbThumb)
{
	if (pCertContext == NULL || pbThumb == NULL) return FALSE;

	BYTE pbContextThumb[SHA1_BINARY_SIZE];
	DWORD cbContextThumb = sizeof(pbContextThumb);
	return CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID,
		pbContextThumb, &cbContextThumb) &&
		cbContextThumb == SHA1_BINARY_SIZE &&
		memcmp(pbThumb, pbContextThumb, SHA1_BINARY_SIZE) == 0;
}

BOOL cert_parse_x509_public_blob(LPCSTR szKeyAlg,
	LPCBYTE pBlob, size_t iBlobLen,
	LPCBYTE* ppBody, size_t* piBodyLen,
	LPCBYTE* ppLeafCert, size_t* piLeafCertLen)
{
	if (szKeyAlg == NULL || pBlob == NULL || ppBody == NULL ||
		piBodyLen == NULL || ppLeafCert == NULL || piLeafCertLen == NULL)
	{
		return FALSE;
	}

	BinarySource src[1];
	BinarySource_BARE_INIT(src, pBlob, iBlobLen);
	if (!ptrlen_eq_string(get_string(src), szKeyAlg)) return FALSE;

	LPCBYTE pBody = get_ptr(src);
	size_t iBodyLen = get_avail(src);
	uint32_t iCertCount = get_uint32(src);
	if (iCertCount < 1 || iCertCount > get_avail(src) / 4)
		return FALSE;

	ptrlen leaf = { 0 };
	for (uint32_t i = 0; i < iCertCount && !get_err(src); i++)
	{
		ptrlen cert = get_string(src);
		if (get_err(src) || cert.len > MAXDWORD) return FALSE;

		PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, cert.ptr, (DWORD)cert.len);
		LPCBYTE pAlgorithm, pPublicKey;
		size_t iAlgorithmLen, iPublicKeyLen;
		BOOL bValid = pCertContext != NULL && (i != 0 ||
			(pCertContext->pCertInfo->dwVersion == CERT_V3 && cert_x509_subject_public_key(cert.ptr, cert.len,
				&pAlgorithm, &iAlgorithmLen, &pPublicKey, &iPublicKeyLen)));
		if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
		if (!bValid) return FALSE;
		if (i == 0) leaf = cert;
	}

	uint32_t iOcspCount = get_uint32(src);
	if (iOcspCount > iCertCount || iOcspCount > get_avail(src) / 4)
		return FALSE;
	for (uint32_t i = 0; i < iOcspCount && !get_err(src); i++)
	{
		ptrlen ocsp = get_string(src);
		if (get_err(src) || ocsp.len > MAXDWORD) return FALSE;
		POCSP_RESPONSE_INFO pOcspInfo = NULL;
		DWORD iOcspInfoLen = 0;
		LPCBYTE pOcsp = ocsp.ptr, pOcspEnd = pOcsp + ocsp.len, pValue;
		size_t iValueLen;
		BYTE iTag;
		if (!cert_der_read_tlv(&pOcsp, pOcspEnd, &iTag, &pValue, &iValueLen) || iTag != 0x30 ||
			pOcsp != pOcspEnd || !CryptDecodeObjectEx(X509_ASN_ENCODING, OCSP_RESPONSE, ocsp.ptr, (DWORD)ocsp.len,
				CRYPT_DECODE_ALLOC_FLAG, NULL, &pOcspInfo, &iOcspInfoLen))
		{
			return FALSE;
		}
		LocalFree(pOcspInfo);
	}

	if (get_err(src) || get_avail(src) != 0) return FALSE;
	*ppBody = pBody;
	*piBodyLen = iBodyLen;
	*ppLeafCert = leaf.ptr;
	*piLeafCertLen = leaf.len;
	return TRUE;
}

BOOL cert_der_read_tlv(LPCBYTE* ppData, LPCBYTE pEnd,
	BYTE* pTag, LPCBYTE* ppValue, size_t* piValueLen)
{
	LPCBYTE p = *ppData;
	if (p >= pEnd) return FALSE;
	*pTag = *p++;
	if (p >= pEnd) return FALSE;

	size_t iLen = *p++;
	if (iLen & 0x80)
	{
		unsigned iLenBytes = (unsigned)(iLen & 0x7F);
		if (iLenBytes < 1 || iLenBytes > 4 ||
			(size_t)(pEnd - p) < iLenBytes || *p == 0)
		{
			return FALSE;
		}

		iLen = 0;
		while (iLenBytes-- > 0) iLen = (iLen << 8) | *p++;
		if (iLen < 0x80) return FALSE;
	}

	if (iLen > (size_t)(pEnd - p)) return FALSE;
	*ppValue = p;
	*piValueLen = iLen;
	*ppData = p + iLen;
	return TRUE;
}

BOOL cert_x509_subject_public_key(LPCBYTE pCert, size_t iCertLen,
	LPCBYTE* ppAlgorithm, size_t* piAlgorithmLen,
	LPCBYTE* ppPublicKey, size_t* piPublicKeyLen)
{
	if (pCert == NULL || ppAlgorithm == NULL || piAlgorithmLen == NULL ||
		ppPublicKey == NULL || piPublicKeyLen == NULL)
		return FALSE;

	LPCBYTE p = pCert, pEnd = pCert + iCertLen, pValue;
	size_t iValueLen;
	BYTE iTag;

	/* Certificate ::= SEQUENCE { tbsCertificate, ... } */
	if (!cert_der_read_tlv(&p, pEnd, &iTag, &pValue, &iValueLen) ||
		iTag != 0x30 || p != pEnd)
	{
		return FALSE;
	}
	LPCBYTE pOuter = pValue;
	LPCBYTE pOuterEnd = pValue + iValueLen;

	/* tbsCertificate ::= SEQUENCE { ... } */
	if (!cert_der_read_tlv(&pOuter, pOuterEnd, &iTag, &pValue, &iValueLen) ||
		iTag != 0x30)
	{
		return FALSE;
	}
	LPCBYTE pTbs = pValue;
	size_t iTbsLen = iValueLen;

	// Validate the complete certificate envelope before parsing the TBS body.
	LPCBYTE pSignatureValue;
	size_t iSignatureValueLen;
	if (!cert_der_read_tlv(&pOuter, pOuterEnd, &iTag, &pSignatureValue, &iSignatureValueLen) || iTag != 0x30 ||
		!cert_der_read_tlv(&pOuter, pOuterEnd, &iTag, &pSignatureValue, &iSignatureValueLen) || iTag != 0x03 ||
		iSignatureValueLen < 1 || pSignatureValue[0] > 7 || pOuter != pOuterEnd)
	{
		return FALSE;
	}

	p = pTbs;
	pEnd = pTbs + iTbsLen;

	// Require the explicit X.509v3 version field.
	if (!cert_der_read_tlv(&p, pEnd, &iTag, &pValue, &iValueLen) || iTag != 0xA0)
	{
		return FALSE;
	}
	LPCBYTE pVersion = pValue;
	LPCBYTE pVersionEnd = pValue + iValueLen;
	if (!cert_der_read_tlv(&pVersion, pVersionEnd, &iTag, &pValue, &iValueLen) || iTag != 0x02 ||
		iValueLen != 1 || pValue[0] != 2 || pVersion != pVersionEnd)
	{
		return FALSE;
	}

	// Skip the serial number and four fields preceding SPKI.
	if (!cert_der_read_tlv(&p, pEnd, &iTag, &pValue, &iValueLen) ||
		iTag != 0x02)
	{
		return FALSE;
	}
	for (int i = 0; i < 4; i++)
	{
		if (!cert_der_read_tlv(&p, pEnd, &iTag, &pValue, &iValueLen) ||
			iTag != 0x30)
		{
			return FALSE;
		}
	}
	if (!cert_der_read_tlv(&p, pEnd, &iTag, &pValue, &iValueLen) ||
		iTag != 0x30)
	{
		return FALSE;
	}

	/* SubjectPublicKeyInfo ::= SEQUENCE { algorithm, BIT STRING }. */
	p = pValue;
	pEnd = pValue + iValueLen;
	if (!cert_der_read_tlv(&p, pEnd, &iTag, ppAlgorithm, piAlgorithmLen) ||
		iTag != 0x30 ||
		!cert_der_read_tlv(&p, pEnd, &iTag, &pValue, &iValueLen) ||
		iTag != 0x03 || p != pEnd || iValueLen < 1 || pValue[0] != 0)
	{
		return FALSE;
	}

	*ppPublicKey = pValue + 1;
	*piPublicKeyLen = iValueLen - 1;
	return TRUE;
}

static BOOL cert_x509_algorithm_matches(
	LPCBYTE pAlgorithm, size_t iAlgorithmLen,
	LPCBYTE pKeyOid, size_t iKeyOidLen,
	BYTE iParameterTag, LPCBYTE pParameter, size_t iParameterLen)
{
	LPCBYTE p = pAlgorithm, pEnd = pAlgorithm + iAlgorithmLen, pValue;
	size_t iValueLen;
	BYTE iTag;
	return cert_der_read_tlv(&p, pEnd, &iTag, &pValue, &iValueLen) &&
		iTag == 0x06 && iValueLen == iKeyOidLen &&
		memcmp(pValue, pKeyOid, iKeyOidLen) == 0 &&
		cert_der_read_tlv(&p, pEnd, &iTag, &pValue, &iValueLen) &&
		iTag == iParameterTag && iValueLen == iParameterLen &&
		memcmp(pValue, pParameter, iParameterLen) == 0 && p == pEnd;
}

BOOL cert_x509_ecdsa_public_key(LPCSTR szKeyAlg,
	LPCBYTE pCert, size_t iCertLen,
	LPCBYTE* ppPublicKey, size_t* piPublicKeyLen)
{
	if (szKeyAlg == NULL) return FALSE;

	static const BYTE idEcPublicKey[] = {
		0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
	};
	static const BYTE nistp256[] = {
		0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
	};
	static const BYTE nistp384[] = { 0x2B, 0x81, 0x04, 0x00, 0x22 };
	static const BYTE nistp521[] = { 0x2B, 0x81, 0x04, 0x00, 0x23 };

	LPCBYTE pCurveOid;
	size_t iCurveOidLen;
	if (!strcmp(szKeyAlg, "x509v3-ecdsa-sha2-nistp256"))
	{
		pCurveOid = nistp256;
		iCurveOidLen = sizeof(nistp256);
	}
	else if (!strcmp(szKeyAlg, "x509v3-ecdsa-sha2-nistp384"))
	{
		pCurveOid = nistp384;
		iCurveOidLen = sizeof(nistp384);
	}
	else if (!strcmp(szKeyAlg, "x509v3-ecdsa-sha2-nistp521"))
	{
		pCurveOid = nistp521;
		iCurveOidLen = sizeof(nistp521);
	}
	else
	{
		return FALSE;
	}

	LPCBYTE pAlgorithm;
	size_t iAlgorithmLen;
	return cert_x509_subject_public_key(
		pCert, iCertLen, &pAlgorithm, &iAlgorithmLen,
		ppPublicKey, piPublicKeyLen) &&
		cert_x509_algorithm_matches(
			pAlgorithm, iAlgorithmLen,
			idEcPublicKey, sizeof(idEcPublicKey),
			0x06, pCurveOid, iCurveOidLen);
}

static BOOL cert_der_positive_integer(LPCBYTE pValue, size_t iValueLen,
	LPCBYTE* ppInteger, size_t* piIntegerLen)
{
	if (iValueLen == 0 || (pValue[0] & 0x80) != 0) return FALSE;
	if (iValueLen > 1 && pValue[0] == 0)
	{
		if ((pValue[1] & 0x80) == 0) return FALSE;
		pValue++;
		iValueLen--;
	}
	if (iValueLen == 1 && pValue[0] == 0) return FALSE;
	*ppInteger = pValue;
	*piIntegerLen = iValueLen;
	return TRUE;
}

BOOL cert_decode_ecdsa_signature(LPCBYTE pDer, size_t iDerLen,
	size_t iPartLen, LPBYTE pSignature)
{
	if (pDer == NULL || iPartLen == 0 || iPartLen > SIZE_MAX / 2 ||
		pSignature == NULL)
	{
		return FALSE;
	}

	LPCBYTE p = pDer, pEnd = pDer + iDerLen, pValue;
	size_t iValueLen;
	BYTE iTag;
	if (!cert_der_read_tlv(&p, pEnd, &iTag, &pValue, &iValueLen) ||
		iTag != 0x30 || p != pEnd)
	{
		return FALSE;
	}

	p = pValue;
	pEnd = pValue + iValueLen;
	LPCBYTE pR, pS;
	size_t iRLen, iSLen;
	if (!cert_der_read_tlv(&p, pEnd, &iTag, &pValue, &iValueLen) ||
		iTag != 0x02 || !cert_der_positive_integer(
			pValue, iValueLen, &pR, &iRLen) ||
		!cert_der_read_tlv(&p, pEnd, &iTag, &pValue, &iValueLen) ||
		iTag != 0x02 || !cert_der_positive_integer(
			pValue, iValueLen, &pS, &iSLen) || p != pEnd ||
		iRLen > iPartLen || iSLen > iPartLen)
	{
		return FALSE;
	}

	memset(pSignature, 0, 2 * iPartLen);
	memcpy(pSignature + iPartLen - iRLen, pR, iRLen);
	memcpy(pSignature + 2 * iPartLen - iSLen, pS, iSLen);
	return TRUE;
}

BOOL cert_x509_rsa_public_key(LPCBYTE pCert, size_t iCertLen,
	LPCBYTE* ppModulus, size_t* piModulusLen,
	LPCBYTE* ppExponent, size_t* piExponentLen)
{
	if (ppModulus == NULL || piModulusLen == NULL || ppExponent == NULL || piExponentLen == NULL)
	{
		return FALSE;
	}

	static const BYTE rsaEncryption[] = {
		0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01
	};
	static const BYTE nullParameter[1] = { 0 };

	LPCBYTE p, pEnd, pValue, pAlgorithm;
	size_t iLen, iValueLen;
	BYTE iTag;
	if (!cert_x509_subject_public_key(
		pCert, iCertLen, &pAlgorithm, &iValueLen, &p, &iLen) ||
		!cert_x509_algorithm_matches(
			pAlgorithm, iValueLen,
			rsaEncryption, sizeof(rsaEncryption),
			0x05, nullParameter, 0))
	{
		return FALSE;
	}
	pEnd = p + iLen;
	if (!cert_der_read_tlv(&p, pEnd, &iTag, &pValue, &iValueLen) || iTag != 0x30 || p != pEnd)
	{
		return FALSE;
	}

	p = pValue;
	pEnd = pValue + iValueLen;
	if (!cert_der_read_tlv(&p, pEnd, &iTag, &pValue, &iValueLen) ||
		iTag != 0x02 || !cert_der_positive_integer(
			pValue, iValueLen, ppModulus, piModulusLen) ||
		!cert_der_read_tlv(&p, pEnd, &iTag, &pValue, &iValueLen) ||
		iTag != 0x02 || !cert_der_positive_integer(
			pValue, iValueLen, ppExponent, piExponentLen) || p != pEnd)
	{
		return FALSE;
	}

	return TRUE;
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

	// close original store as we no longer need it
	CertCloseStore(hCertStore, 0);

	// select certificate from store
	LPSTR szCert = NULL;
	if (iCertCount == 1 && bAutoSelect)
	{
		// auto select if only single certificate specified
		pCertContext = CertFindCertificateInStore(hMemoryStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_ANY, NULL, NULL);
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
	if (szCert == NULL || ppCertContext == NULL || phCertStore == NULL)
	{
		return FALSE;
	}

	*ppCertContext = NULL;
	*phCertStore = NULL;

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
		return cert_fido_test_hash(szCert, iHashRequest);
	}

	return TRUE;
}

typedef enum CERT_HASHALG
{
	CERT_HASH_INVALID,
	CERT_HASH_SHA1,
	CERT_HASH_SHA256,
	CERT_HASH_SHA384,
	CERT_HASH_SHA512
} CERT_HASHALG;

static CERT_HASHALG cert_hash_alg_from_name(LPCSTR szAlgo)
{
	if (szAlgo == NULL) return CERT_HASH_INVALID;
	if (strstartswith(szAlgo, "x509v3-"))
		szAlgo += strlen("x509v3-");

	if (!strcmp(szAlgo, "rsa-sha2-512") ||
		!strcmp(szAlgo, "ecdsa-sha2-nistp521") ||
		!strcmp(szAlgo, "sk-ecdsa-sha2-nistp521@openssh.com"))
		return CERT_HASH_SHA512;

	if (!strcmp(szAlgo, "ecdsa-sha2-nistp384") ||
		!strcmp(szAlgo, "sk-ecdsa-sha2-nistp384@openssh.com"))
		return CERT_HASH_SHA384;

	if (!strcmp(szAlgo, "rsa-sha2-256") ||
		!strcmp(szAlgo, "rsa2048-sha256") ||
		!strcmp(szAlgo, "ecdsa-sha2-nistp256") ||
		!strcmp(szAlgo, "sk-ecdsa-sha2-nistp256@openssh.com") ||
		!strcmp(szAlgo, "sk-ssh-ed25519@openssh.com"))
		return CERT_HASH_SHA256;

	return !strcmp(szAlgo, "ssh-rsa") ? CERT_HASH_SHA1 : CERT_HASH_INVALID;
}

static LPCSTR cert_signature_alg(
	struct ssh2_userkey* userkey, int iAgentFlags)
{
	if (userkey == NULL || userkey->key == NULL ||
		userkey->key->vt == NULL || userkey->key->vt->ssh_id == NULL)
	{
		return NULL;
	}

	LPCSTR szAlgo = userkey->key->vt->ssh_id;
	if (!strcmp(szAlgo, "x509v3-ssh-rsa"))
		return (iAgentFlags & SSH_AGENT_RSA_SHA2_256) ?
			"rsa2048-sha256" : "ssh-rsa";
	if (strstartswith(szAlgo, "x509v3-"))
		return szAlgo + strlen("x509v3-");

	if (!strcmp(szAlgo, "ssh-rsa"))
	{
		if ((iAgentFlags & SSH_AGENT_RSA_SHA2_512) &&
			userkey->comment != NULL &&
			cert_test_hash(userkey->comment, SSH_AGENT_RSA_SHA2_512))
		{
			return "rsa-sha2-512";
		}
		if ((iAgentFlags & SSH_AGENT_RSA_SHA2_256) &&
			userkey->comment != NULL &&
			cert_test_hash(userkey->comment, SSH_AGENT_RSA_SHA2_256))
		{
			return "rsa-sha2-256";
		}
	}

	return szAlgo;
}

BOOL cert_hash_alg(LPCSTR szAlgo, DWORD iHashRequest,
	DWORD* piHashAlg, LPCWSTR* psHashAlgId)
{
	CERT_HASHALG iResolvedHash = cert_hash_alg_from_name(szAlgo);
	if (iHashRequest == SSH_AGENT_RSA_SHA2_256)
		iResolvedHash = CERT_HASH_SHA256;
	else if (iHashRequest == SSH_AGENT_RSA_SHA2_512)
		iResolvedHash = CERT_HASH_SHA512;
	else if (iHashRequest != 0)
		return FALSE;
	if (iResolvedHash == CERT_HASH_INVALID) return FALSE;

	if (piHashAlg != NULL) *piHashAlg = CALG_SHA1;
	/* BCRYPT_SHA*_ALGORITHM and NCRYPT_SHA*_ALGORITHM share values. */
	if (psHashAlgId != NULL) *psHashAlgId = BCRYPT_SHA1_ALGORITHM;

	switch (iResolvedHash)
	{
	case CERT_HASH_SHA256:
		if (piHashAlg != NULL) *piHashAlg = CALG_SHA_256;
		if (psHashAlgId != NULL) *psHashAlgId = BCRYPT_SHA256_ALGORITHM;
		break;

	case CERT_HASH_SHA384:
		if (piHashAlg != NULL) *piHashAlg = CALG_SHA_384;
		if (psHashAlgId != NULL) *psHashAlgId = BCRYPT_SHA384_ALGORITHM;
		break;

	case CERT_HASH_SHA512:
		if (piHashAlg != NULL) *piHashAlg = CALG_SHA_512;
		if (psHashAlgId != NULL) *psHashAlgId = BCRYPT_SHA512_ALGORITHM;
		break;

	case CERT_HASH_SHA1:
	default:
		break;
	}

	return TRUE;
}

BOOL cert_confirm_signing(LPCSTR sFingerPrint, LPCSTR sComment,
	BOOL bProviderBacked)
{
	// prompt if usage prompting is enabled
	if (!cert_auth_prompting(CERT_QUERY)) return TRUE;

	// prompt user
	BOOL bIsCert = bProviderBacked && cert_is_certpath(sComment);
	LPSTR sDescription = bIsCert ? cert_subject_string(sComment) :
		dupstr(sComment != NULL ? sComment : "");
	if (sDescription == NULL)
	{
		/* The token or certificate may have disappeared since it was listed. */
		sDescription = dupstr(sComment != NULL ? sComment : "");
		bIsCert = FALSE;
	}
	LPSTR sMessage = dupprintf("%s\r\n\r\n%s: %s\r\n%s: %s\r\n\r\n %s",
		"An application is attempting to authenticate using a certificate or key with the following details:",
		bIsCert ? "Subject" : "Comment", sDescription,
		"Fingerprint", sFingerPrint != NULL ? sFingerPrint : "",
		"Would you like to permit this signing operation?");
	int iResponse = MessageBox(NULL, sMessage, "Certificate & Key Usage Confirmation - Pageant",
		MB_SYSTEMMODAL | MB_ICONQUESTION | MB_YESNO);
	sfree(sMessage);
	sfree(sDescription);

	// return true if user allowed
	return (iResponse == IDYES);
}

BOOL cert_public_blob_matches(struct ssh2_userkey* userkey, LPCBYTE pExpectedBlob, size_t iExpectedBlobLen)
{
	ptrlen expected = make_ptrlen(pExpectedBlob, iExpectedBlobLen);
	strbuf* actual = strbuf_new();
	ssh_key_public_blob(userkey->key, BinarySink_UPCAST(actual));
	if (!cert_keyalg_is_x509(userkey->key->vt))
	{
		BOOL bMatches = ptrlen_eq_ptrlen(expected, ptrlen_from_strbuf(actual));
		strbuf_free(actual);
		return bMatches;
	}

	// Bind X.509 signing to the leaf certificate while allowing chain refreshes.
	const ssh_keyalg* expected_vt = pubkey_blob_to_alg(expected);
	if (expected_vt == NULL || !cert_keyalg_is_x509(expected_vt) ||
		!cert_keyalgs_compatible(userkey->key->vt, expected_vt))
	{
		strbuf_free(actual);
		return FALSE;
	}

	LPCBYTE pExpectedBody, pExpectedLeaf, pActualBody, pActualLeaf;
	size_t iExpectedBodyLen, iExpectedLeafLen, iActualBodyLen, iActualLeafLen;
	BOOL bMatches = cert_parse_x509_public_blob(expected_vt->ssh_id, pExpectedBlob, iExpectedBlobLen,
		&pExpectedBody, &iExpectedBodyLen, &pExpectedLeaf, &iExpectedLeafLen) &&
		cert_parse_x509_public_blob(userkey->key->vt->ssh_id, actual->s, actual->len,
			&pActualBody, &iActualBodyLen, &pActualLeaf, &iActualLeafLen) &&
		iExpectedLeafLen == iActualLeafLen &&
		memcmp(pExpectedLeaf, pActualLeaf, iExpectedLeafLen) == 0;
	strbuf_free(actual);
	return bMatches;
}

BOOL cert_sign(struct ssh2_userkey* userkey,
	LPCBYTE pExpectedBlob, size_t iExpectedBlobLen,
	LPCBYTE pDataToSign, int iDataToSignLen, int iAgentFlags,
	struct strbuf* pSignature)
{
	LPBYTE pRawSig = NULL;
	DWORD iCounter = 0;
	BYTE iFlags = 0;
	int iRawSigLen = 0;

	if (userkey == NULL || userkey->key == NULL || userkey->key->vt == NULL ||
		userkey->comment == NULL || pDataToSign == NULL ||
		iDataToSignLen < 0 || pSignature == NULL)
	{
		return FALSE;
	}

	if (pExpectedBlob != NULL)
	{
		if (!cert_public_blob_matches(userkey, pExpectedBlob, iExpectedBlobLen)) return FALSE;
	}

	// determine hashing algorithm for signing - upgrade to sha2 if possible
	LPCSTR sHashAlgName = cert_signature_alg(userkey, iAgentFlags);
	if (cert_hash_alg_from_name(sHashAlgName) == CERT_HASH_INVALID)
		return FALSE;

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
	if (cert_keyalg_is_ecdsa(userkey->key->vt))
	{
		struct ecdsa_key* ec = container_of(
			userkey->key, struct ecdsa_key, sshk);
		size_t iPartLen = (ec->curve->fieldBits + 7) / 8;
		if (iRawSigLen < 0 || (size_t)iRawSigLen != 2 * iPartLen)
		{
			sfree(pRawSig);
			return FALSE;
		}
		// For ECDSA keys the signature is encoded:
		//
		//         string     "sk-ecdsa-sha2-nistpXXX@openssh.com"
		//         string           ecdsa_signature (wrapped)
		//    mpint    r
		//    mpint    s
		//         byte       flags (sk-only)
		//         uint32     counter (sk-only)
		//
		// append algorithm
		put_stringz(pSignature, sHashAlgName);

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
	else if (userkey->key->vt == &ssh_ecdsa_ed25519_sk)
	{
		if (iRawSigLen != 64)
		{
			sfree(pRawSig);
			return FALSE;
		}
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
	else if (cert_keyalg_is_rsa(userkey->key->vt))
	{
		if (iRawSigLen <= 0)
		{
			sfree(pRawSig);
			return FALSE;
		}
		// For RSA keys the signature is encoded as:
		//
		// string    algorithm
		// string    signature

		// append algorithm
		put_stringz(pSignature, sHashAlgName);

		/* RFC 6187 encodes RSA s as an unpadded unsigned integer. */
		LPBYTE pEncodedSig = pRawSig;
		int iEncodedSigLen = iRawSigLen;
		if (cert_keyalg_is_x509(userkey->key->vt))
		{
			while (iEncodedSigLen > 0 && *pEncodedSig == 0)
			{
				pEncodedSig++;
				iEncodedSigLen--;
			}
		}

		put_string(pSignature, pEncodedSig, iEncodedSigLen);
	}
	else
	{
		sfree(pRawSig);
		return FALSE;
	}

	// cleanup
	sfree(pRawSig);
	return TRUE;
}

BOOL cert_build_x509_public_blob_body(
	PCCERT_CONTEXT pCertContext, HCERTSTORE hCertStore,
	unsigned char** ppBlob, size_t* pBlobLen)
{
	*ppBlob = NULL;
	*pBlobLen = 0;
	strbuf* pBlob = strbuf_new();
	PCCERT_CHAIN_CONTEXT pChainContext = NULL;
	PCCERT_SIMPLE_CHAIN pSimpleChain = NULL;
	CERT_CHAIN_PARA tChainParams = { .cbSize = sizeof(tChainParams) };

	if (CertGetCertificateChain(NULL, pCertContext, NULL, hCertStore,
		&tChainParams, 0, NULL, &pChainContext) &&
		pChainContext != NULL && pChainContext->cChain > 0)
	{
		PCCERT_SIMPLE_CHAIN pCandidate = pChainContext->rgpChain[0];
		DWORD iInvalidChain = CERT_TRUST_IS_PARTIAL_CHAIN | CERT_TRUST_IS_CYCLIC |
			CERT_TRUST_IS_NOT_SIGNATURE_VALID | CERT_TRUST_INVALID_BASIC_CONSTRAINTS;
		if (pCandidate != NULL && pCandidate->cElement > 0 &&
			(pCandidate->TrustStatus.dwErrorStatus & iInvalidChain) == 0)
		{
			PCCERT_CONTEXT pFirst = pCandidate->rgpElement[0]->pCertContext;
			if (pFirst != NULL && pFirst->cbCertEncoded == pCertContext->cbCertEncoded &&
				memcmp(pFirst->pbCertEncoded, pCertContext->pbCertEncoded,
					pCertContext->cbCertEncoded) == 0)
			{
				pSimpleChain = pCandidate;
			}
		}
	}

	if (pSimpleChain != NULL)
	{
		DWORD iCertCount = pSimpleChain->cElement;
		PCERT_CHAIN_ELEMENT pLast = pSimpleChain->rgpElement[iCertCount - 1];
		if (iCertCount > 1 && (pLast->TrustStatus.dwInfoStatus & CERT_TRUST_IS_SELF_SIGNED) != 0)
		{
			/* RFC 6187 permits the self-signed root to be omitted. */
			iCertCount--;
		}

		put_uint32(pBlob, iCertCount);
		for (DWORD iCert = 0; iCert < iCertCount; iCert++)
		{
			PCCERT_CONTEXT pChainCert =
				pSimpleChain->rgpElement[iCert]->pCertContext;
			put_string(pBlob, pChainCert->pbCertEncoded,
				pChainCert->cbCertEncoded);
		}
	}
	else
	{
		if (pChainContext != NULL) CertFreeCertificateChain(pChainContext);
		strbuf_free(pBlob);
		return FALSE;
	}

	put_uint32(pBlob, 0); /* OCSP response count */
	if (pChainContext != NULL) CertFreeCertificateChain(pChainContext);

	*pBlobLen = pBlob->len;
	*ppBlob = (unsigned char*)strbuf_to_str(pBlob);
	return TRUE;
}

static struct ssh2_userkey* cert_get_ssh_userkey(
	LPCSTR szCert, PCERT_CONTEXT pCertContext, HCERTSTORE hCertStore,
	BOOL bAttemptX509)
{
	struct ssh2_userkey* pUserKey = NULL;
	/* FIDO certificates are synthetic containers, not RFC 6187 identities. */
	bAttemptX509 = bAttemptX509 && !cert_is_fidopath(szCert);
	bAttemptX509 = bAttemptX509 && pCertContext->pCertInfo->dwVersion == CERT_V3 &&
		cert_check_x509_usage(pCertContext, NULL);

	// get a convenience pointer to the algorithm identifier 
	LPCSTR sAlgoId = pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
	LPCSTR sSigAlgId = pCertContext->pCertInfo->SignatureAlgorithm.pszObjId;

	// get convenience pointer to public key blob
	PCRYPT_BIT_BLOB pPubKey = _ADDRESSOF(pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey);

	// Handle RSA Keys
	if (strcmp(sAlgoId, szOID_RSA_RSA) == 0)
	{
		DWORD cbPublicKeyBlob = 0;
		LPBYTE pbPublicKeyBlob = NULL;
		if (CryptDecodeObject(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, pPubKey->pbData,
			pPubKey->cbData, 0, NULL, &cbPublicKeyBlob) != FALSE && cbPublicKeyBlob != 0 &&
			CryptDecodeObject(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, pPubKey->pbData,
				pPubKey->cbData, 0, pbPublicKeyBlob = malloc(cbPublicKeyBlob), &cbPublicKeyBlob) != FALSE)
		{
			unsigned char* pCertData = NULL;
			size_t iCertDataLen = 0;
			if (bAttemptX509 && !cert_build_x509_public_blob_body(pCertContext, hCertStore, &pCertData, &iCertDataLen))
			{
				bAttemptX509 = FALSE;
			}

			// create a new putty rsa structure fill out all non-private params
			struct RSAKey* rsa;
			struct x509_ssh_rsa_key* xkey = NULL;
			// If X.509v3 behavior is enabled, allocate the X.509 wrapper struct and load the cert data
			if (bAttemptX509) {
				xkey = snew(struct x509_ssh_rsa_key);
				*xkey = (struct x509_ssh_rsa_key){0};
				rsa = &xkey->rsa;
				rsa->sshk.vt = find_pubkey_alg("x509v3-ssh-rsa");
				xkey->cert_data = pCertData;
				xkey->cert_len = iCertDataLen;
			} else {
				rsa = snew(struct RSAKey);
				*rsa = (struct RSAKey){0};
				rsa->sshk.vt = find_pubkey_alg("ssh-rsa");
			}

			RSAPUBKEY* pPublicKey = (RSAPUBKEY*)(pbPublicKeyBlob + sizeof(BLOBHEADER));
			rsa->bits = pPublicKey->bitlen;
			rsa->bytes = pPublicKey->bitlen / 8;
			rsa->exponent = mp_from_integer(pPublicKey->pubexp);
			cert_reverse_array((BYTE*)(pPublicKey)+sizeof(RSAPUBKEY), rsa->bytes);
			rsa->modulus = mp_from_bytes_be(make_ptrlen((BYTE*)(pPublicKey)+sizeof(RSAPUBKEY), rsa->bytes));
			rsa->comment = dupstr(szCert);
			/* Provider-backed keys have no exportable private components. */
			rsa->private_exponent = NULL;
			rsa->p = NULL;
			rsa->q = NULL;
			rsa->iqmp = NULL;

			// fill out the user key
			pUserKey = snew(struct ssh2_userkey);
			pUserKey->key = &rsa->sshk;
			pUserKey->comment = dupstr(szCert);
		}

		if (pbPublicKeyBlob != NULL) free(pbPublicKeyBlob);
	}

	// Handle EDDSA Keys
	else if (cert_is_fidopath(szCert) && strcmp(sAlgoId, szOID_ECC_PUBLIC_KEY) == 0 && strcmp(sSigAlgId, szOID_ED25519) == 0)
	{
		int iKeyLength = 256;
		const int iKeyBytes = 32;
		if (pPubKey->cbData < 1 + 2 * iKeyBytes || pPubKey->pbData[0] != 0x04) return NULL;
		LPBYTE pPubKeyData = &pPubKey->pbData[1];

		// create eddsa struture to hold our key params
		struct eddsa_key* ec = snew(struct eddsa_key);
		*ec = (struct eddsa_key){0};
		ec_ed_alg_and_curve_by_bits(iKeyLength, &(ec->curve), &(ec->sshk.vt));
		/* The FIDO provider performs signing; no private scalar is exportable. */
		ec->privateKey = NULL;

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
	else if (strcmp(sAlgoId, szOID_ECC_PUBLIC_KEY) == 0)
	{
		// Validate the SPKI and select the exact named NIST curve.
		BCRYPT_KEY_HANDLE hBCryptKey = NULL;
		if (CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, _ADDRESSOF(pCertContext->pCertInfo->SubjectPublicKeyInfo), 0, NULL, &hBCryptKey) == FALSE) return NULL;
		BCryptDestroyKey(hBCryptKey);

		LPCSTR sX509Alg = NULL;
		LPCBYTE pEncodedPoint = NULL;
		size_t iEncodedPointLen = 0;
		DWORD iKeyLength = 0;
		if (cert_x509_ecdsa_public_key("x509v3-ecdsa-sha2-nistp256", pCertContext->pbCertEncoded,
			pCertContext->cbCertEncoded, &pEncodedPoint, &iEncodedPointLen))
		{
			sX509Alg = "x509v3-ecdsa-sha2-nistp256";
			iKeyLength = 256;
		}
		else if (cert_x509_ecdsa_public_key("x509v3-ecdsa-sha2-nistp384", pCertContext->pbCertEncoded,
			pCertContext->cbCertEncoded, &pEncodedPoint, &iEncodedPointLen))
		{
			sX509Alg = "x509v3-ecdsa-sha2-nistp384";
			iKeyLength = 384;
		}
		else if (cert_x509_ecdsa_public_key("x509v3-ecdsa-sha2-nistp521", pCertContext->pbCertEncoded,
			pCertContext->cbCertEncoded, &pEncodedPoint, &iEncodedPointLen))
		{
			sX509Alg = "x509v3-ecdsa-sha2-nistp521";
			iKeyLength = 521;
		}
		else
		{
			return NULL;
		}

		const size_t iKeyBytes = (iKeyLength + 7) / 8;
		if (iEncodedPointLen != 1 + 2 * iKeyBytes || pEncodedPoint[0] != 0x04)
		{
			return NULL;
		}

		unsigned char* pCertData = NULL;
		size_t iCertDataLen = 0;
		if (bAttemptX509 && !cert_build_x509_public_blob_body(pCertContext, hCertStore, &pCertData, &iCertDataLen))
		{
			bAttemptX509 = FALSE;
		}

		struct ecdsa_key* ec;
		struct x509_ssh_ecdsa_key* xkey = NULL;
		if (bAttemptX509) {
			xkey = snew(struct x509_ssh_ecdsa_key);
			*xkey = (struct x509_ssh_ecdsa_key){0};
			ec = &xkey->ecdsa;
			ec->sshk.vt = find_pubkey_alg(sX509Alg);
			const ssh_keyalg *dummy_alg;
			ec_nist_alg_and_curve_by_bits(iKeyLength, &(ec->curve), &dummy_alg);
			xkey->cert_data = pCertData;
			xkey->cert_len = iCertDataLen;
		} else {
			ec = snew(struct ecdsa_key);
			*ec = (struct ecdsa_key){0};
			ec_nist_alg_and_curve_by_bits(iKeyLength, &(ec->curve), &(ec->sshk.vt));
		}
		if (ec->sshk.vt == NULL) {
			if (xkey) {
				sfree(xkey->cert_data);
				sfree(xkey);
			} else {
				sfree(ec);
			}
			return NULL;
		}
		/* CAPI/PKCS/FIDO providers do not expose the private scalar. */
		ec->privateKey = NULL;

		// translate v-tables for fido keys
		if (cert_is_fidopath(szCert))
		{
			if (ec->sshk.vt == &ssh_ecdsa_nistp256) ec->sshk.vt = &ssh_ecdsa_nistp256_sk;
			if (ec->sshk.vt == &ssh_ecdsa_nistp384) ec->sshk.vt = &ssh_ecdsa_nistp384_sk;
			if (ec->sshk.vt == &ssh_ecdsa_nistp521) ec->sshk.vt = &ssh_ecdsa_nistp521_sk;
			ec->appid = dupstr(IDEN_SPLIT(szCert));
		}

		// calculate public key
		LPCBYTE pPubKeyData = pEncodedPoint + 1;
		mp_int* x = mp_from_bytes_be(make_ptrlen(pPubKeyData, iKeyBytes));
		mp_int* y = mp_from_bytes_be(make_ptrlen(pPubKeyData + iKeyBytes, iKeyBytes));
		ec->publicKey = ecc_weierstrass_point_new(ec->curve->w.wc, x, y);
		mp_free(x);
		mp_free(y);
		if (ec->publicKey == NULL || !ecc_weierstrass_point_valid(ec->publicKey))
		{
			if (ec->publicKey != NULL)
				ecc_weierstrass_point_free(ec->publicKey);
			if (xkey) {
				sfree(xkey->cert_data);
				sfree(xkey);
			} else {
				sfree(ec);
			}
			return NULL;
		}

		// fill out the user key
		pUserKey = snew(struct ssh2_userkey);
		pUserKey->key = &ec->sshk;
		pUserKey->comment = dupstr(szCert);
	}

	return pUserKey;
}

struct ssh2_userkey* cert_load_key_with_x509(
	LPCSTR szCert, BOOL bAttemptX509)
{
	// sanity check
	if (!cert_is_certpath(szCert)) return NULL;
	LPSTR szResolvedCert = NULL;

	// if asterisk is specified, then prompt for certificate
	BOOL bDynamicLookup = strcmp(IDEN_SPLIT(szCert), "*") == 0;
	BOOL bDynamicLookupAutoSelect = strcmp(IDEN_SPLIT(szCert), "**") == 0;
	if (bDynamicLookup || bDynamicLookupAutoSelect)
	{
		szResolvedCert = cert_prompt(szCert, bDynamicLookupAutoSelect, NULL);
		if (szResolvedCert == NULL) return NULL;
		szCert = szResolvedCert;
	}

	// load certificate context
	PCERT_CONTEXT pCertContext = NULL;
	HCERTSTORE hCertStore = NULL;
	if (cert_load_cert(szCert, &pCertContext, &hCertStore) == FALSE)
	{
		sfree(szResolvedCert);
		return NULL;
	}

	// get the public key data
	struct ssh2_userkey* pUserKey = cert_get_ssh_userkey(
		szCert, pCertContext, hCertStore, bAttemptX509);
	CertFreeCertificateContext(pCertContext);
	if (hCertStore != NULL) CertCloseStore(hCertStore, 0);
	sfree(szResolvedCert);
	return pUserKey;
}

struct ssh2_userkey* cert_load_key(LPCSTR szCert)
{
	return cert_load_key_with_x509(szCert, cert_auth_x509_enabled(CERT_QUERY));
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
	struct ssh2_userkey* pUserKey = cert_get_ssh_userkey(
		szCert, pCertContext, hCertStore,
		cert_auth_x509_enabled(CERT_QUERY));
	if (pUserKey == NULL)
	{
		CertFreeCertificateContext(pCertContext);
		if (hCertStore != NULL) CertCloseStore(hCertStore, 0);
		return NULL;
	}
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
	if (hCertStore != NULL) CertCloseStore(hCertStore, 0);
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

BOOL cert_check_x509_usage(PCCERT_CONTEXT pCertContext, PBOOL pbFoundSmartCardLogon)
{
	if (pbFoundSmartCardLogon != NULL) *pbFoundSmartCardLogon = FALSE;
	if (pCertContext == NULL || pCertContext->pCertInfo == NULL) return FALSE;

	// Require digitalSignature when KeyUsage is present.
	PCERT_EXTENSION pKeyUsage = CertFindExtension(szOID_KEY_USAGE, pCertContext->pCertInfo->cExtension,
		pCertContext->pCertInfo->rgExtension);
	if (pKeyUsage != NULL)
	{
		BYTE tUsageInfo[2] = { 0, 0 };
		if (!CertGetIntendedKeyUsage(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pCertContext->pCertInfo,
			tUsageInfo, sizeof(tUsageInfo)) || (tUsageInfo[0] & CERT_DIGITAL_SIGNATURE_KEY_USAGE) == 0)
		{
			return FALSE;
		}
	}

	// Preserve CAC compatibility while rejecting unrelated EKUs.
	PCERT_EXTENSION pEnhancedKeyUsage = CertFindExtension(szOID_ENHANCED_KEY_USAGE,
		pCertContext->pCertInfo->cExtension, pCertContext->pCertInfo->rgExtension);
	if (pEnhancedKeyUsage != NULL)
	{
		PCERT_ENHKEY_USAGE pUsage = NULL;
		DWORD iUsageSize = 0;
		if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_ENHANCED_KEY_USAGE,
			pEnhancedKeyUsage->Value.pbData, pEnhancedKeyUsage->Value.cbData, CRYPT_DECODE_ALLOC_FLAG,
			NULL, &pUsage, &iUsageSize))
		{
			return FALSE;
		}

		BOOL bFoundClientAuth = FALSE;
		BOOL bFoundSmartCardLogon = FALSE;
		for (DWORD iUsage = 0; iUsage < pUsage->cUsageIdentifier; iUsage++)
		{
			LPCSTR sUsage = pUsage->rgpszUsageIdentifier[iUsage];
			bFoundClientAuth |= !strcmp(sUsage, szOID_PKIX_KP_CLIENT_AUTH) ||
				!strcmp(sUsage, szOID_PKIX_KP_SECURE_SHELL_CLIENT);
			bFoundSmartCardLogon |= !strcmp(sUsage, szOID_KP_SMARTCARD_LOGON);
		}
		LocalFree(pUsage);
		if (!bFoundClientAuth && !bFoundSmartCardLogon) return FALSE;
		if (pbFoundSmartCardLogon != NULL) *pbFoundSmartCardLogon = bFoundSmartCardLogon;
	}

	return TRUE;
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

	BOOL bFoundSmartCardLogon = FALSE;
	if (!cert_check_x509_usage(pCertContext, &bFoundSmartCardLogon))
		return FALSE;

	// verify any excluded certificates are ignored
	LPSTR sIgnoredCertName = cert_ignore_cert_name(NULL);
	BOOL bIgnoredCertNameMatch = FALSE;
	if (strlen(sIgnoredCertName) > 0)
	{
		DWORD iSize = CertNameToStr(X509_ASN_ENCODING, &pCertContext->pCertInfo->Subject, CERT_X500_NAME_STR, NULL, 0);
		if (iSize > 0)
		{
			LPSTR sSubjectName = malloc(iSize);
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
		CERT_CHAIN_PARA tChainParams = { .cbSize = sizeof(tChainParams) };
		PCCERT_CHAIN_CONTEXT pChainContext = NULL;
		BOOL bChainResult = CertGetCertificateChain(NULL, pCertContext, NULL, NULL, &tChainParams,
			CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, NULL, &pChainContext);
		if (bChainResult == false) return FALSE;

		// consider trusted if error was account offline crls
		DWORD dwIgnoredErrors = CERT_TRUST_IS_OFFLINE_REVOCATION | CERT_TRUST_REVOCATION_STATUS_UNKNOWN;
		if (!cert_ignore_expired_certs(CERT_QUERY))
		{
			// tolerate chain time errors only when not filtering expired certs
			dwIgnoredErrors |= CERT_TRUST_IS_NOT_TIME_VALID | CERT_TRUST_IS_NOT_TIME_NESTED;
		}
		BOOL bTrusted = (pChainContext->TrustStatus.dwErrorStatus & ~dwIgnoredErrors) == 0;
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
	if (iHashedDataSize == NULL || (pDataToHash == NULL && iDataToHashSize != 0))
		return NULL;
	*iHashedDataSize = 0;

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
	LPCWSTR sHashAlgId;

	const BOOL bNeedsDigest = bRequestDigest && szAlgo != NULL && (strstr(szAlgo, "rsa") != NULL);
	CERT_HASHALG iHashAlg = cert_hash_alg_from_name(szAlgo);
	if (iHashAlg == CERT_HASH_INVALID || !cert_hash_alg(szAlgo, 0, NULL, &sHashAlgId))
	{
		return NULL;
	}
	switch (iHashAlg)
	{
	case CERT_HASH_SHA256:
		if (bNeedsDigest)
		{
			iDigestSize = sizeof(OID_SHA256);
			pDigest = (LPBYTE)OID_SHA256;
		}
		break;

	case CERT_HASH_SHA384:
		if (bNeedsDigest)
		{
			iDigestSize = sizeof(OID_SHA384);
			pDigest = (LPBYTE)OID_SHA384;
		}
		break;

	case CERT_HASH_SHA512:
		if (bNeedsDigest)
		{
			iDigestSize = sizeof(OID_SHA512);
			pDigest = (LPBYTE)OID_SHA512;
		}
		break;

	case CERT_HASH_SHA1:
	default:
		if (bNeedsDigest)
		{
			iDigestSize = sizeof(OID_SHA1);
			pDigest = (LPBYTE)OID_SHA1;
		}
		break;
	}

	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	DWORD iPropSize = 0;
	LPBYTE pHashData = NULL;
	// acquire crypto provider, hash data, and export hashed binary data
	if (BCryptOpenAlgorithmProvider(&hAlg, sHashAlgId, NULL, 0) != STATUS_SUCCESS ||
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
		*iHashedDataSize = 0;
	}

	// prepend the digest if necessary
	if (bNeedsDigest && pHashData != NULL)
	{
		*iHashedDataSize += iDigestSize;
		memcpy(pHashData, pDigest, iDigestSize);
	}

	// cleanup and return
	if (hHash != NULL) BCryptDestroyHash(hHash);
	if (hAlg != NULL) BCryptCloseAlgorithmProvider(hAlg, 0);
	return pHashData;
}

PVOID cert_prompt_pin(BOOL bWide)
{
	CREDUI_INFOW tCredInfo = { .cbSize = sizeof(tCredInfo) };
	tCredInfo.pszCaptionText = L"PuTTY Authentication";
	tCredInfo.pszMessageText = L"Please Enter Your Smart Card Credentials";
	tCredInfo.hwndParent = GetDesktopWindow();
	WCHAR szUserName[CREDUI_MAX_USERNAME_LENGTH + 1] = L"<Using Smart Card>";
	WCHAR szPassword[CREDUI_MAX_PASSWORD_LENGTH + 1] = L"";
	if (CredUIPromptForCredentialsW(&tCredInfo, L"Smart Card", NULL, 0, szUserName, _countof(szUserName),
		szPassword, _countof(szPassword), NULL,
		CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_KEEP_USERNAME) != ERROR_SUCCESS)
	{
		SecureZeroMemory(szPassword, sizeof(szPassword));
		return NULL;
	}

	PVOID szReturn = NULL;
	if (bWide)
	{
		szReturn = _wcsdup(szPassword);
	}
	else
	{
		int iPasswordUtf8 = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, szPassword, -1, NULL, 0, NULL, NULL);
		LPSTR szPasswordUtf8 = iPasswordUtf8 > 0 ? malloc(iPasswordUtf8) : NULL;
		if (szPasswordUtf8 != NULL &&
			WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, szPassword, -1,
				szPasswordUtf8, iPasswordUtf8, NULL, NULL) == iPasswordUtf8)
		{
			szReturn = _strdup(szPasswordUtf8);
		}
		if (szPasswordUtf8 != NULL)
		{
			SecureZeroMemory(szPasswordUtf8, iPasswordUtf8);
			free(szPasswordUtf8);
		}
	}

	SecureZeroMemory(szPassword, sizeof(szPassword));
	return szReturn;
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
		VOID* pEncrypted = memcpy(calloc(1, iCryptLength), szPin, iLength);

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

	return cert_prompt_pin(bWide);
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
	if (iCommand & (CERT_SET | CERT_UNSET)) cert_registry_setting_set(sSetting, iCommand);
	return cert_registry_setting_load(sSetting, FALSE, iCommand);
}

BOOL cert_save_cert_list_enabled(CERT_SETCMD iCommand)
{
	const LPSTR sSetting = "SaveCertListEnabled";
	if (iCommand & (CERT_SET | CERT_UNSET)) cert_registry_setting_set(sSetting, iCommand);
	return cert_registry_setting_load(sSetting, FALSE, iCommand);
}

BOOL cert_cache_enabled(CERT_SETCMD iCommand)
{
	const LPSTR sSetting = "ForcePinCaching";
	if (iCommand & (CERT_SET | CERT_UNSET)) cert_registry_setting_set(sSetting, iCommand);
	return cert_registry_setting_load(sSetting, FALSE, iCommand);
}

BOOL cert_auth_prompting(CERT_SETCMD iCommand)
{
	const LPSTR sSetting = "CertAuthPrompting";
	if (iCommand & (CERT_SET | CERT_UNSET)) cert_registry_setting_set(sSetting, iCommand);
	return cert_registry_setting_load(sSetting, FALSE, iCommand);
}

BOOL cert_smartcard_certs_only(CERT_SETCMD iCommand)
{
	const LPSTR sSetting = "SmartCardLogonCertsOnly";
	if (iCommand & (CERT_SET | CERT_UNSET)) cert_registry_setting_set(sSetting, iCommand);
	return cert_registry_setting_load(sSetting, FALSE, iCommand);
}

BOOL cert_ignore_expired_certs(CERT_SETCMD iCommand)
{
	const LPSTR sSetting = "IgnoreExpiredCerts";
	if (iCommand & (CERT_SET | CERT_UNSET)) cert_registry_setting_set(sSetting, iCommand);
	return cert_registry_setting_load(sSetting, FALSE, iCommand);
}

BOOL cert_allow_any_cert(CERT_SETCMD iCommand)
{
	const LPSTR sSetting = "AllowAnyCert";
	if (iCommand & (CERT_SET | CERT_UNSET)) cert_registry_setting_set(sSetting, iCommand);
	return cert_registry_setting_load(sSetting, FALSE, iCommand);
}

BOOL cert_auto_load_certs(CERT_SETCMD iCommand)
{
	const LPSTR sSetting = "AutoloadCerts";
	if (iCommand & (CERT_SET | CERT_UNSET)) cert_registry_setting_set(sSetting, iCommand);
	return cert_registry_setting_load(sSetting, FALSE, iCommand);
}

BOOL cert_auth_x509_enabled(CERT_SETCMD iCommand)
{
	const LPSTR sSetting = "AuthX509";
	if (iCommand & (CERT_SET | CERT_UNSET)) cert_registry_setting_set(sSetting, iCommand);
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
	else if (!strcmp(sCommand, "-x509") || !strcmp(sCommand, "-x509off"))
	{
		cert_auth_x509_enabled((!strcmp(sCommand, "-x509")) ? CERT_SET : CERT_UNSET);
	}
	else
	{
		return FALSE;
	}

	return TRUE;
}

#endif // PUTTY_CAC

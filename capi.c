/*
 * CAPI: Windows Crypto API support file.
 * Andrew Prout, aprout at ll mit edu
 */

#include <windows.h>
#include <Cryptuiapi.h>
#include <ntstatus.h>
#include "capi.h"
#include "ssh.h"
#define SHA1_BYTES 20

typedef unsigned char		uint8;
typedef  signed  char		sint8;
typedef unsigned short		uint16;
typedef  signed  short		sint16;
//typedef unsigned long		uint32;
typedef  signed  long		sint32;

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Cryptui.lib")

//#define DebugLog_FileName "c:\\blah\\putty-capi.log"
#ifdef DebugLog_FileName
void AsciiDumpBuffer(FILE* iStream, uint8* buf, uint32 size) {
	uint32 x;
	for (x=0; x<size; x++) {
		if (x && (x % 8) == 0)
			fprintf(iStream, " ");
		if (buf[x] >= 32 && buf[x] <= 126)
			fprintf(iStream, "%hc", buf[x]);
		else
			fprintf(iStream, ".");
	}
}
void HexDumpBuffer(FILE* iStream, uint8* buf, uint32 size, char* newlinepad) {
	uint32 x, tmp;
	if (newlinepad)
		fprintf(iStream, "%s", newlinepad);
	for (x=0; x<size; x++) {
		if (x && (x % 16) == 0) {
			fprintf(iStream, " ");
			AsciiDumpBuffer(iStream, &buf[x-16], 16);
			fprintf(iStream, "\n");
			if (newlinepad)
				fprintf(iStream, "%s", newlinepad);
		}
		else if (x % 16 == 8)
			fprintf(iStream, "- ");
		if ((x % 16) == 0)
			fprintf(iStream, "%4u: ", x);
		fprintf(iStream, "%02X ", buf[x]);
	}
	tmp = 16 - (size%16);
	if (tmp != 16) {
		for (x=0; x<tmp; x++) {
			if (x == 7)
				fprintf(iStream, "  ");
			fprintf(iStream, "   ");
		}
	}
	tmp = size % 16;
	if (tmp == 0)
		tmp = 16;
	fprintf(iStream, " ");
	AsciiDumpBuffer(iStream, &buf[size - tmp], tmp);
	fprintf(iStream, "\n");
}

void debuglog_buffer(void* buf, uint32 size) {
	FILE* f = fopen(DebugLog_FileName, "a+");
	if (f == NULL)
		return;
	HexDumpBuffer(f, (uint8*) buf, size, "");
	fclose(f);
}
void debuglog(char* format, ...) {
	va_list arg_ptr;
	DWORD tmpAllocedSize = 16384;
	DWORD contlen;
	FILE* f;
	char* message;

	va_start(arg_ptr, format);
	message = (char*) malloc(tmpAllocedSize);
	if (!message)
		return;
	_vsnprintf(message, tmpAllocedSize, format, arg_ptr);
	message[tmpAllocedSize-1] = 0;
	contlen = (DWORD) strlen(message);

	f = fopen(DebugLog_FileName, "a+");
	if (f == NULL)
		return;
	fprintf(f, "%s", message);
	fclose(f);
	free(message);
}
#else //#ifdef DebugLog_FileName
	#define debuglog_buffer
	#define debuglog
#endif //#ifdef DebugLog_FileName

#define CAPI_PUT_32BIT(cp, value) { \
        (cp)[0] = (unsigned char)((value) >> 24);       \
        (cp)[1] = (unsigned char)((value) >> 16);       \
        (cp)[2] = (unsigned char)((value) >> 8);        \
        (cp)[3] = (unsigned char)(value); }

#define CAPI_BYTES_USED_IN_INT32(i) \
	(i & 0xFF000000 ? 4 : ( \
		i & 0x00FF0000 ? 3 : ( \
			i & 0x0000FF00 ? 2 : 1 \
		) \
	))

uint8 GetCodeFromHex(const char iHex) {
	if (iHex >= '0' && iHex <= '9') // numbers
		return iHex - 48;
	if (iHex >= 'A' && iHex <= 'F') // uppercase A-F
		return iHex - 55;
	if (iHex >= 'a' && iHex <= 'f') // lowercase a-f
		return iHex - 87;
	return 255;
}

BOOL hextobytes(const char* iHex, uint8* oBytes) {
	uint32 x = 0;
	uint8 val;
	while (iHex[x]) {
		val = GetCodeFromHex(iHex[x]);
		if (val >= 16)
			return FALSE;
		if (x % 2)
			oBytes[x/2] |= val;
		else
			oBytes[x/2] = (val << 4);
		x++;
#ifdef _DEBUG
		if (x > 10000)
			RaiseException(STATUS_BUFFER_OVERFLOW, EXCEPTION_NONCONTINUABLE, 0, 0);
#endif
	}
	return TRUE;
}

struct ssh2_userkey capi_key_ssh2_userkey = { 0, 0, 0 };

struct CAPI_PUBKEY_BIT_BLOB_struct {
	PUBLICKEYSTRUC publickeystruct;
	RSAPUBKEY rsapubkey;
//	BYTE modulus[0];
};

BOOL capi_get_cert_handle(char* certID, PCCERT_CONTEXT* oCertContext) {
	BOOL retval = FALSE;
    PCCERT_CONTEXT pCertContext = NULL, pFindCertContext = NULL;
	HCERTSTORE hStore = NULL;
	CRYPT_HASH_BLOB chb = { 0, NULL };
	DWORD FoundCount = 0, dwStoreType, tmpSize;
	char *LcertID = NULL, *LcertID_StoreType, *LcertID_StoreName, *LcertID_fingerprint;

	if (certID == NULL || oCertContext == NULL) {
		debuglog("capi_get_cert_handle: input parameter is NULL that cannot be\n");
		return FALSE; // no goto cleanup, it'll crash
	}

	if ((LcertID = malloc(strlen(certID) + 1)) == NULL) {
		debuglog("capi_get_cert_handle: malloc for LcertID failed\n");
		goto cleanup;
	}
	strcpy(LcertID, certID);

	LcertID_StoreType = strtok(LcertID, "\\");
	LcertID_StoreName = strtok(NULL, "\\");
	LcertID_fingerprint = strtok(NULL, "\\");
	if (LcertID_StoreType == NULL || LcertID_StoreName == NULL || LcertID_fingerprint == NULL) {
		debuglog("capi_get_cert_handle: strtok(LcertID) failed\n");
		goto cleanup;
	}

	if (strcmp(LcertID_StoreType, "User") == 0)
		dwStoreType = CERT_SYSTEM_STORE_CURRENT_USER;
	else if (strcmp(LcertID_StoreType, "System") == 0)
		dwStoreType = CERT_SYSTEM_STORE_LOCAL_MACHINE;
	else {
		debuglog("capi_get_cert_handle: Unknown store type\n");
		goto cleanup;
	}

	if (strlen(LcertID_fingerprint) != (SHA1_BYTES * 2)) {
		debuglog("capi_get_cert_handle: strlen(LcertID_fingerprint) != (SHA1_BYTES * 2)\n");
		goto cleanup;
	}

	chb.cbData = SHA1_BYTES;
	if ((chb.pbData = (BYTE*) malloc(SHA1_BYTES)) == NULL) {
		debuglog("capi_get_cert_handle: malloc for chb.pbData failed\n");
		goto cleanup;
	}
	if (!hextobytes(LcertID_fingerprint, chb.pbData)) {
		debuglog("capi_get_cert_handle: hextobytes(LcertID_fingerprint) failed\n");
		goto cleanup;
	}

	if((hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0 /*hCryptProv*/, dwStoreType | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_ENUM_ARCHIVED_FLAG, LcertID_StoreName)) == NULL) {
		debuglog("capi_get_cert_handle: CertOpenStore(%d, %s) failed\n", dwStoreType, LcertID_StoreName);
        goto cleanup;
	}

	while (pFindCertContext = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &chb, pFindCertContext)) {
		debuglog("capi_get_cert_handle: found a cert, checking for private key...\n");
		tmpSize = 0;
		if (CertGetCertificateContextProperty(pFindCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &tmpSize)) {
			debuglog("capi_get_cert_handle: got a private key duplicating context...\n");
			if (pCertContext == NULL)
				pCertContext = CertDuplicateCertificateContext(pFindCertContext);
			FoundCount++;
			debuglog("capi_get_cert_handle: All set\n");
		}
		else {
			// no private key, ignore the cert
		}
	}

	if (FoundCount != 1) {
		debuglog("capi_get_cert_handle: FoundCount != 1. FoundCount=%d\n", FoundCount);
		goto cleanup;
	}

	if (strcmp(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_RSA_RSA) != 0) {
		// Not an RSA key? egads, bail out...
		debuglog("capi_get_cert_handle: Not an RSA key?\n");
		debuglog("pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId=%s\n", pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);
		goto cleanup;
	}

	*oCertContext = pCertContext;
	pCertContext = NULL; // to avoid the free in cleanup;

	retval = TRUE;
cleanup:
	if (chb.pbData)
		free(chb.pbData);
	chb.pbData = NULL;

	if (LcertID)
		free(LcertID);
	LcertID = NULL;

	if (pCertContext)
		CertFreeCertificateContext(pCertContext);
	pCertContext = NULL;

	return retval;
}

BOOL capi_display_cert_ui(HWND hwnd, char* certID, WCHAR* title) {
	BOOL retval = FALSE;
    PCCERT_CONTEXT pCertContext = NULL;

	if (!capi_get_cert_handle(certID, &pCertContext)) {
		debuglog("capi_display_cert_ui: capi_get_cert_handle failed\n");
		goto cleanup;
	}

	if (!CryptUIDlgViewContext(CERT_STORE_CERTIFICATE_CONTEXT, pCertContext, hwnd, title, 0, NULL)) {
		debuglog("capi_display_cert_ui: CryptUIDlgViewContext failed\n");
		goto cleanup;
	}

	retval = TRUE;

cleanup:
	if (pCertContext)
		CertFreeCertificateContext(pCertContext);
	pCertContext = NULL;

	return retval;
}

BOOL capi_get_pubkey_blob(PCCERT_CONTEXT pCertContext, unsigned char** pubkey, int *blob_len) {
	BOOL retval = FALSE;
	DWORD tmpSize, mbits, mbytes, ebytes;
	int i; // signed, for loop goes to -1
	unsigned char *p = NULL;//, *modu = NULL;
	struct CAPI_PUBKEY_BIT_BLOB_struct* capi_pubkey = NULL;
	Bignum modu = NULL;

	if (pubkey == NULL || blob_len == NULL) {
		debuglog("capi_get_pubkey: input parameter is NULL that cannot be\n");
		return FALSE; // no goto cleanup, it'll crash
	}

	if ((mbits = CertGetPublicKeyLength(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &pCertContext->pCertInfo->SubjectPublicKeyInfo)) == 0) {
		debuglog("capi_get_pubkey: CertGetPublicKeyLength failed\n");
		goto cleanup;
	}
	debuglog("capi_get_pubkey: mbits=%d\n", mbits);

	tmpSize = 0;
	if (!CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData, pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData, 0, NULL, &tmpSize)) {
		debuglog("capi_get_pubkey: CryptDecodeObject[1] failed\n");
		goto cleanup;
	}
	capi_pubkey = malloc(tmpSize);
	if (!CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData, pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData, 0, capi_pubkey, &tmpSize)) {
		debuglog("capi_get_pubkey: CryptDecodeObject[2] failed\n");
		goto cleanup;
	}

	// the below formula for the format is taken from sc.c... I agree with the comments there, it's ugly.

//	ebytes = (ebits/8) + ((ebits % 8) ? 1 : 0);
	ebytes = CAPI_BYTES_USED_IN_INT32(capi_pubkey->rsapubkey.pubexp);
	mbytes = (mbits/8) + ((mbits % 8) ? 1 : 0);

	// offset by sizeof(*capi_pubkey) bytes to the public key...
	//modu = ((unsigned char*) capi_pubkey) + sizeof(*capi_pubkey);
	modu = bignum_from_bytes(((unsigned char*) capi_pubkey) + sizeof(*capi_pubkey), mbytes);

	debuglog("capi_get_pubkey_int: tmpSize=%d, capi_pubkey=:\n", tmpSize);
	debuglog_buffer(capi_pubkey, tmpSize);
	
    *blob_len = 4+7+4+ebytes+4+(1+mbytes); // mbytes has a leading zero
	if ((p = *pubkey = (unsigned char*) malloc(*blob_len)) == NULL) {
		debuglog("capi_get_pubkey: malloc for *pubkey failed\n");
		goto cleanup;
	}

	CAPI_PUT_32BIT(p, 7);
	p += 4;

	memcpy(p, "ssh-rsa", 7);
	p += 7;

	CAPI_PUT_32BIT(p, ebytes);
	p += 4;

	debuglog("capi_get_pubkey_int: ebytes=%d, capi_pubkey->rsapubkey.pubexp=%d (0x%08x), mbytes=%d, modu=:\n", ebytes, capi_pubkey->rsapubkey.pubexp, capi_pubkey->rsapubkey.pubexp, mbytes);
	debuglog_buffer(modu, mbytes);

	for (i=ebytes-1; i>=0; i--)
		*p++ = (unsigned char) ((capi_pubkey->rsapubkey.pubexp & (0xFF << (i*8))) >> (i*8));

	CAPI_PUT_32BIT(p, mbytes + 1); // add room for a leading zero
	p += 4;

	*p++ = 0; // leading zero
	for (i = 0; i < (int) mbytes; i++)
        *p++ = bignum_byte(modu, i);

	retval = TRUE;
cleanup:
	if (modu)
		freebn(modu);

	if (capi_pubkey)
		free(capi_pubkey);
	capi_pubkey = NULL;

	if (!retval) {
		if (pubkey) {
			if (*pubkey)
				free(*pubkey);
			*pubkey = NULL;
		}
		if (blob_len)
			*blob_len = 0;
	}

	return retval;
}

BOOL capi_get_pubkey_int(void *f /*frontend*/, char* certID, unsigned char** pubkey, char **algorithm, int *blob_len, PCCERT_CONTEXT* oCertContext) {
	BOOL retval = FALSE;
	PCCERT_CONTEXT pCertContext = NULL;

	if (certID == NULL || pubkey == NULL || algorithm == NULL || blob_len == NULL) {
		debuglog("capi_get_pubkey: input parameter is NULL that cannot be\n");
		return FALSE; // no goto cleanup, it'll crash
	}
	*pubkey = NULL;
	*algorithm = NULL;
	*blob_len = 0;
	// goto cleanup now OK

	if ((*algorithm = calloc(sizeof(char *), strlen("ssh-rsa")+1)) == NULL) {
		debuglog("capi_get_pubkey: calloc for *algorithm failed\n");
		goto cleanup;
	}
    strcpy(*algorithm, "ssh-rsa");

	if (!capi_get_cert_handle(certID, &pCertContext)) {
		debuglog("capi_get_pubkey: capi_get_cert_handle failed\n");
		goto cleanup;
	}

	if (!capi_get_pubkey_blob(pCertContext, pubkey, blob_len)) {
		debuglog("capi_get_pubkey_int: capi_get_pubkey_blob failed\n");
		goto cleanup;
	}

	if (oCertContext) {
		*oCertContext = pCertContext;
		pCertContext = NULL; // to avoid the free in cleanup;
	}
	retval = TRUE;
cleanup:
	if (!retval) {
		if (pubkey) {
			if (*pubkey)
				free(*pubkey);
			*pubkey = NULL;
		}
		if (algorithm) {
			if (*algorithm)
				free(*algorithm);
			*algorithm = NULL;
		}
		if (blob_len)
			*blob_len = 0;
	}

	return retval;
}
BOOL capi_get_pubkey(void *f, char* certID, unsigned char** pubkey, char **algorithm, int *blob_len) {
	return capi_get_pubkey_int(f, certID, pubkey, algorithm, blob_len, NULL);
}

char *capi_base64key(char *data, int len) {
    int bi, bn;
    char out[4];
    int datalen = len;
    char *buffi = calloc(len + len, sizeof(char *));
    int buffi_pos = 0;
    for(bi=0;bi<(len + len); bi++) buffi[bi] = '\0';
    while (datalen > 0) {
        bn = (datalen < 3 ? datalen : 3);
        base64_encode_atom(data, bn, out);
        data += bn;
        datalen -= bn;
        for (bi = 0; bi < 4; bi++) {
            buffi[buffi_pos] = out[bi];
            buffi_pos++;
        }
    }
    return buffi;
}

char* capi_get_key_string(char* certID) {
	unsigned char *pubkey, *algorithm;
	int pubkey_len;
	char *key64 = NULL, *keystring = NULL;

	if (!capi_get_pubkey(NULL, certID, &pubkey, &algorithm, &pubkey_len)) {
		debuglog("capi_get_key_string: capi_get_pubkey failed\n");
		goto cleanup;
	}
	debuglog("capi_get_key_string: Got pubkey. algorithm=%s. pubkey_len=%d. pubkey=:\n", algorithm, pubkey_len);
	debuglog_buffer(pubkey, pubkey_len);
	if ((key64 = capi_base64key(pubkey, pubkey_len)) == NULL) {
		debuglog("capi_get_key_string: capi_get_pubkey failed\n");
		goto cleanup;
	}
	if ((keystring = calloc(1, strlen("ssh-rsa")+1+strlen(key64)+1+strlen("CAPI:")+strlen(certID) + 1)) == NULL) {
		debuglog("capi_get_key_string: capi_get_pubkey failed\n");
		goto cleanup;
	}
	sprintf(keystring, "ssh-rsa %s CAPI:%s", key64, certID);
cleanup:
	return keystring;
}

BOOL capi_get_key_handle(void *f, char* certID, struct capi_keyhandle_struct** keyhandle) {
	BOOL retval = FALSE;
	struct capi_keyhandle_struct* newkeyhandle = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	HCRYPTKEY privkey = 0;
	DWORD ckpi_size;
	CRYPT_KEY_PROV_INFO* ckpi = NULL;

	if (certID == NULL || keyhandle == NULL) {
		debuglog("capi_get_pubkey: input parameter is NULL that cannot be\n");
		return FALSE; // no goto cleanup, it'll crash
	}
	*keyhandle = NULL;
	// goto cleanup now OK

	if ((newkeyhandle = calloc(1, sizeof(struct capi_keyhandle_struct))) == NULL)
		goto cleanup;

	if (!capi_get_pubkey_int(f, certID, &newkeyhandle->pubkey, &newkeyhandle->algorithm, &newkeyhandle->pubkey_len, &pCertContext))
		goto cleanup;

	ckpi_size = 0;
	if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &ckpi_size))
		goto cleanup;
	if ((ckpi = (CRYPT_KEY_PROV_INFO*) malloc(ckpi_size)) == NULL)
		goto cleanup;
	if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, ckpi, &ckpi_size))
		goto cleanup;
	if (ckpi->dwProvType == 0) { // CNG
		// eh, later...
debuglog("capi_get_key_handle: CNG Key, bailing...\n");
		goto cleanup;
	}
	else { // CAPI
		if (!CryptAcquireContextW((HCRYPTPROV*) &newkeyhandle->win_provider, ckpi->pwszContainerName, ckpi->pwszProvName, ckpi->dwProvType, ((ckpi->dwFlags & CRYPT_MACHINE_KEYSET) ? CRYPT_MACHINE_KEYSET : 0) )) {
			debuglog("capi_get_key_handle: Error calling CryptAcquireContext. GetLastError()=%i (0x%08x)\n", GetLastError(), GetLastError());
			goto cleanup;
		}
		newkeyhandle->win_keyspec = ckpi->dwKeySpec;
	}

	*keyhandle = newkeyhandle;
	retval = TRUE;
cleanup:
	if (pCertContext)
		CertFreeCertificateContext(pCertContext);
	pCertContext = NULL;

	if (ckpi)
		free(ckpi);
	ckpi = NULL;

	if (!retval) {
		if (newkeyhandle) {
			if (newkeyhandle->win_provider)
				CryptReleaseContext((HCRYPTPROV) newkeyhandle->win_provider, 0);
			newkeyhandle->win_provider = NULL;

			if (newkeyhandle->pubkey)
				free(newkeyhandle->pubkey);
			newkeyhandle->pubkey = NULL;

			if (newkeyhandle->algorithm)
				free(newkeyhandle->algorithm);
			newkeyhandle->algorithm = NULL;

			free(newkeyhandle);
		}
		newkeyhandle = NULL;
	}

	return retval;
}

unsigned char* capi_sig_certID(char* certID, char *sigdata, int sigdata_len, int *sigblob_len) {
	BOOL success = FALSE;
	unsigned char* retval = NULL, *rawsig = NULL, *p;
	HCRYPTHASH hash = 0;
	DWORD ckpi_size, tmpSize, tmpHashLen, rawsig_len, x;
	Bignum bn = NULL;
	HCRYPTPROV hProv = 0;
	CRYPT_KEY_PROV_INFO* ckpi = NULL;
	PCCERT_CONTEXT pCertContext = NULL;

	debuglog("capi_sig_certID called. sigdata_len=%d\n", sigdata_len);
	debuglog_buffer(sigdata, sigdata_len);

	// Find cert context from certID
	if (!capi_get_cert_handle(certID, &pCertContext)) {
		debuglog("capi_sig: capi_get_cert_handle failed\n");
		goto cleanup;
	}

	// find the key info from the cert and get a handle
	if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &ckpi_size))
		goto cleanup;
	if ((ckpi = (CRYPT_KEY_PROV_INFO*) malloc(ckpi_size)) == NULL)
		goto cleanup;
	if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, ckpi, &ckpi_size))
		goto cleanup;
	if (ckpi->dwProvType == 0) { // CNG
		// eh, later...
debuglog("capi_sig_certID: CNG Key, bailing...\n");
		goto cleanup;
	}
	else { // CAPI
		if (!CryptAcquireContextW(&hProv, ckpi->pwszContainerName, ckpi->pwszProvName, ckpi->dwProvType, ((ckpi->dwFlags & CRYPT_MACHINE_KEYSET) ? CRYPT_MACHINE_KEYSET : 0) )) {
			debuglog("capi_sig_certID: Error calling CryptAcquireContext. GetLastError()=%i (0x%08x)\n", GetLastError(), GetLastError());
			goto cleanup;
		}
	}

	// create the hash object, set it to SHA-1 and confirm expectations
	if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hash))
		goto cleanup;
	tmpSize = sizeof(tmpHashLen);
	if (!CryptGetHashParam(hash, HP_HASHSIZE, (BYTE *) &tmpHashLen, &tmpSize, 0))
		goto cleanup;
	if (tmpHashLen != SHA1_BYTES)
		goto cleanup;

	if (!CryptHashData(hash, sigdata, sigdata_len, 0))
		goto cleanup;

	// hash & sign
	rawsig_len = 0;
	if (!CryptSignHash(hash, ckpi->dwKeySpec, NULL, 0, NULL, &rawsig_len))
		goto cleanup;

	rawsig = malloc(rawsig_len);
	if (!CryptSignHash(hash, ckpi->dwKeySpec, NULL, 0, rawsig, &rawsig_len))
		goto cleanup;

	// convert to SSH-style buffer
	bn = bignum_from_bytes(rawsig, rawsig_len);
	tmpSize = (bignum_bitcount(bn) + 7) / 8;
	*sigblob_len = 4 + 7 + 4 + tmpSize;
	if ((p = retval = calloc(1, *sigblob_len)) == NULL)
		goto cleanup;

	CAPI_PUT_32BIT(p, 7);
	p += 4;

	memcpy(p, "ssh-rsa", 7);
	p += 7;

	CAPI_PUT_32BIT(p, tmpSize);
	p += 4;

	for (x = 0; x < tmpSize; x++)
		*p++ = bignum_byte(bn, x);

	success = TRUE;
cleanup:
	if (pCertContext)
		CertFreeCertificateContext(pCertContext);
	pCertContext = NULL;

	if (hProv)
		CryptReleaseContext(hProv, 0);
	hProv = 0;

	if (ckpi)
		free(ckpi);
	ckpi = NULL;

	if (hash)
		CryptDestroyHash(hash);
	hash = 0;

	if (rawsig)
		free(rawsig);
	rawsig = NULL;

	if (bn)
		freebn(bn);
	bn = NULL;

	if (!success) {
		if (retval)
			free(retval);
		retval = NULL;
	}
	return retval;
}

unsigned char* capi_sig(struct capi_keyhandle_struct* keyhandle, char *sigdata, int sigdata_len, int *sigblob_len) {
	BOOL success = FALSE;
	unsigned char* retval = NULL, *rawsig = NULL, *p;
	HCRYPTHASH hash = 0;
	DWORD tmpSize, tmpHashLen, rawsig_len, x;
	Bignum bn = NULL;

	debuglog("capi_sig(keyhandle) called. sigdata_len=%d\n", sigdata_len);
	debuglog_buffer(sigdata, sigdata_len);

	if (!CryptCreateHash((HCRYPTPROV) keyhandle->win_provider, CALG_SHA1, 0, 0, &hash))
		goto cleanup;
	tmpSize = sizeof(tmpHashLen);
	if (!CryptGetHashParam(hash, HP_HASHSIZE, (BYTE *) &tmpHashLen, &tmpSize, 0))
		goto cleanup;
	if (tmpHashLen != SHA1_BYTES)
		goto cleanup;

	if (!CryptHashData(hash, sigdata, sigdata_len, 0))
		goto cleanup;

	rawsig_len = 0;
	if (!CryptSignHash(hash, keyhandle->win_keyspec, NULL, 0, NULL, &rawsig_len))
		goto cleanup;

	rawsig = malloc(rawsig_len);
	if (!CryptSignHash(hash, keyhandle->win_keyspec, NULL, 0, rawsig, &rawsig_len))
		goto cleanup;

	bn = bignum_from_bytes(rawsig, rawsig_len);
	tmpSize = (bignum_bitcount(bn) + 7) / 8;
	*sigblob_len = 4 + 7 + 4 + tmpSize;
	if ((p = retval = calloc(1, *sigblob_len)) == NULL)
		goto cleanup;

	CAPI_PUT_32BIT(p, 7);
	p += 4;

	memcpy(p, "ssh-rsa", 7);
	p += 7;

	CAPI_PUT_32BIT(p, tmpSize);
	p += 4;

	for (x = 0; x < tmpSize; x++)
		*p++ = bignum_byte(bn, x);

	success = TRUE;
cleanup:
	if (hash)
		CryptDestroyHash(hash);
	hash = 0;

	if (rawsig)
		free(rawsig);
	rawsig = NULL;

	if (bn)
		freebn(bn);
	bn = NULL;

	if (!success) {
		if (retval)
			free(retval);
		retval = NULL;
	}
	return retval;
}

void capi_release_key(struct capi_keyhandle_struct** keyhandle) {
	if (keyhandle) {
		if (*keyhandle) {
			if ((*keyhandle)->win_provider)
				CryptReleaseContext((HCRYPTPROV) (*keyhandle)->win_provider, 0);
			(*keyhandle)->win_provider = NULL;

			if ((*keyhandle)->pubkey)
				free((*keyhandle)->pubkey);
			(*keyhandle)->pubkey = NULL;

			if ((*keyhandle)->algorithm)
				free((*keyhandle)->algorithm);
			(*keyhandle)->algorithm = NULL;

			free(*keyhandle);
		}
		*keyhandle = NULL;
	}
	return;
}

struct CAPI_userkey* Create_CAPI_userkey(const char* certID, PCERT_CONTEXT pCertContext) {
	BOOL success = FALSE;
	struct CAPI_userkey* retval = NULL;
	PCERT_CONTEXT LpCertContext = NULL;

	if (pCertContext == NULL) {
		if (!capi_get_cert_handle(certID, &LpCertContext)) {
			debuglog("Create_CAPI_userkey: capi_get_cert_handle failed\n");
			goto cleanup;
		}
		pCertContext = LpCertContext;
	}

	if ((retval = malloc(sizeof(struct CAPI_userkey))) == NULL) {
		debuglog("Create_CAPI_userkey: malloc for retval failed\n");
		goto cleanup;
	}
	retval->certID = NULL;
	retval->blob = NULL;

	if ((retval->certID = malloc(strlen(certID) + 1)) == NULL) {
		debuglog("Create_CAPI_userkey: malloc for certID failed\n");
		goto cleanup;
	}
	strcpy(retval->certID, certID);

	if (!capi_get_pubkey_blob(pCertContext, &retval->blob, &retval->bloblen)) {
		debuglog("Create_CAPI_userkey: capi_get_pubkey_blob failed\n");
		goto cleanup;
	}

	success = TRUE;
cleanup:
	if (LpCertContext)
		CertFreeCertificateContext(LpCertContext);
	LpCertContext = NULL;

	if (!success) {
		Free_CAPI_userkey(retval);
		retval = NULL;
	}
	return retval;
}
void Free_CAPI_userkey(struct CAPI_userkey* ckey) {
	if (ckey->certID)
		free(ckey->certID);
	ckey->certID = NULL;

	if (ckey->blob)
		free(ckey->blob);
	ckey->blob = NULL;

	free(ckey);
}

char* CAPI_userkey_GetComment(struct CAPI_userkey* ckey) {
	char *retval = NULL;
	
	debuglog("CAPI_userkey_GetComment: called\n");
	if ((retval = malloc(5 + strlen(ckey->certID) + 1)) == NULL) {
		debuglog("CAPI_userkey_GetComment: malloc failed\n");
		return NULL;
	}
	sprintf(retval, "CAPI:%s", ckey->certID);
	return retval;
}




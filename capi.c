/*
 * CAPI: Windows Crypto API support file.
 * Andrew Prout, aprout at ll mit edu
 */

#define UMDF_USING_NTSTATUS
#include <ntstatus.h>

#include <windows.h>
#include <stdlib.h>
#include <Cryptuiapi.h>
#include "capi.h"
#include "ssh.h"

#define SHA1_BYTES 20

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Cryptui.lib")

#ifdef _DEBUG
char* GetDebugFileName() {
	static char DebugPath[MAX_PATH + 1] = "";
	if (strlen(DebugPath) == 0) {
		// attempt to get the directory to the path to this executable
		if (GetModuleFileNameA(NULL, DebugPath, _countof(DebugPath)) == 0) {
			// error-occurred - use default
			strcpy(DebugPath, "putty-capi.log");
		}
		else {
			// generate a log name based on the calling exe and the process id
			sprintf(strrchr(DebugPath, '.'), "-%d-capi.log",
			        GetCurrentProcessId());
		}
	}
	return DebugPath;
}

void AsciiDumpBuffer(FILE* iStream, unsigned char* buf, uint32 size) {
	uint32 x;
	for (x = 0; x < size; x++) {
		if (x && (x % 8) == 0)
			fprintf(iStream, " ");
		if (buf[x] >= 32 && buf[x] <= 126)
			fprintf(iStream, "%hc", buf[x]);
		else
			fprintf(iStream, ".");
	}
}

void HexDumpBuffer(FILE* iStream, unsigned char* buf, uint32 size, char* newlinepad) {
	uint32 x, tmp;
	if (newlinepad)
		fprintf(iStream, "%s", newlinepad);
	for (x = 0; x < size; x++) {
		if (x && (x % 16) == 0) {
			fprintf(iStream, " ");
			AsciiDumpBuffer(iStream, &buf[x - 16], 16);
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
	tmp = 16 - (size % 16);
	if (tmp != 16) {
		for (x = 0; x < tmp; x++) {
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
	FILE* f = fopen(GetDebugFileName(), "a+");
	if (f == NULL)
		return;
	HexDumpBuffer(f, (unsigned char*)buf, size, "");
	fclose(f);
}

void debuglogx(char* file, char* function, int line, int error, char* format, ...) {
	va_list arg_ptr;
	DWORD tmpAllocedSize = 16384;
	DWORD contlen;
	FILE* f;
	char* message;

	va_start(arg_ptr, format);
	message = (char*)malloc(tmpAllocedSize);
	if (!message)
		return;
	_vsnprintf(message, tmpAllocedSize, format, arg_ptr);
	message[tmpAllocedSize - 1] = 0;
	contlen = (DWORD)strlen(message);

	f = fopen(GetDebugFileName(), "a+");
	if (f == NULL)
		return;
	if (error) {
		fprintf(f, "ERROR: %s:%s:%d; %s; GetLastError()=%i (0x%08x)\n",
		        (strrchr(file, '\\') ? strrchr(file, '\\') + 1 : file),
		        function, line, message, GetLastError(), GetLastError());
	}
	else {
		fprintf(f, "INFO: %s:%s:%d; %s\n",
		        (strrchr(file, '\\') ? strrchr(file, '\\') + 1 : file),
		        function, line, message);
	}
	fclose(f);
	free(message);
}

#define debuglog(error,format,...) debuglogx(__FILE__,__FUNCTION__,__LINE__,error,format, __VA_ARGS__)
#else //#ifdef CAPI_DEBUG
#define debuglog_buffer
#define debuglog
#endif //#ifdef CAPI_DEBUG

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

unsigned char GetCodeFromHex(const char iHex) {
	if (iHex >= '0' && iHex <= '9') // numbers
		return iHex - 48;
	if (iHex >= 'A' && iHex <= 'F') // uppercase A-F
		return iHex - 55;
	if (iHex >= 'a' && iHex <= 'f') // lowercase a-f
		return iHex - 87;
	return 255;
}

BOOL hextobytes(const char* iHex, unsigned char* oBytes) {
	unsigned int x = 0;
	unsigned char val;
	while (iHex[x]) {
		val = GetCodeFromHex(iHex[x]);
		if (val >= 16)
			return FALSE;
		if (x % 2)
			oBytes[x / 2] |= val;
		else
			oBytes[x / 2] = (val << 4);
		x++;
#ifdef _DEBUG
		if (x > 10000)
			RaiseException(STATUS_BUFFER_OVERFLOW, EXCEPTION_NONCONTINUABLE, 0, 0);
#endif
	}
	return TRUE;
}

struct ssh2_userkey capi_key_ssh2_userkey = {0, 0, 0};

struct CAPI_PUBKEY_BIT_BLOB_struct {
	PUBLICKEYSTRUC publickeystruct;
	RSAPUBKEY rsapubkey;
};

BOOL capi_get_cert_handle(const char* certid, PCCERT_CONTEXT* oCertContext) {
	BOOL retval = FALSE;
	PCCERT_CONTEXT pCertContext = NULL, pFindCertContext = NULL;
	HCERTSTORE hStore = NULL;
	CRYPT_HASH_BLOB chb = {0, NULL};
	DWORD FoundCount = 0, dwStoreType, tmpSize;
	char *Lcertid = NULL, *Lcertid_StoreType, *Lcertid_StoreName, *Lcertid_fingerprint;

	debuglog(0, "Called.");

	if (certid == NULL || oCertContext == NULL) {
		debuglog(0, "input parameter is NULL that cannot be");
		return FALSE; // no goto cleanup, it'll crash
	}

	if ((Lcertid = malloc(strlen(certid) + 1)) == NULL) {
		debuglog(1, "Error calling malloc for Lcertid.");
		goto cleanup;
	}
	strcpy(Lcertid, certid);

	Lcertid_StoreType = strtok(Lcertid, "\\");
	Lcertid_StoreName = strtok(NULL, "\\");
	Lcertid_fingerprint = strtok(NULL, "\\");
	if (Lcertid_StoreType == NULL || Lcertid_StoreName == NULL || Lcertid_fingerprint == NULL) {
		debuglog(1, "Error calling strtok(Lcertid).");
		goto cleanup;
	}

	if (strcmp(Lcertid_StoreType, "User") == 0)
		dwStoreType = CERT_SYSTEM_STORE_CURRENT_USER;
	else if (strcmp(Lcertid_StoreType, "System") == 0)
		dwStoreType = CERT_SYSTEM_STORE_LOCAL_MACHINE;
	else {
		debuglog(1, "Unknown store type");
		goto cleanup;
	}

	if (strlen(Lcertid_fingerprint) != (SHA1_BYTES * 2)) {
		debuglog(1, "strlen(Lcertid_fingerprint) != (SHA1_BYTES * 2)");
		goto cleanup;
	}

	chb.cbData = SHA1_BYTES;
	if ((chb.pbData = (BYTE*)malloc(SHA1_BYTES)) == NULL) {
		debuglog(1, "Error calling malloc for chb.pbData.");
		goto cleanup;
	}
	if (!hextobytes(Lcertid_fingerprint, chb.pbData)) {
		debuglog(1, "Error calling hextobytes(Lcertid_fingerprint).");
		goto cleanup;
	}

	if ((hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0 /*hCryptProv*/, dwStoreType | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_ENUM_ARCHIVED_FLAG, Lcertid_StoreName)) == NULL) {
		debuglog(1, "CertOpenStore(%d, %s) failed", dwStoreType, Lcertid_StoreName);
		goto cleanup;
	}

	while (pFindCertContext = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &chb, pFindCertContext)) {
		debuglog(0, "Found a cert, checking for private key...");
		tmpSize = 0;
		if (CertGetCertificateContextProperty(pFindCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &tmpSize)) {
			debuglog(0, "Got a private key duplicating context...");
			if (pCertContext == NULL)
				pCertContext = CertDuplicateCertificateContext(pFindCertContext);
			FoundCount++;
			debuglog(0, "All set");
		}
		else {
			// no private key, ignore the cert
		}
	}

	if (FoundCount != 1) {
		debuglog(1, "FoundCount != 1. FoundCount=%d", FoundCount);
		goto cleanup;
	}

	if (strcmp(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_RSA_RSA) != 0) {
		// Not an RSA key? egads, bail out...
		debuglog(1, "Not an RSA key?");
		debuglog(1, "pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId=%s", pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);
		goto cleanup;
	}

	*oCertContext = pCertContext;
	pCertContext = NULL; // to avoid the free in cleanup;

	retval = TRUE;
cleanup:
	if (chb.pbData) {
		free(chb.pbData);
		chb.pbData = NULL;
	}

	if (Lcertid) {
		free(Lcertid);
		Lcertid = NULL;
	}

	if (pCertContext && !CertFreeCertificateContext(pCertContext)) {
		debuglog(1, "Error calling CertFreeCertificateContext.");
	}

	return retval;
}

BOOL capi_display_cert_ui(HWND hwnd, char* certid, WCHAR* title) {
	BOOL retval = FALSE;
	PCCERT_CONTEXT pCertContext = NULL;

	debuglog(0, "Called.");

	if (!capi_get_cert_handle(certid, &pCertContext)) {
		debuglog(1, "Error calling capi_get_cert_handle.");
		goto cleanup;
	}

	if (!CryptUIDlgViewContext(CERT_STORE_CERTIFICATE_CONTEXT, pCertContext, hwnd, title, 0, NULL)) {
		debuglog(1, "Error calling CryptUIDlgViewContext.");
		goto cleanup;
	}

	retval = TRUE;

cleanup:
	if (pCertContext && !CertFreeCertificateContext(pCertContext)) {
		debuglog(1, "Error calling CertFreeCertificateContext.");
	}

	return retval;
}

BOOL capi_get_pubkey_blob(PCCERT_CONTEXT pCertContext, unsigned char** pubkey, int* blob_len) {
	BOOL retval = FALSE;
	DWORD tmpSize, mbits, mbytes, ebytes;
	int i; // signed, for loop goes to -1
	unsigned char* p = NULL;//, *modu = NULL;
	struct CAPI_PUBKEY_BIT_BLOB_struct* capi_pubkey = NULL;
	Bignum modu = NULL;

	debuglog(0, "Called.");

	if (pubkey == NULL || blob_len == NULL) {
		debuglog(1, "Input parameter is NULL that cannot be");
		return FALSE; // no goto cleanup, it'll crash
	}

	if ((mbits = CertGetPublicKeyLength(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &pCertContext->pCertInfo->SubjectPublicKeyInfo)) == 0) {
		debuglog(1, "Error calling CertGetPublicKeyLength.");
		goto cleanup;
	}
	debuglog(0, "mbits=%d" , mbits);

	tmpSize = 0;
	if (!CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData, pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData, 0, NULL, &tmpSize)) {
		debuglog(1, "Error calling CryptDecodeObject.");
		goto cleanup;
	}
	capi_pubkey = malloc(tmpSize);
	if (!CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData, pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData, 0, capi_pubkey, &tmpSize)) {
		debuglog(1, "Error calling CryptDecodeObject.");
		goto cleanup;
	}

	// the below formula for the format is taken from sc.c... I agree with the comments there, it's ugly.

	//	ebytes = (ebits/8) + ((ebits % 8) ? 1 : 0);
	ebytes = CAPI_BYTES_USED_IN_INT32(capi_pubkey->rsapubkey.pubexp);
	mbytes = (mbits / 8) + ((mbits % 8) ? 1 : 0);

	// offset by sizeof(*capi_pubkey) bytes to the public key...
	//modu = ((unsigned char*) capi_pubkey) + sizeof(*capi_pubkey);
	modu = bignum_from_bytes(((unsigned char*)capi_pubkey) + sizeof(*capi_pubkey), mbytes);

	debuglog(0, "tmpSize=%d, capi_pubkey=:" , tmpSize);
	debuglog_buffer(capi_pubkey, tmpSize);

	*blob_len = 4 + 7 + 4 + ebytes + 4 + (1 + mbytes); // mbytes has a leading zero
	if ((p = *pubkey = (unsigned char*)malloc(*blob_len)) == NULL) {
		debuglog(1, "Error calling malloc for *pubkey.");
		goto cleanup;
	}

	CAPI_PUT_32BIT(p, 7);
	p += 4;

	memcpy(p, "ssh-rsa", 7);
	p += 7;

	CAPI_PUT_32BIT(p, ebytes);
	p += 4;

	debuglog(0, "ebytes=%d, capi_pubkey->rsapubkey.pubexp=%d (0x%08x), mbytes=%d, modu=:" , ebytes , capi_pubkey->rsapubkey.pubexp , capi_pubkey->rsapubkey.pubexp , mbytes);
	debuglog_buffer(modu, mbytes);

	for (i = ebytes - 1; i >= 0; i--)
		*p++ = (unsigned char)((capi_pubkey->rsapubkey.pubexp & (0xFF << (i * 8))) >> (i * 8));

	CAPI_PUT_32BIT(p, mbytes + 1); // add room for a leading zero
	p += 4;

	*p++ = 0; // leading zero
	for (i = 0; i < (int)mbytes; i++)
		*p++ = bignum_byte(modu, i);

	retval = TRUE;
cleanup:
	if (modu) {
		freebn(modu);
	}

	if (capi_pubkey) {
		free(capi_pubkey);
		capi_pubkey = NULL;
	}

	if (!retval) {
		if (pubkey && *pubkey) {
			free(*pubkey);
			*pubkey = NULL;
		}
		if (blob_len) {
			*blob_len = 0;
		}
	}

	return retval;
}

BOOL capi_get_pubkey_int(char* certid, unsigned char** pubkey, char** algorithm, int* blob_len, PCCERT_CONTEXT* oCertContext) {
	BOOL retval = FALSE;
	PCCERT_CONTEXT pCertContext = NULL;

	debuglog(0, "Called.");

	if (certid == NULL || pubkey == NULL || algorithm == NULL || blob_len == NULL) {
		debuglog(1, "Input parameter is NULL that cannot be");
		return FALSE; // no goto cleanup, it'll crash
	}
	*pubkey = NULL;
	*algorithm = NULL;
	*blob_len = 0;
	// goto cleanup now OK

	if ((*algorithm = calloc(sizeof(char *), strlen("ssh-rsa") + 1)) == NULL) {
		debuglog(1, "Error calling calloc for *algorithm.");
		goto cleanup;
	}
	strcpy(*algorithm, "ssh-rsa");

	if (!capi_get_cert_handle(certid, &pCertContext)) {
		debuglog(1, "Error calling capi_get_cert_handle.");
		goto cleanup;
	}

	if (!capi_get_pubkey_blob(pCertContext, pubkey, blob_len)) {
		debuglog(1, "Error calling capi_get_pubkey_blob.");
		goto cleanup;
	}

	if (oCertContext) {
		*oCertContext = pCertContext;
		pCertContext = NULL; // to avoid the free in cleanup;
	}
	retval = TRUE;
cleanup:
	if (!retval) {
		if (pubkey && *pubkey) {
			free(*pubkey);
			*pubkey = NULL;
		}
		if (algorithm && *algorithm) {
			free(*algorithm);
			*algorithm = NULL;
		}
		if (blob_len) {
			*blob_len = 0;
		}
	}

	return retval;
}

BOOL capi_get_pubkey(char* certid, unsigned char** pubkey, char** algorithm, int* blob_len) {
	debuglog(0, "Called.");

	return capi_get_pubkey_int(certid, pubkey, algorithm, blob_len, NULL);
}

char* capi_base64key(char* data, int len) {
	DWORD iBufferSize = (int)((4.0 * (len / 3.0)) + 1 + 1);
	char* buffer = calloc(iBufferSize, 1);
	CryptBinaryToStringA(data, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, buffer, &iBufferSize);
	return buffer;
}

char* capi_get_key_string(char* certid) {
	unsigned char *pubkey, *algorithm;
	int pubkey_len;
	char *key64 = NULL, *keystring = NULL;

	debuglog(0, "Called.");

	if (!capi_get_pubkey(certid, &pubkey, &algorithm, &pubkey_len)) {
		debuglog(1, "Error calling capi_get_pubkey.");
		goto cleanup;
	}
	debuglog(0, "capi_get_key_string: Got pubkey. algorithm=%s. pubkey_len=%d. pubkey=:" , algorithm , pubkey_len);
	debuglog_buffer(pubkey, pubkey_len);
	if ((key64 = capi_base64key(pubkey, pubkey_len)) == NULL) {
		debuglog(1, "Error calling capi_get_pubkey.");
		goto cleanup;
	}
	if ((keystring = calloc(1, strlen("ssh-rsa") + 1 + strlen(key64) + 1 + strlen("CAPI:") + strlen(certid) + 1)) == NULL) {
		debuglog(1, "Error calling capi_get_pubkey.");
		goto cleanup;
	}
	sprintf(keystring, "ssh-rsa %s CAPI:%s", key64, certid);
cleanup:
	return keystring;
}

BOOL capi_get_key_handle(char* certid, struct capi_keyhandle_struct** keyhandle) {
	BOOL retval = FALSE;
	struct capi_keyhandle_struct* newkeyhandle = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	DWORD ckpi_size;
	CRYPT_KEY_PROV_INFO* ckpi = NULL;

	debuglog(0, "Called.");

	if (certid == NULL || keyhandle == NULL) {
		debuglog(1, "Input parameter is NULL that cannot be");
		return FALSE; // no goto cleanup, it'll crash
	}
	*keyhandle = NULL;
	// goto cleanup now OK

	if ((newkeyhandle = calloc(1, sizeof(struct capi_keyhandle_struct))) == NULL) {
		debuglog(1, "Error calling newkeyhandle.");
		goto cleanup;
	}

	if (!capi_get_pubkey_int(certid, &newkeyhandle->pubkey, &newkeyhandle->algorithm, &newkeyhandle->pubkey_len, &pCertContext)) {
		debuglog(1, "Error calling capi_get_pubkey_int.");
		goto cleanup;
	}

	ckpi_size = 0;
	if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &ckpi_size)) {
		debuglog(1, "Error calling CertGetCertificateContextProperty.");
		goto cleanup;
	}

	if ((ckpi = (CRYPT_KEY_PROV_INFO*)malloc(ckpi_size)) == NULL) {
		debuglog(1, "Error calling malloc (size=%d).", ckpi_size);
		goto cleanup;
	}

	if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, ckpi, &ckpi_size)) {
		debuglog(1, "Error calling CertGetCertificateContextProperty.");
		goto cleanup;
	}

	if (ckpi->dwProvType == 0) {
		debuglog(1, "Unexpected key provider type.");
		goto cleanup;
	}

	if (!CryptAcquireContextW((HCRYPTPROV*)&newkeyhandle->win_provider, ckpi->pwszContainerName, ckpi->pwszProvName, ckpi->dwProvType, ((ckpi->dwFlags & CRYPT_MACHINE_KEYSET) ? CRYPT_MACHINE_KEYSET : 0))) {
		debuglog(1, "Error calling CryptAcquireContext.");
		goto cleanup;
	}

	newkeyhandle->win_keyspec = ckpi->dwKeySpec;
	*keyhandle = newkeyhandle;
	retval = TRUE;

cleanup:

	if (pCertContext && !CertFreeCertificateContext(pCertContext)) {
		debuglog(1, "Error calling CertFreeCertificateContext.");
		pCertContext = NULL;
	}

	if (ckpi) {
		free(ckpi);
		ckpi = NULL;
	}

	if (!retval && newkeyhandle) {
		if ((newkeyhandle->win_provider) && !CryptReleaseContext((HCRYPTPROV)newkeyhandle->win_provider, 0)) {
			debuglog(1, "Error calling CryptAcquireContext.");
			newkeyhandle->win_provider = NULL;
		}

		if (newkeyhandle->pubkey) {
			free(newkeyhandle->pubkey);
			newkeyhandle->pubkey = NULL;
		}

		if (newkeyhandle->algorithm) {
			free(newkeyhandle->algorithm);
			newkeyhandle->algorithm = NULL;
		}

		free(newkeyhandle);
		newkeyhandle = NULL;
	}

	return retval;
}

unsigned char* capi_sig_certid(char* certid, const char* sigdata, int sigdata_len, int* sigblob_len) {
	// early declarations to support cleanup code
	PCERT_CONTEXT pCertContext = NULL;
	CRYPT_KEY_PROV_INFO* ckpi = NULL;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hash = 0;
	BOOL success = FALSE;
	unsigned char* retval = NULL;

	debuglog(0, "Called.");

	// Find cert context from certid
	if (!capi_get_cert_handle(certid, &pCertContext)) {
		debuglog(1, "Error calling capi_get_cert_handle.");
		goto cleanup;
	}

	// find the key info from the cert and get a handle
	DWORD ckpi_size = 0;
	if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &ckpi_size)) {
		debuglog(1, "Error calling CertGetCertificateContextProperty.");
		goto cleanup;
	}

	if ((ckpi = (CRYPT_KEY_PROV_INFO*) malloc(ckpi_size)) == NULL) {
		debuglog(1, "Failed to allocate memory (size=%d).", ckpi_size);
		goto cleanup;
	}

	if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, ckpi, &ckpi_size)) {
		debuglog(1, "Error calling CryptAcquireContext.");
		goto cleanup;
	}

	if (ckpi->dwProvType == 0) {
		debuglog(1, "Unexpected key provider type.");
		goto cleanup;
	}

	if (!CryptAcquireContextW(&hProv, ckpi->pwszContainerName, ckpi->pwszProvName, ckpi->dwProvType, ((ckpi->dwFlags & CRYPT_MACHINE_KEYSET) ? CRYPT_MACHINE_KEYSET : 0))) {
		debuglog(1, "Error calling CryptAcquireContextW.");
		goto cleanup;
	}

	retval = capi_sig(hProv, ckpi->dwKeySpec, sigdata, sigdata_len, sigblob_len);
	if (retval == NULL) {
		debuglog(1, "Error calling capi_sig.");
		goto cleanup;
	}

	success = TRUE;

cleanup:

	if (hash && !CryptDestroyHash(hash)) {
		debuglog(1, "Error calling CryptDestroyHash.");
	}

	if (hProv && !CryptReleaseContext(hProv, 0)) {
		debuglog(1, "Error calling CryptReleaseContext.");
	}

	if (pCertContext && !CertFreeCertificateContext(pCertContext)) {
		debuglog(1, "Error calling CertFreeCertificateContext.");
	}

	if (ckpi) {
		free(ckpi);
	}

	return retval;
}

unsigned char* capi_sig(HCRYPTPROV hProv, DWORD keyspec, const char* sigdata, int sigdata_len, int* sigblob_len) {
	HCRYPTHASH hash = 0;
	BYTE* rawsig = NULL;
	Bignum bn = NULL;
	BOOL success = FALSE;
	unsigned char* retval = NULL;

	debuglog(0, "called. sigdata_len=%d", sigdata_len);
	debuglog_buffer(sigdata, sigdata_len);

	// create the hash object, set it to SHA-1 and confirm expectations
	if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hash)) {
		debuglog(1, "Error calling CryptCreateHash.");
		goto cleanup;
	}

	DWORD tmpHashLen = 0;
	DWORD tmpSize = sizeof(tmpHashLen);
	if (!CryptGetHashParam(hash, HP_HASHSIZE, (BYTE *)&tmpHashLen, &tmpSize, 0)) {
		debuglog(1, "Error calling CryptCreateHash.");
		goto cleanup;
	}
	if (tmpHashLen != SHA1_BYTES) {
		debuglog(1, "Improper hash length %i.", tmpHashLen);
		goto cleanup;
	}

	if (!CryptHashData(hash, sigdata, sigdata_len, 0)) {
		debuglog(1, "Error calling CryptCreateHash.");
		goto cleanup;
	}

	// hash & sign
	DWORD rawsig_len = 0;
	if (!CryptSignHash(hash, keyspec, NULL, 0, NULL, &rawsig_len)) {
		debuglog(1, "Error calling CryptSignHash.");
		goto cleanup;
	}

	rawsig = malloc(rawsig_len);
	if (!CryptSignHash(hash, keyspec, NULL, 0, rawsig, &rawsig_len)) {
		debuglog(1, "Error calling CryptSignHash.");
		goto cleanup;
	}

	// convert to SSH-style buffer
	bn = bignum_from_bytes(rawsig, rawsig_len);
	tmpSize = (bignum_bitcount(bn) + 7) / 8;
	*sigblob_len = 4 + 7 + 4 + tmpSize;
	retval = calloc(1, *sigblob_len);

	unsigned char* p = retval;
	CAPI_PUT_32BIT(p, 7);
	p += 4;

	memcpy(p, "ssh-rsa", 7);
	p += 7;

	CAPI_PUT_32BIT(p, tmpSize);
	p += 4;

	for (DWORD x = 0; x < tmpSize; x++) {
		*p++ = bignum_byte(bn, x);
	}

	success = TRUE;

cleanup:

	if (hash && !CryptDestroyHash(hash)) {
		debuglog(1, "Error calling CryptDestroyHash.");
	}

	if (rawsig) {
		free(rawsig);
	}

	if (bn) {
		freebn(bn);
	}

	if (!success && retval) {
		free(retval);
		retval = NULL;
	}
	return retval;
}

void capi_release_key(struct capi_keyhandle_struct** keyhandle) {
	debuglog(0, "Called.");

	if (keyhandle && *keyhandle) {
		if ((*keyhandle)->win_provider && !CryptReleaseContext((HCRYPTPROV)(*keyhandle)->win_provider, 0)) {
			debuglog(1, "Error calling CryptReleaseContext.");
			(*keyhandle)->win_provider = NULL;
		}

		if ((*keyhandle)->pubkey) {
			free((*keyhandle)->pubkey);
			(*keyhandle)->pubkey = NULL;
		}

		if ((*keyhandle)->algorithm) {
			free((*keyhandle)->algorithm);
			(*keyhandle)->algorithm = NULL;
		}

		free(*keyhandle);
		*keyhandle = NULL;
	}
}

struct capi_userkey* create_capi_userkey(const char* certid, PCERT_CONTEXT pCertContext) {
	BOOL success = FALSE;
	struct capi_userkey* retval = NULL;
	PCERT_CONTEXT LpCertContext = NULL;

	debuglog(0, "Called.");

	if (pCertContext == NULL) {
		if (!capi_get_cert_handle(certid, &LpCertContext)) {
			debuglog(1, "Error calling capi_get_cert_handle.");
			goto cleanup;
		}
		pCertContext = LpCertContext;
	}

	if ((retval = malloc(sizeof(struct capi_userkey))) == NULL) {
		debuglog(1, "Error calling malloc for retval.");
		goto cleanup;
	}
	retval->certid = NULL;
	retval->blob = NULL;

	if ((retval->certid = malloc(strlen(certid) + 1)) == NULL) {
		debuglog(1, "Error calling malloc for certid.");
		goto cleanup;
	}
	strcpy(retval->certid, certid);

	if (!capi_get_pubkey_blob(pCertContext, &retval->blob, &retval->bloblen)) {
		debuglog(1, "Error calling capi_get_pubkey_blob.");
		goto cleanup;
	}

	success = TRUE;
cleanup:
	if (LpCertContext && !CertFreeCertificateContext(LpCertContext)) {
		debuglog(1, "Error calling CertFreeCertificateContext.");
		LpCertContext = NULL;
	}

	if (!success && retval) {
		free_capi_userkey(retval);
		retval = NULL;
	}
	return retval;
}

void free_capi_userkey(struct capi_userkey* ckey) {
	debuglog(0, "Called.");

	if (ckey->certid)
		free(ckey->certid);
	ckey->certid = NULL;

	if (ckey->blob)
		free(ckey->blob);
	ckey->blob = NULL;

	free(ckey);
}

char* capi_userkey_getcomment(struct capi_userkey* ckey) {
	char* retval = NULL;

	debuglog(0, "Called.");

	if ((retval = malloc(5 + strlen(ckey->certid) + 1)) == NULL) {
		debuglog(1, "Error calling malloc.");
		return NULL;
	}
	sprintf(retval, "CAPI:%s", ckey->certid);
	return retval;
}

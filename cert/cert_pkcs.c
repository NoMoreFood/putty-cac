#ifdef PUTTY_CAC

#include <windows.h>
#include <stdio.h>
#include <malloc.h>
#include <cryptuiapi.h>
#include <cryptdlg.h>
#include <wincred.h>

#pragma comment(lib,"crypt32.lib")
#pragma comment(lib,"credui.lib")

#include "cert_common.h"

#define DEFINE_VARIABLES
#include "cert_pkcs.h"
#undef DEFINE_VARIABLES

#ifndef SSH_AGENT_SUCCESS
#include "ssh.h"
#endif

// required to be defined by pkcs headers
#define CK_PTR *
#define NULL_PTR 0

// required to be defined by pkcs headers
#define CK_DECLARE_FUNCTION(returnType, name) \
	returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
	returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
    returnType (* name)

// required to be defined by pkcs headers
#pragma pack(push, cryptoki, 1)
#include "pkcs\pkcs11.h"
#pragma pack(pop, cryptoki)

// id-sha1 OBJECT IDENTIFIER 
static const BYTE OID_SHA1[] = {
	0x30, 0x21, /* type Sequence, length 0x21 (33) */
	0x30, 0x09, /* type Sequence, length 0x09 */
	0x06, 0x05, /* type OID, length 0x05 */
	0x2b, 0x0e, 0x03, 0x02, 0x1a, /* id-sha1 OID */
	0x05, 0x00, /* NULL */
	0x04, 0x14  /* Octet string, length 0x14 (20), followed by sha1 hash */
};

typedef struct PROGRAM_ITEM
{
	struct PROGRAM_ITEM * NextItem;
	HMODULE Library;
	CK_FUNCTION_LIST_PTR FunctionList;
} PROGRAM_ITEM;

// functions used within the capi module
PCCERT_CONTEXT pkcs_get_cert_from_token(CK_FUNCTION_LIST_PTR FunctionList, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
PROGRAM_ITEM * cert_pkcs_load_library(LPSTR szLibrary);
void * pkcs_get_attribute_value(CK_FUNCTION_LIST_PTR FunctionList, CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_TYPE iAttribute, CK_ULONG_PTR iValueSize);
void pkcs_lookup_token_cert(LPCSTR szCert, CK_SESSION_HANDLE_PTR phSession, CK_OBJECT_HANDLE_PTR phObject,
	CK_ATTRIBUTE aFindCriteria[], CK_ULONG iFindCriteria, BOOL bReturnFirst);

BYTE *  cert_pkcs_sign(struct ssh2_userkey * userkey, const char* data, int datalen, int * siglen, HWND hwnd)
{
	// get the library to load from based on comment
	LPSTR szLibrary = strrchr(userkey->comment, '=') + 1;
	PROGRAM_ITEM * hItem = cert_pkcs_load_library(szLibrary);
	if (hItem == NULL) return NULL;

	// convert the modulus back to the form that will be stored in the token
	struct RSAKey * rsa = userkey->data;
	byte * tBigData = malloc(rsa->bytes);
	for (int i = 0; i < rsa->bytes; i++)
	{
		tBigData[rsa->bytes - i - 1] = bignum_byte(rsa->modulus, i);
	}

	// setup the find structure to identiy the public key on the token
	static CK_OBJECT_CLASS iPublicType = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE aFindPubCriteria[] = {
		{ CKA_CLASS,    &iPublicType,  sizeof(CK_OBJECT_CLASS) },
		{ CKA_MODULUS,  tBigData,      rsa->bytes },
	};

	// get a handle to the session of the token and the public key object
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hPublicKey;
	pkcs_lookup_token_cert(rsa->comment, &hSession, &hPublicKey, aFindPubCriteria,
		_countof(aFindPubCriteria), TRUE);

	// cleanup the modulus since we no longer need it
	free(tBigData);

	// check for error
	if (hSession == 0 || hPublicKey == 0)
	{
		// error
		return NULL;
	}

	// fetch the id of the public key so we can find 
	// the corresponding private key id
	CK_ULONG iSize = 0;
	char * id = pkcs_get_attribute_value(hItem->FunctionList,
		hSession, hPublicKey, CKA_ID, &iSize);

	// check for error
	if (id == NULL)
	{
		// error
		return NULL;
	}

	// setup the find structure to identiy the private key on the token
	static CK_OBJECT_HANDLE iPrivateType = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE aFindPrivateCriteria[] = {
		{ CKA_CLASS,    &iPrivateType,	sizeof(CK_OBJECT_CLASS) },
		{ CKA_ID,		id,				iSize },
	};

	// attempt to lookup the private key without logging in
	CK_OBJECT_HANDLE hPrivateKey;
	CK_ULONG iCertListSize = 0;
	if ((hItem->FunctionList->C_FindObjectsInit(hSession, aFindPrivateCriteria, _countof(aFindPrivateCriteria))) != CKR_OK ||
		hItem->FunctionList->C_FindObjects(hSession, &hPrivateKey, 1, &iCertListSize) != CKR_OK ||
		hItem->FunctionList->C_FindObjectsFinal(hSession) != CKR_OK)
	{
		// error
		free(id);
		return FALSE;
	}

	// if could not find the key, prompt the user for the pin
	if (iCertListSize == 0)
	{
		// prompt the user to enter the pin
		CREDUI_INFO tCredInfo;
		ZeroMemory(&tCredInfo, sizeof(CREDUI_INFO));
		tCredInfo.hwndParent = hwnd;
		tCredInfo.cbSize = sizeof(tCredInfo);
		tCredInfo.pszCaptionText = "PuTTY Authentication";
		tCredInfo.pszMessageText = "Please Enter Your Smart Card Credentials";
		char szUserName[CREDUI_MAX_USERNAME_LENGTH + 1] = "<Using Smart Card>";
		char szPassword[CREDUI_MAX_PASSWORD_LENGTH + 1] = "";
		if (CredUIPromptForCredentials(&tCredInfo, "Smart Card", NULL, 0, szUserName, _countof(szUserName),
			szPassword, _countof(szPassword), NULL, CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_KEEP_USERNAME) != ERROR_SUCCESS)
		{
			// error
			free(id);
			SecureZeroMemory(szPassword, sizeof(szPassword));
			return NULL;
		}

		// login to the card to unlock the private key
		if (hItem->FunctionList->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)szPassword, strlen(szPassword)) != CKR_OK)
		{
			// error
			free(id);
			SecureZeroMemory(szPassword, sizeof(szPassword));
			return NULL;
		}

		// cleanup creds
		SecureZeroMemory(szPassword, sizeof(szPassword));

		// attempt to lookup the private key
		iCertListSize = 0;
		if ((hItem->FunctionList->C_FindObjectsInit(hSession, aFindPrivateCriteria, _countof(aFindPrivateCriteria))) != CKR_OK ||
			hItem->FunctionList->C_FindObjects(hSession, &hPrivateKey, 1, &iCertListSize) != CKR_OK ||
			hItem->FunctionList->C_FindObjectsFinal(hSession) != CKR_OK)
		{
			// error
			free(id);
			return FALSE;
		}

		// check for error
		if (iCertListSize == 0)
		{
			// error
			free(id);
			return NULL;
		}
	}

	// the message to send contains the static sha1 oid header
	// followed by a sha1 hash of the data sent from the host
	BYTE pMessageToSign[sizeof(OID_SHA1) + SHA1_BINARY_SIZE];
	memcpy(pMessageToSign, OID_SHA1, sizeof(OID_SHA1));
	SHA_Simple(data, datalen, &pMessageToSign[sizeof(OID_SHA1)]);

	// setup the signature process to sign using the rsa private key on the card 
	CK_MECHANISM sign_mechanism;
	sign_mechanism.mechanism = CKM_RSA_PKCS;
	sign_mechanism.pParameter = NULL;
	sign_mechanism.ulParameterLen = 0;

	// sign the data
	CK_ULONG iSignatureLen = rsa->bytes;
	void * aSignature = malloc(rsa->bytes);
	if (hItem->FunctionList->C_SignInit(hSession, &sign_mechanism, hPrivateKey) != CKR_OK ||
		hItem->FunctionList->C_Sign(hSession, pMessageToSign, sizeof(pMessageToSign), aSignature, &iSignatureLen) != CKR_OK)
	{
		// error
		free(id);
		return NULL;
	}

	// return the signature to the caller
	free(id);
	*siglen = iSignatureLen;
	return aSignature;
}

void cert_pkcs_load_cert(LPCSTR szCert, PCCERT_CONTEXT* ppCertCtx, HCERTSTORE* phStore)
{
	// split on the hint symbol to get the library path
	LPSTR szThumb = strdup(szCert);
	LPSTR szLibrary = strrchr(szThumb, '=');
	*szLibrary++ = '\0';

	PROGRAM_ITEM * hItem = cert_pkcs_load_library(szLibrary);
	if (hItem == NULL) return;

	static CK_BBOOL bFalse = 0;
	static CK_BBOOL bTrue = 1;
	static CK_OBJECT_CLASS iObjectType = CKO_CERTIFICATE;
	CK_ATTRIBUTE aFindCriteria[] = {
		{ CKA_CLASS,    &iObjectType, sizeof(CK_OBJECT_CLASS) },
		{ CKA_TOKEN,    &bTrue,       sizeof(CK_BBOOL) },
		{ CKA_PRIVATE,  &bFalse,      sizeof(CK_BBOOL) }
	};

	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hObject;
	pkcs_lookup_token_cert(szCert, &hSession, &hObject,
		aFindCriteria, _countof(aFindCriteria), FALSE);

	// lookup the cert in the token
	*phStore = NULL;
	*ppCertCtx = pkcs_get_cert_from_token(hItem->FunctionList, hSession, hObject);

	// cleanup
	free(szThumb);
}

PROGRAM_ITEM * cert_pkcs_load_library(LPSTR szLibrary)
{
	static PROGRAM_ITEM * LibraryList = NULL;
	HMODULE hModule = LoadLibrary(szLibrary);

	// validate library was loaded
	if (hModule == NULL)
	{
		LPCSTR szMessage = "PuTTY could not load the selected PKCS library. " \
			"Either the file is corrupted or not appropriate for this version " \
			"of PuTTY. Remember 32-bit PuTTY can only load 32-bit PKCS libraries and " \
			"64-bit PuTTY can only load 64-bit PKCS libraries.";
			MessageBox(NULL, szMessage, "PuTTY Could Not Load Library", MB_OK | MB_ICONERROR);
		return NULL;
	}

	// see if module was already loaded
	for (PROGRAM_ITEM * hCurItem = LibraryList; hCurItem != NULL; hCurItem = hCurItem->NextItem)
	{
		if (hCurItem->Library == hModule)
		{
			return hCurItem;
		}
	}

	// if not already loaded, add it to the list
	PROGRAM_ITEM * hItem = (PROGRAM_ITEM *)calloc(1, sizeof(struct PROGRAM_ITEM));
	hItem->Library = hModule;
	hItem->NextItem = LibraryList;

	// load the master function list for the librar
	hItem->FunctionList;
	CK_C_GetFunctionList C_GetFunctionList =
		(CK_C_GetFunctionList)GetProcAddress(hModule, "C_GetFunctionList");
	if (hItem == NULL || C_GetFunctionList == NULL ||
		C_GetFunctionList(&(hItem->FunctionList)) != CKR_OK)
	{
		// does not look like a valid PKCS library
		LPCSTR szMessage = "PuTTY was able to read the selected library file " \
			"but it does not appear to be a PKCS library.  It does not contain " \
			"the functions necessary to interface with PKCS.";
		MessageBox(NULL, szMessage, "PuTTY PKCS Library Problem", MB_OK | MB_ICONERROR);

		// error - cleanup and return
		FreeLibrary(hModule);
		free(hItem);
		return NULL;
	}

	// run the library initialization
	CK_LONG iLong = hItem->FunctionList->C_Initialize(NULL_PTR);
	if (iLong != CKR_OK &&
		iLong != CKR_CRYPTOKI_ALREADY_INITIALIZED)
	{
		// error - cleanup and return
		FreeLibrary(hModule);
		free(hItem);
		return NULL;
	}

	// return the library info
	LibraryList = hItem;
	return hItem;
}

HCERTSTORE cert_pkcs_get_cert_store(LPCSTR * szHint, HWND hWnd)
{
	char szFile[MAX_PATH + 1] = "\0";
	OPENFILENAME tFileNameInfo;
	ZeroMemory(&tFileNameInfo, sizeof(OPENFILENAME));
	tFileNameInfo.lStructSize = sizeof(OPENFILENAME);
	tFileNameInfo.hwndOwner = hWnd;
	tFileNameInfo.lpstrFilter = "PKCS #11 Library Files (*.dll)\0*.dll\0\0";
	tFileNameInfo.lpstrTitle = "Please Select PKCS #11 Library File";
	tFileNameInfo.Flags = OFN_DONTADDTORECENT | OFN_FORCESHOWHIDDEN | OFN_FILEMUSTEXIST;
	tFileNameInfo.lpstrFile = (LPSTR)&szFile;
	tFileNameInfo.nMaxFile = _countof(szFile);
	tFileNameInfo.nFilterIndex = 1;
	if (GetOpenFileName(&tFileNameInfo) == 0) return NULL;

	PROGRAM_ITEM * hItem = cert_pkcs_load_library(tFileNameInfo.lpstrFile);
	if (hItem == NULL) return NULL;

	// create a memory store for this certificate
	HCERTSTORE hMemoryStore = CertOpenStore(CERT_STORE_PROV_MEMORY,
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		0, CERT_STORE_CREATE_NEW_FLAG, NULL);

	// get slots -- assume a safe maximum
	CK_SLOT_ID pSlotList[32];
	CK_ULONG iSlotCount = _countof(pSlotList);
	if (hItem->FunctionList->C_GetSlotList(FALSE, pSlotList, &iSlotCount) != CKR_OK)
	{
		return NULL;
	}

	// enumerate all slot counts
	for (CK_ULONG iSlot = 0; iSlot < iSlotCount; iSlot++)
	{
		struct CK_TOKEN_INFO tTokenInfo;
		if (hItem->FunctionList->C_GetTokenInfo(pSlotList[iSlot], &tTokenInfo) != CKR_OK)
		{
			continue;
		}

		CK_SESSION_HANDLE hSession;
		if (hItem->FunctionList->C_OpenSession(pSlotList[iSlot],
			CKF_SERIAL_SESSION | CKR_SESSION_READ_ONLY, NULL_PTR, NULL_PTR, &hSession) != CKR_OK)
		{
			continue;
		}

		static CK_BBOOL bFalse = 0;
		static CK_BBOOL bTrue = 1;
		static CK_OBJECT_CLASS iObjectType = CKO_CERTIFICATE;
		CK_ATTRIBUTE aFindCriteria[] = {
			{ CKA_CLASS,    &iObjectType, sizeof(CK_OBJECT_CLASS) },
			{ CKA_TOKEN,    &bTrue,       sizeof(CK_BBOOL) },
			{ CKA_PRIVATE,  &bFalse,      sizeof(CK_BBOOL) }
		};

		// enumerate all eligible certs in store
		CK_OBJECT_HANDLE aCertList[32];
		CK_ULONG iCertListSize = 0;
		if (hItem->FunctionList->C_FindObjectsInit(hSession, aFindCriteria, _countof(aFindCriteria)) != CKR_OK ||
			hItem->FunctionList->C_FindObjects(hSession, aCertList, _countof(aCertList), &iCertListSize) != CKR_OK ||
			hItem->FunctionList->C_FindObjectsFinal(hSession) != CKR_OK)
		{
			// error
			hItem->FunctionList->C_CloseSession(hSession);
			continue;
		}

		// enumerate the discovered certificates
		for (CK_ULONG iCert = 0; iCert < iCertListSize; iCert++)
		{
			PCCERT_CONTEXT pCertContext =
				pkcs_get_cert_from_token(hItem->FunctionList, hSession, aCertList[iCert]);

			// attributes to query from the certificate
			if (pCertContext == NULL)
			{
				// error
				continue;
			}

			// add this certificate to our store
			CertAddCertificateContextToStore(hMemoryStore, pCertContext, CERT_STORE_ADD_ALWAYS, NULL);
			CertFreeCertificateContext(pCertContext);
		}

		// cleanup 
		hItem->FunctionList->C_CloseSession(hSession);
	}

	if (szHint != NULL) *szHint = strdup(szFile);
	return hMemoryStore;
}

void * pkcs_get_attribute_value(CK_FUNCTION_LIST_PTR FunctionList, CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_TYPE iAttribute, CK_ULONG_PTR iValueSize)
{
	// attributes to query from the certificate
	CK_ATTRIBUTE aAttribute = { iAttribute, NULL_PTR, 0 };

	// query to see the sizes of the requested attributes
	if (FunctionList->C_GetAttributeValue(hSession, hObject, &aAttribute, 1) != CKR_OK)
	{
		// error
		return NULL;
	}

	// allocate memory for the requested attributes
	aAttribute.pValue = malloc(aAttribute.ulValueLen);

	// query to see the sizes of the requested attributes
	if (FunctionList->C_GetAttributeValue(hSession, hObject, &aAttribute, 1) != CKR_OK)
	{
		// free memory for the requested attributes
		free(aAttribute.pValue);

		// error
		return NULL;
	}

	// set retuned size if requested
	if (iValueSize != NULL)
	{
		*iValueSize = aAttribute.ulValueLen;
	}

	return aAttribute.pValue;
}

PCCERT_CONTEXT pkcs_get_cert_from_token(CK_FUNCTION_LIST_PTR FunctionList, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	// query value from string
	CK_ULONG iValue = 0;
	void * pValue = pkcs_get_attribute_value(FunctionList, hSession, hObject, CKA_VALUE, &iValue);

	// query to see the sizes of the requested attributes
	if (pValue == NULL)
	{
		// error
		return NULL;
	}

	// create a certificate context from this token
	PCCERT_CONTEXT pCertObject = CertCreateCertificateContext(
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pValue, iValue);

	// cleanup and return
	free(pValue);
	return pCertObject;
}

void pkcs_lookup_token_cert(LPCSTR szCert, CK_SESSION_HANDLE_PTR phSession, CK_OBJECT_HANDLE_PTR phObject,
	CK_ATTRIBUTE aFindCriteria[], CK_ULONG iFindCriteria, BOOL bReturnFirst)
{
	LPSTR szLibrary = strrchr(szCert, '=') + 1;
	PROGRAM_ITEM * hItem = cert_pkcs_load_library(szLibrary);
	if (hItem == NULL) return;

	// set default return values
	*phSession = 0;
	*phObject = 0;

	// convert the string sha1 hash into binary form
	BYTE pbThumb[SHA1_BINARY_SIZE];
	if (szCert != NULL)
	{
		CRYPT_HASH_BLOB cryptHashBlob;
		cryptHashBlob.cbData = SHA1_BINARY_SIZE;
		cryptHashBlob.pbData = pbThumb;
		CryptStringToBinary(&szCert[IDEN_PKCS_SIZE], SHA1_HEX_SIZE, CRYPT_STRING_HEXRAW,
			cryptHashBlob.pbData, &cryptHashBlob.cbData, NULL, NULL);
	}

	// enumerate all loaded libraries
	for (PROGRAM_ITEM * hCurItem = hItem; hCurItem != NULL; hCurItem = hCurItem->NextItem)
	{
		// get slots -- assume a safe maximum
		CK_SLOT_ID pSlotList[32];
		CK_ULONG iSlotCount = _countof(pSlotList);
		if (hItem->FunctionList->C_GetSlotList(FALSE, pSlotList, &iSlotCount) != CKR_OK)
		{
			return;
		}

		// enumerate all slot counts
		for (CK_ULONG iSlot = 0; iSlot < iSlotCount; iSlot++)
		{
			struct CK_TOKEN_INFO tTokenInfo;
			if (hItem->FunctionList->C_GetTokenInfo(pSlotList[iSlot], &tTokenInfo) != CKR_OK)
			{
				continue;
			}

			CK_SESSION_HANDLE hSession;
			if (hItem->FunctionList->C_OpenSession(pSlotList[iSlot],
				CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) != CKR_OK)
			{
				continue;
			}

			// enumerate all eligible certs in store
			CK_OBJECT_HANDLE aCertList[32];
			CK_ULONG iCertListSize = 0;
			int i = 0;
			if ((i = hItem->FunctionList->C_FindObjectsInit(hSession, aFindCriteria, iFindCriteria)) != CKR_OK ||
				hItem->FunctionList->C_FindObjects(hSession, aCertList, _countof(aCertList), &iCertListSize) != CKR_OK ||
				hItem->FunctionList->C_FindObjectsFinal(hSession) != CKR_OK)
			{
				// error
				hItem->FunctionList->C_CloseSession(hSession);
				continue;
			}

			// no specific cert was requested so just return the first found cert
			if (bReturnFirst && iCertListSize > 0)
			{
				*phSession = hSession;
				*phObject = *aCertList;
				return;
			}

			// enumerate the discovered certificates
			for (CK_ULONG iCert = 0; iCert < iCertListSize; iCert++)
			{
				// decode windows cert object from 
				PCCERT_CONTEXT pCertContext =
					pkcs_get_cert_from_token(hItem->FunctionList, hSession, aCertList[iCert]);

				// attributes to query from the certificate
				if (pCertContext == NULL)
				{
					// error
					continue;
				}

				// get the sha1 hash and see if it matches
				BYTE pbThumbBinary[SHA1_BINARY_SIZE];
				DWORD cbThumbBinary = SHA1_BINARY_SIZE;
				BOOL bCertFound = FALSE;
				if (CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID, pbThumbBinary, &cbThumbBinary) == TRUE &&
					memcmp(pbThumb, pbThumbBinary, cbThumbBinary) == 0)
				{
					bCertFound = TRUE;
				}

				// free up our temporary blob
				CertFreeCertificateContext(pCertContext);

				// if found, return session and handle
				if (bCertFound)
				{
					*phSession = hSession;
					*phObject = aCertList[iCert];
					return;
				}
			}

			// cleanup
			hItem->FunctionList->C_CloseSession(pSlotList[iSlot]);
		}
	}
}

#endif // PUTTY_CAC
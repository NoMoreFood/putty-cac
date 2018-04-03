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

// functions used within the capi module
PCCERT_CONTEXT pkcs_get_cert_from_token(CK_FUNCTION_LIST_PTR FunctionList, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
CK_FUNCTION_LIST_PTR cert_pkcs_load_library(LPCSTR szLibrary);
void * pkcs_get_attribute_value(CK_FUNCTION_LIST_PTR FunctionList, CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_TYPE iAttribute, CK_ULONG_PTR iValueSize);
void pkcs_lookup_token_cert(LPCSTR szCert, CK_SESSION_HANDLE_PTR phSession, CK_OBJECT_HANDLE_PTR phObject,
	CK_ATTRIBUTE aFindCriteria[], CK_ULONG iFindCriteria, BOOL bReturnFirst);

BYTE * cert_pkcs_sign(struct ssh2_userkey * userkey, LPCBYTE pDataToSign, int iDataToSignLen, int * iSigLen, HWND hWnd)
{
	// get the library to load from based on comment
	LPSTR szLibrary = strrchr(userkey->comment, '=') + 1;
	CK_FUNCTION_LIST_PTR pFunctionList = cert_pkcs_load_library(szLibrary);
	if (pFunctionList == NULL) return NULL;

	// handle lookup of rsa key
	LPBYTE pLookupValue = NULL;
	CK_ULONG iLookupSize = 0;
	CK_KEY_TYPE oType = 0;
	CK_ATTRIBUTE_TYPE oAttribute = 0;

	// ecdsa
	if (strstr(userkey->alg->name, "ecdsa-") == userkey->alg->name)
	{
		oType = CKK_EC;
		oAttribute = CKA_EC_POINT;
		struct ec_key *ec = userkey->data;

		// determine key size (assume x and y are same key size)
		int iKeySize = ((bignum_bitcount(ec->publicKey.x) + 7) / 8);

		// combine the x and y bytes in to a continue structures
		LPBYTE pDataToEncode = malloc(1 + iKeySize + iKeySize);
		pDataToEncode[0] = 0x04;
		for (int i = 0; i < iKeySize; i++)
		{
			pDataToEncode[1 + i] = bignum_byte(ec->publicKey.x, i);
			pDataToEncode[1 + i + iKeySize] = bignum_byte(ec->publicKey.y, i);
		}

		// reverse for big-endian
		cert_reverse_array(1 + pDataToEncode, iKeySize);
		cert_reverse_array(1 + pDataToEncode + iKeySize, iKeySize);

		// encode the structure and an der octet string
		CRYPT_DATA_BLOB tDataToEncode = { 1 + iKeySize + iKeySize, pDataToEncode };
		CRYPT_ENCODE_PARA tParam = { sizeof(CRYPT_ENCODE_PARA),
			(PFN_CRYPT_ALLOC)malloc, (PFN_CRYPT_FREE)free };
		BOOL bEncodeResult = CryptEncodeObjectEx(PKCS_7_ASN_ENCODING, X509_OCTET_STRING,
			&tDataToEncode, CRYPT_ENCODE_ALLOC_FLAG, &tParam, &pLookupValue, &iLookupSize);
		free(pDataToEncode);

		// ensure encoding was successful
		if (bEncodeResult == FALSE)
		{
			if (pLookupValue != NULL) free(pLookupValue);
			return NULL;
		}
	}

	// rsa
	else
	{
		oType = CKK_RSA;
		oAttribute = CKA_MODULUS;
		struct RSAKey * rsa = userkey->data;
		iLookupSize = rsa->bytes;
		pLookupValue = malloc(iLookupSize);
		for (int i = 0; i < iLookupSize; i++)
		{
			pLookupValue[iLookupSize - i - 1] = bignum_byte(rsa->modulus, i);
		}
	}

	// setup the find structure to identify the public key on the token
	CK_OBJECT_CLASS iPublicType = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE aFindPubCriteria[] = {
		{ CKA_CLASS,     &iPublicType,  sizeof(CK_OBJECT_CLASS) },
		{ oAttribute,    pLookupValue,  iLookupSize },
		{ CKA_KEY_TYPE,  &oType,        sizeof(CK_KEY_TYPE) }
	};

	// get a handle to the session of the token and the public key object
	CK_SESSION_HANDLE hSession = 0;
	CK_OBJECT_HANDLE hPublicKey = 0;
	pkcs_lookup_token_cert(userkey->comment, &hSession,
		&hPublicKey, aFindPubCriteria, _countof(aFindPubCriteria), TRUE);

	// cleanup the modulus since we no longer need it
	free(pLookupValue);

	// check for error
	if (hSession == 0 || hPublicKey == 0)
	{
		// error
		return NULL;
	}

	// fetch the id of the public key so we can find 
	// the corresponding private key id
	CK_ULONG iSize = 0;
	LPBYTE pSharedKeyId = pkcs_get_attribute_value(pFunctionList,
		hSession, hPublicKey, CKA_ID, &iSize);

	// check for error
	if (pSharedKeyId == NULL)
	{
		// error
		pFunctionList->C_CloseSession(hSession);
		return NULL;
	}

	// setup the find structure to identify the private key on the token
	CK_OBJECT_HANDLE iPrivateType = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE aFindPrivateCriteria[] = {
		{ CKA_CLASS,    &iPrivateType,	sizeof(CK_OBJECT_CLASS) },
		{ CKA_ID,		pSharedKeyId,	iSize },
	};

	// attempt to lookup the private key without logging in
	CK_OBJECT_HANDLE hPrivateKey;
	CK_ULONG iCertListSize = 0;
	if ((pFunctionList->C_FindObjectsInit(hSession, aFindPrivateCriteria, _countof(aFindPrivateCriteria))) != CKR_OK ||
		pFunctionList->C_FindObjects(hSession, &hPrivateKey, 1, &iCertListSize) != CKR_OK ||
		pFunctionList->C_FindObjectsFinal(hSession) != CKR_OK)
	{
		// error
		free(pSharedKeyId);
		pFunctionList->C_CloseSession(hSession);
		return NULL;
	}

	// if could not find the key, prompt the user for the pin
	if (iCertListSize == 0)
	{
		LPSTR szPin = cert_pin(userkey->comment, FALSE, NULL, hWnd);
		if (szPin == NULL)
		{
			// error
			free(pSharedKeyId);
			pFunctionList->C_CloseSession(hSession);
			return NULL;
		}

		// login to the card to unlock the private key
		if (pFunctionList->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)szPin, strlen(szPin)) != CKR_OK)
		{
			// error
			SecureZeroMemory(szPin, strlen(szPin));
			free(szPin);
			free(pSharedKeyId);
			pFunctionList->C_CloseSession(hSession);
			return NULL;
		}

		// cleanup creds
		cert_pin(userkey->comment, FALSE, szPin, hWnd);
		SecureZeroMemory(szPin, strlen(szPin));
		free(szPin);

		// attempt to lookup the private key
		iCertListSize = 0;
		if ((pFunctionList->C_FindObjectsInit(hSession, aFindPrivateCriteria, _countof(aFindPrivateCriteria))) != CKR_OK ||
			pFunctionList->C_FindObjects(hSession, &hPrivateKey, 1, &iCertListSize) != CKR_OK ||
			pFunctionList->C_FindObjectsFinal(hSession) != CKR_OK)
		{
			// error
			free(pSharedKeyId);
			pFunctionList->C_CloseSession(hSession);
			return FALSE;
		}

		// check for error
		if (iCertListSize == 0)
		{
			// error
			free(pSharedKeyId);
			pFunctionList->C_CloseSession(hSession);
			return NULL;
		}
	}

	// no longer need the shared key identifier
	free(pSharedKeyId);

	// the message to send contains the static sha1 oid header
	// followed by a sha1 hash of the data sent from the host
	DWORD iHashSize = 0;
	LPBYTE pHashData = cert_get_hash(userkey->alg->name, pDataToSign, iDataToSignLen, &iHashSize, TRUE);

	// setup the signature process to sign using the rsa private key on the card 
	CK_MECHANISM tSignMech;
	tSignMech.mechanism = (oType == CKK_RSA) ? CKM_RSA_PKCS : CKM_ECDSA;
	tSignMech.pParameter = NULL;
	tSignMech.ulParameterLen = 0;

	// create the hash value
	CK_BYTE_PTR pSignature = NULL;
	CK_ULONG iSignatureLen = 0;
	CK_RV iResult = CKR_OK;
	if ((iResult = pFunctionList->C_SignInit(hSession, &tSignMech, hPrivateKey)) != CKR_OK ||
		(iResult = pFunctionList->C_Sign(hSession, pHashData, iHashSize, NULL, &iSignatureLen)) != CKR_OK ||
		(iResult = pFunctionList->C_Sign(hSession, pHashData, iHashSize,
			pSignature = snewn(iSignatureLen, CK_BYTE), &iSignatureLen)) != CKR_OK)
	{
		// report signing errors
		if (iResult == CKR_KEY_TYPE_INCONSISTENT)
		{
			LPCSTR szMessage = "The PKCS library reported the selected certificate cannot be used to sign data.";
			MessageBox(hWnd, szMessage, "PuTTY PKCS Signing Problem", MB_OK | MB_ICONERROR);
		}
		else
		{
			LPCSTR szMessage = "The PKCS library experienced an error attempting to perform a signing operation.";
			MessageBox(hWnd, szMessage, "PuTTY PKCS Signing Problem", MB_OK | MB_ICONERROR);
		}

		// something failed so cleanup signature
		if (pSignature != NULL)
		{
			sfree(pSignature);
			pSignature = NULL;
		}
	}

	// return the signature to the caller
	sfree(pHashData);
	*iSigLen = iSignatureLen;
	pFunctionList->C_CloseSession(hSession);
	return pSignature;
}

void cert_pkcs_load_cert(LPCSTR szCert, PCCERT_CONTEXT* ppCertCtx, HCERTSTORE* phStore)
{
	// split on the hint symbol to get the library path
	LPSTR szThumb = strdup(szCert);
	LPSTR szLibrary = strrchr(szThumb, '=');
	*szLibrary++ = '\0';

	CK_FUNCTION_LIST_PTR pFunctionList = cert_pkcs_load_library(szLibrary);
	if (pFunctionList == NULL) return;

	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_OBJECT_CLASS iObjectType = CKO_CERTIFICATE;
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
	*ppCertCtx = pkcs_get_cert_from_token(pFunctionList, hSession, hObject);

	// cleanup
	free(szThumb);
}

CK_FUNCTION_LIST_PTR cert_pkcs_load_library(LPCSTR szLibrary)
{
	typedef struct PROGRAM_ITEM
	{
		struct PROGRAM_ITEM * NextItem;
		LPCSTR Path;
		HMODULE Library;
		CK_FUNCTION_LIST_PTR FunctionList;
	} PROGRAM_ITEM;

	static PROGRAM_ITEM * LibraryList = NULL;

	// see if module was already loaded
	for (PROGRAM_ITEM * hCurItem = LibraryList; hCurItem != NULL; hCurItem = hCurItem->NextItem)
	{
		if (stricmp(hCurItem->Path,szLibrary) == 0)
		{
			return hCurItem->FunctionList;
		}
	}

	// load the library and allow the loader to search the directory the dll is 
	// being loaded in and the system directory
	HMODULE hModule = LoadLibraryEx(szLibrary, 
		NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);

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

	// load the master function list for the library
	CK_FUNCTION_LIST_PTR hFunctionList = NULL;
	CK_C_GetFunctionList C_GetFunctionList =
		(CK_C_GetFunctionList)GetProcAddress(hModule, "C_GetFunctionList");
	if (C_GetFunctionList == NULL || C_GetFunctionList(&hFunctionList) != CKR_OK)
	{
		// does not look like a valid PKCS library
		LPCSTR szMessage = "PuTTY was able to read the selected library file " \
			"but it does not appear to be a PKCS library.  It does not contain " \
			"the functions necessary to interface with PKCS.";
		MessageBox(NULL, szMessage, "PuTTY PKCS Library Problem", MB_OK | MB_ICONERROR);

		// error - cleanup and return
		FreeLibrary(hModule);
		return NULL;
	}

	// run the library initialization
	CK_LONG iLong = hFunctionList->C_Initialize(NULL_PTR);
	if (iLong != CKR_OK &&
		iLong != CKR_CRYPTOKI_ALREADY_INITIALIZED)
	{
		LPCSTR szMessage = "PuTTY could not initialize the selected PKCS library. " \
			"Usually this is the result of a buggy or misconfigured PKCS library.";
		MessageBox(NULL, szMessage, "PuTTY PKCS Library Problem", MB_OK | MB_ICONERROR);

		// error - cleanup and return
		FreeLibrary(hModule);
		return NULL;
	}

	// add the item to the linked list
	PROGRAM_ITEM * hItem = (PROGRAM_ITEM *)calloc(1, sizeof(struct PROGRAM_ITEM));
	hItem->Path = strdup(szLibrary);
	hItem->Library = hModule;
	hItem->FunctionList = hFunctionList;
	hItem->NextItem = LibraryList;
	LibraryList = hItem;
	return hItem->FunctionList;
}

HCERTSTORE cert_pkcs_get_cert_store(LPCSTR * szHint, HWND hWnd)
{
	char szFile[MAX_PATH + 1] = "\0";
	OPENFILENAME tFileNameInfo;
	ZeroMemory(&tFileNameInfo, sizeof(OPENFILENAME));
	tFileNameInfo.lStructSize = sizeof(OPENFILENAME);
	tFileNameInfo.hwndOwner = hWnd;
	tFileNameInfo.lpstrFilter = "PKCS Library Files (*pkcs*.dll)\0*pkcs*.dll\0All Library Files (*.dll)\0*.dll\0\0";
	tFileNameInfo.lpstrTitle = "Please Select PKCS #11 Library File";
	tFileNameInfo.Flags = OFN_DONTADDTORECENT | OFN_FORCESHOWHIDDEN | OFN_FILEMUSTEXIST;
	tFileNameInfo.lpstrFile = (LPSTR)&szFile;
	tFileNameInfo.nMaxFile = _countof(szFile);
	tFileNameInfo.nFilterIndex = 1;
	if (GetOpenFileName(&tFileNameInfo) == 0) return NULL;

	CK_FUNCTION_LIST_PTR pFunctionList = cert_pkcs_load_library(tFileNameInfo.lpstrFile);
	if (pFunctionList == NULL) return NULL;

	// get slots -- assume a safe maximum
	CK_SLOT_ID pSlotList[32];
	CK_ULONG iSlotCount = _countof(pSlotList);
	if (pFunctionList->C_GetSlotList(CK_TRUE, pSlotList, &iSlotCount) != CKR_OK)
	{
		return NULL;
	}

	// create a memory store for this certificate
	HCERTSTORE hMemoryStore = CertOpenStore(CERT_STORE_PROV_MEMORY,
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		0, CERT_STORE_CREATE_NEW_FLAG, NULL);

	// enumerate all slot counts
	for (CK_ULONG iSlot = 0; iSlot < iSlotCount; iSlot++)
	{
		// open the session - first try read-only and then read-write
		CK_SESSION_HANDLE hSession;
		if (pFunctionList->C_OpenSession(pSlotList[iSlot],
				CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) != CKR_OK &&
			pFunctionList->C_OpenSession(pSlotList[iSlot],
				CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) != CKR_OK)
		{
			continue;
		}

		CK_BBOOL bFalse = CK_FALSE;
		CK_BBOOL bTrue = CK_TRUE;
		CK_OBJECT_CLASS iObjectType = CKO_CERTIFICATE;
		CK_ATTRIBUTE aFindCriteria[] = {
			{ CKA_CLASS,    &iObjectType, sizeof(CK_OBJECT_CLASS) },
			{ CKA_TOKEN,    &bTrue,       sizeof(CK_BBOOL) },
			{ CKA_PRIVATE,  &bFalse,      sizeof(CK_BBOOL) }
		};

		// enumerate all eligible certs in token slot
		CK_OBJECT_HANDLE aCertList[16];
		CK_ULONG iCertListSize = 0;
		if (pFunctionList->C_FindObjectsInit(hSession, aFindCriteria, _countof(aFindCriteria)) != CKR_OK ||
			pFunctionList->C_FindObjects(hSession, aCertList, _countof(aCertList), &iCertListSize) != CKR_OK ||
			pFunctionList->C_FindObjectsFinal(hSession) != CKR_OK)
		{
			// error
			pFunctionList->C_CloseSession(hSession);
			continue;
		}

		// enumerate the discovered certificates
		for (CK_ULONG iCert = 0; iCert < iCertListSize; iCert++)
		{
			PCCERT_CONTEXT pCertContext =
				pkcs_get_cert_from_token(pFunctionList, hSession, aCertList[iCert]);

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
		pFunctionList->C_CloseSession(hSession);
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

	// set returned size if requested
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
	CK_FUNCTION_LIST_PTR pFunctionList = cert_pkcs_load_library(szLibrary);
	if (pFunctionList == NULL) return;

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

	// get slots -- assume a safe maximum
	CK_SLOT_ID pSlotList[32];
	CK_ULONG iSlotCount = _countof(pSlotList);
	if (pFunctionList->C_GetSlotList(CK_TRUE, pSlotList, &iSlotCount) != CKR_OK)
	{
		return;
	}

	// enumerate all slot counts
	for (CK_ULONG iSlot = 0; iSlot < iSlotCount; iSlot++)
	{
		struct CK_TOKEN_INFO tTokenInfo;
		if (pFunctionList->C_GetTokenInfo(pSlotList[iSlot], &tTokenInfo) != CKR_OK)
		{
			continue;
		}

		// open the session - first try read-only and then read-write
		CK_SESSION_HANDLE hSession;
		if (pFunctionList->C_OpenSession(pSlotList[iSlot],
				CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) != CKR_OK &&
			pFunctionList->C_OpenSession(pSlotList[iSlot],
				CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) != CKR_OK)
		{
			continue;
		}

		// enumerate all eligible certs in store
		CK_OBJECT_HANDLE aCertList[32];
		CK_ULONG iCertListSize = 0;
		if ((pFunctionList->C_FindObjectsInit(hSession, aFindCriteria, iFindCriteria)) != CKR_OK ||
			pFunctionList->C_FindObjects(hSession, aCertList, _countof(aCertList), &iCertListSize) != CKR_OK ||
			pFunctionList->C_FindObjectsFinal(hSession) != CKR_OK)
		{
			// error
			pFunctionList->C_CloseSession(hSession);
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
				pkcs_get_cert_from_token(pFunctionList, hSession, aCertList[iCert]);

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
		pFunctionList->C_CloseSession(pSlotList[iSlot]);
	}
}

#endif // PUTTY_CAC
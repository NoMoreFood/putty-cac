#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <bcrypt.h>
#include <fido.h>
#include <string.h>
#include <sddl.h>
#include <wincred.h>
#include <aclapi.h>
#include <setupapi.h>
#include <initguid.h> 
#include <devpkey.h>
#include <fido/credman.h>

#pragma comment(lib,"setupapi.lib")
#pragma comment(lib,"crypto.lib")
#pragma comment(lib,"fido2.lib")
#pragma comment(lib,"cbor.lib")
#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"SetupAPI.lib")
#pragma comment(lib,"Hid.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"credui.lib")
#pragma comment(lib,"advapi32.lib")

// preliminary support
#ifndef COSE_ES384
#define COSE_ES384 -35
#endif
#ifndef COSE_ES512
#define COSE_ES512 -36
#endif

enum
{
	MODE_UNDEFINED = 0,
	MODE_IMPORT = 1,
	MODE_DELETE = 2,
	MODE_GRANT = 3
};

BOOL GrantAccessToDevice(LPCWSTR sDevicePath)
{
	// get device security information 
	DEVPROPTYPE devPropType = 0;
	WCHAR aSDDL[1024];
	PSECURITY_DESCRIPTOR pSecurityDescriptor = &aSDDL[0];
	HDEVINFO devInfo = SetupDiCreateDeviceInfoList(NULL, NULL);
	SP_DEVINFO_DATA devInfoData = { sizeof(SP_DEVINFO_DATA) };
	if (SetupDiOpenDeviceInfoW(devInfo, sDevicePath, NULL, 0, &devInfoData) != TRUE ||
		SetupDiGetDevicePropertyW(devInfo, &devInfoData, &DEVPKEY_Device_Security, &devPropType,
			pSecurityDescriptor, sizeof(aSDDL), NULL, 0) != TRUE)
	{
		return FALSE;
	}

	// get the DACL from the security information
	BOOL bDaclDefaulted = FALSE;
	BOOL bDaclPresent = FALSE;
	PACL pAcl = NULL;
	if (GetSecurityDescriptorDacl(pSecurityDescriptor, &bDaclPresent, &pAcl, &bDaclDefaulted) == 0)
	{
		return FALSE;
	}

	// allow interactive users to communicate with the device
	BYTE aSidBytes[SECURITY_MAX_SID_SIZE];
	DWORD iSidSize = sizeof(aSidBytes);
	PSID pSid = (PSID)&aSidBytes;
	CreateWellKnownSid(WinInteractiveSid, NULL, pSid, &iSidSize);
	EXPLICIT_ACCESSW tExplcitAccess = { 0 };
	tExplcitAccess.grfAccessMode = GRANT_ACCESS;
	tExplcitAccess.grfInheritance = NO_INHERITANCE;
	tExplcitAccess.grfAccessPermissions = GENERIC_WRITE | GENERIC_READ;
	BuildTrusteeWithSidW(&tExplcitAccess.Trustee, pSid);

	// merge the new ace into the acl
	PACL pNewAcl = NULL;
	if (SetEntriesInAclW(1, &tExplcitAccess, pAcl, &pNewAcl) != ERROR_SUCCESS)
	{
		return FALSE;
	}

	// rebuild the security information and commit to the device
	ULONG iSizeNew = 0;
	ULONG iEntryCount = 0;
	PEXPLICIT_ACCESSW pEntryList = NULL;
	PSECURITY_DESCRIPTOR pSecurityDescriptorNew = NULL;
	BOOL bReturn = FALSE;
	if (GetExplicitEntriesFromAclW(pNewAcl, &iEntryCount, &pEntryList) == ERROR_SUCCESS &&
		BuildSecurityDescriptorW(NULL, NULL, iEntryCount, pEntryList, 0, NULL,
			pSecurityDescriptor, &iSizeNew, &pSecurityDescriptorNew) == ERROR_SUCCESS &&
		SetupDiOpenDeviceInfoW(devInfo, sDevicePath, NULL, 0, &devInfoData) == TRUE &&
		SetupDiSetDevicePropertyW(devInfo, &devInfoData, &DEVPKEY_Device_Security, devPropType,
			pSecurityDescriptorNew, iSizeNew, 0) == TRUE)
	{
		bReturn = TRUE;
	}

	// cycle device state to trigger descriptor re-read
	for (int iState[2] = { DICS_DISABLE , DICS_ENABLE }, iIndex = 0; iIndex < _countof(iState); iIndex++)
	{
		SP_PROPCHANGE_PARAMS pcParams = {0};
		pcParams.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
		pcParams.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
		pcParams.StateChange = iState[iIndex];
		pcParams.Scope = DICS_FLAG_GLOBAL;
		pcParams.HwProfile = 0;

		SetupDiSetClassInstallParamsW(devInfo, &devInfoData, &pcParams.ClassInstallHeader, sizeof(SP_PROPCHANGE_PARAMS));
		SetupDiChangeState(devInfo, &devInfoData);
	}

	// cleanup
	if (pEntryList != NULL) LocalFree(pEntryList);
	if (pSecurityDescriptorNew != NULL) LocalFree(pSecurityDescriptorNew);
    if (pNewAcl != NULL) LocalFree(pNewAcl);
	return bReturn;
}

LPCSTR GetTokenPin()
{
	static CHAR sPINUTF[CREDUI_MAX_PASSWORD_LENGTH + 1] = "";
	if (strlen(sPINUTF) > 0) return sPINUTF;

	// prompt the user to enter the application name
	CREDUI_INFOW tCredInfo;
	ZeroMemory(&tCredInfo, sizeof(CREDUI_INFOW));
	tCredInfo.cbSize = sizeof(tCredInfo);
	tCredInfo.pszCaptionText = L"Enter Token PIN";
	tCredInfo.pszMessageText = L"Please enter the PIN for the FIDO token. This will be used to " \
		L"query the token and cache all public keys assocatied with existing resident keys. ";
	WCHAR sUserName[CREDUI_MAX_USERNAME_LENGTH + 1] = L"<Using Token>";
	WCHAR sPIN[CREDUI_MAX_PASSWORD_LENGTH + 1] = L"";
	if (CredUIPromptForCredentialsW(&tCredInfo, L"Enter PIN", NULL, 0, &sUserName[0],
		_countof(sUserName), &sPIN[0], _countof(sPIN), NULL,
		CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_DO_NOT_PERSIST | CREDUI_FLAGS_EXCLUDE_CERTIFICATES | CREDUI_FLAGS_KEEP_USERNAME | CREDUI_FLAGS_ALWAYS_SHOW_UI) != ERROR_SUCCESS)
	{
		exit(__LINE__);
	}

	// convert to utf8 for libfido compatibility
	if (WideCharToMultiByte(CP_UTF8, 0, sPIN, -1, sPINUTF, sizeof(sPINUTF), NULL, NULL) == 0 ||
		strlen(sPINUTF) != wcslen(sPIN))
	{
		exit(__LINE__);
	}

	return sPINUTF;
}

int wmain(int iArgc, WCHAR** sArgv)
{
	// parameters for argument processing
	DWORD iOperationMode = MODE_UNDEFINED;
	LPSTR sTargetedKey = NULL;
	LPWSTR sSidToModify = NULL;

	DWORD iProcessList[] = { 0, 0 };
	if (iArgc == 1 && GetConsoleProcessList(&iProcessList[0], _countof(iProcessList)) > 1)
	{
		// assume in import mode when run from non-console apps
		iOperationMode = MODE_IMPORT;
	}
	else if (iArgc >= 2 && _wcsicmp(sArgv[1], L"--import-fido") == 0)
	{
		iOperationMode = MODE_IMPORT;
		if (iArgc == 3) sSidToModify = sArgv[2];
	}
	else if (iArgc == 2 && _wcsicmp(sArgv[1], L"--grant-fido") == 0)
	{
		iOperationMode = MODE_GRANT;
	}
	else if (iArgc >= 3 && _wcsicmp(sArgv[1], L"--delete-fido") == 0)
	{
		iOperationMode = MODE_DELETE;
		int isTargetedKeySize = (wcslen(sArgv[2]) + 1) * sizeof(CHAR);
		sTargetedKey = malloc(isTargetedKeySize);
		if (WideCharToMultiByte(CP_UTF8, 0, sArgv[2], -1, sTargetedKey, isTargetedKeySize, NULL, NULL) == 0)
		{
			return __LINE__;
		}
		
		if (iArgc == 4) sSidToModify = sArgv[2];
	}

	// print help if problem processing arguments
	if (iOperationMode == MODE_UNDEFINED)
	{
		wprintf(L"Syntax: --import-fido [SID]\r\n");
		wprintf(L"Syntax: --delete-fido-key <AppName> [SID]\r\n");
		wprintf(L"Syntax: --grant-fido\r\n");
		return __LINE__;
	}

	// if third argument is specified, then import to that key instead of HKCU
	LPWSTR sPubKeySubKey = L"Software\\SimonTatham\\PuTTY\\Fido\\PubKeyBlobs";
	LPWSTR sCredIdSubKey = L"Software\\SimonTatham\\PuTTY\\Fido\\CredIdBlobs";
	LPWSTR sUserVerSubKey = L"Software\\SimonTatham\\PuTTY\\Fido\\UserVerification";
	HANDLE hBaseKey = HKEY_CURRENT_USER;
	if (iOperationMode == MODE_IMPORT && sSidToModify != NULL)
	{
		hBaseKey = HKEY_USERS;
		LPWSTR sNewPubIdSubKey = calloc(wcslen(sSidToModify) + 1 + wcslen(sPubKeySubKey) + 1, sizeof(WCHAR));
		wsprintfW(sNewPubIdSubKey, L"%s\\%s", sSidToModify, sPubKeySubKey);
		sPubKeySubKey = sNewPubIdSubKey;
		LPWSTR sNewCredIdSubKey = calloc(wcslen(sSidToModify) + 1 + wcslen(sCredIdSubKey) + 1, sizeof(WCHAR));
		wsprintfW(sNewCredIdSubKey, L"%s\\%s", sSidToModify, sCredIdSubKey);
		sCredIdSubKey = sNewCredIdSubKey;
		LPWSTR sNewUserVerSubKey = calloc(wcslen(sSidToModify) + 1 + wcslen(sUserVerSubKey) + 1, sizeof(WCHAR));
		wsprintfW(sNewUserVerSubKey, L"%s\\%s", sSidToModify, sUserVerSubKey);
		sUserVerSubKey = sNewUserVerSubKey;
	}

	// allocate memory to hold list of devices
	fido_dev_info_t* tDevList = fido_dev_info_new(64);
	if (tDevList == NULL) return __LINE__;

	// enumerate devices
	size_t iKeyCount = 0;
	size_t iDevices;
	fido_dev_info_manifest(tDevList, 64, &iDevices);
	for (size_t iDevice = 0; iDevice < iDevices; iDevice++)
	{
		const fido_dev_info_t* tDeviceInfo = fido_dev_info_ptr(tDevList, iDevice);

		// get device id for sddl lookup
		if (iOperationMode == MODE_GRANT)
		{
			// parse the device id to reconstruct from the fido dev path
			CHAR sVid[9] = "", sPid[9] = "", sId[64] = "";
			if (sscanf(fido_dev_info_path(tDeviceInfo), 
				"\\\\?\\hid#%8[^&]&%8[^#]#%64[^#]#{", sVid, sPid, sId) != 3) continue;
		
			// reconstruct the path to open the device handle
			WCHAR sDevicePath[128] = L"";
			wsprintfW(sDevicePath, L"HID\\%S&%S\\%S", _strupr(sVid), _strupr(sPid), _strupr(sId));

			// update the security string
			if (GrantAccessToDevice(sDevicePath) == FALSE)
			{
				wprintf(L"Failed to update security: %s", sDevicePath);
			}
			continue;
		}

		// connect to the device
		fido_dev_t* tDevice = fido_dev_new();

		if (tDevice != NULL &&
			fido_dev_open(tDevice, fido_dev_info_path(tDeviceInfo)) == FIDO_OK)
		{
			// get relying party list for this device
			fido_credman_rp_t* tRelyingParty = fido_credman_rp_new();
			if (tRelyingParty != NULL && (
				fido_credman_get_dev_rp(tDevice, tRelyingParty, NULL) == FIDO_OK ||
				fido_credman_get_dev_rp(tDevice, tRelyingParty, GetTokenPin()) == FIDO_OK))
			{
				// enumerate relying parties
				const size_t iRelyingPartyCount = fido_credman_rp_count(tRelyingParty);
				for (size_t iRelyingParty = 0; iRelyingParty < iRelyingPartyCount; iRelyingParty++)
				{
					const char* sRelyingPartyId = fido_credman_rp_id(tRelyingParty, iRelyingParty);
					if (_strnicmp(sRelyingPartyId, "ssh:", strlen("ssh:")) != 0) continue;

					// skip if key is targetted but this is not the key
					if (sTargetedKey != NULL && _stricmp(sTargetedKey, sRelyingPartyId) != 0) continue;

					// convert to unicode in order to modify registry keys
					int iRelyingPartyUnicodeSize = (strlen(sRelyingPartyId) + 1) * sizeof(WCHAR);
					LPWSTR sRelyingPartyIdUnicode = malloc(iRelyingPartyUnicodeSize);
					if (MultiByteToWideChar(CP_UTF8, 0, sRelyingPartyId, -1, sRelyingPartyIdUnicode, iRelyingPartyUnicodeSize) == 0)
					{
						free(sRelyingPartyIdUnicode);
						wprintf(L"Unable to format application name '%S'.", sRelyingPartyId);
						continue;
					}

					// get a list of resident credentials
					fido_credman_rk_t* tResidentKeyList = fido_credman_rk_new();
					if (tResidentKeyList != NULL &&
						fido_credman_get_dev_rk(tDevice, sRelyingPartyId, tResidentKeyList, NULL) == FIDO_OK ||
						fido_credman_get_dev_rk(tDevice, sRelyingPartyId, tResidentKeyList, GetTokenPin()) == FIDO_OK)
					{
						// enumerate resident keys
						const size_t iResidentKeyCount = fido_credman_rk_count(tResidentKeyList);
						if (iResidentKeyCount > 1) wprintf(L"Notice: application name '%S' has more than one key.", sRelyingPartyId);

						// enumerate resident keys for this relying party
						for (int iResidentKey = iResidentKeyCount - 1; iResidentKey >= 0; iResidentKey--)
						{
							// get the credential structure associated with this resident key
							const fido_cred_t* tCred = fido_credman_rk(tResidentKeyList, iResidentKey);
							if (tCred == NULL) continue;

							// delete key if in delete mode
							if (iOperationMode == MODE_DELETE)
							{
								if (fido_credman_del_dev_rk(tDevice, fido_cred_id_ptr(tCred), fido_cred_id_len(tCred), NULL) == FIDO_OK ||
									fido_credman_del_dev_rk(tDevice, fido_cred_id_ptr(tCred), fido_cred_id_len(tCred), GetTokenPin()) == FIDO_OK)
								{
									RegDeleteKeyValueW(hBaseKey, sPubKeySubKey, sRelyingPartyIdUnicode);
									RegDeleteKeyValueW(hBaseKey, sCredIdSubKey, sRelyingPartyIdUnicode);
									RegDeleteKeyValueW(hBaseKey, sUserVerSubKey, sRelyingPartyIdUnicode);
									iKeyCount++;
								}
								continue;
							}

							// warn and skip if unsupported type
							DWORD iMagicByte = 0;
							const int iCredAlg = fido_cred_type(tCred);
							if (iCredAlg == COSE_EDDSA) iMagicByte = BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC;
							else if (iCredAlg == COSE_ES256) iMagicByte = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
							else if (iCredAlg == COSE_ES384) iMagicByte = BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
							else if (iCredAlg == COSE_ES512) iMagicByte = BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
							else
							{
								wprintf(L"Unsupported type for relying party '%S'.", sRelyingPartyId);
								continue;
							}

							// get the public key associated with this credential 
							const unsigned char* aPubKeyData = fido_cred_pubkey_ptr(tCred);
							size_t iPubKeyLen = fido_cred_pubkey_len(tCred);
							const unsigned char* aCredId = fido_cred_id_ptr(tCred);
							size_t iCredIdLen = fido_cred_id_len(tCred);
							DWORD iUserVerification = fido_cred_prot(tCred);
							const ULONG iKeySize = fido_cred_pubkey_len(tCred) / (iCredAlg == COSE_EDDSA ? 1 : 2);

							// allocate key blob and populate headers
							int iPublicKeyBobBufferSize = sizeof(PBCRYPT_ECCKEY_BLOB) + fido_cred_pubkey_len(tCred);
							PBYTE aPublicKeyBlobBuffer = malloc(iPublicKeyBobBufferSize);
							((PBCRYPT_ECCKEY_BLOB)aPublicKeyBlobBuffer)->cbKey = iKeySize;
							((PBCRYPT_ECCKEY_BLOB)aPublicKeyBlobBuffer)->dwMagic = iMagicByte;
							memcpy(&aPublicKeyBlobBuffer[sizeof(BCRYPT_ECCKEY_BLOB)], aPubKeyData, fido_cred_pubkey_len(tCred));

							// create registry keys
							RegSetKeyValueW(hBaseKey, sPubKeySubKey, sRelyingPartyIdUnicode, REG_BINARY,
								aPublicKeyBlobBuffer, iPublicKeyBobBufferSize);
							RegSetKeyValueW(hBaseKey, sCredIdSubKey, sRelyingPartyIdUnicode, REG_BINARY,
								aCredId, (DWORD)iCredIdLen);
							RegSetKeyValueW(hBaseKey, sUserVerSubKey, sRelyingPartyIdUnicode, REG_DWORD,
								&iUserVerification, (DWORD)sizeof(iUserVerification));
							iKeyCount++;
						}
					}

					fido_credman_rk_free(&tResidentKeyList);
					free(sRelyingPartyIdUnicode);
				}
			}

			fido_credman_rp_free(&tRelyingParty);
			fido_dev_close(tDevice);
		}

		fido_dev_free(&tDevice);
	}

	WCHAR sMessageToDisplay[64];
	if (iOperationMode == MODE_IMPORT)
	{
		swprintf_s(&sMessageToDisplay[0], _countof(sMessageToDisplay), L"Total Keys Imported: %zu", iKeyCount);
		MessageBoxW(NULL, &sMessageToDisplay[0], L"Import Summary", MB_OK);
	}
	if (iOperationMode == MODE_DELETE)
	{
		swprintf_s(&sMessageToDisplay[0], _countof(sMessageToDisplay), L"Total Keys Deleted: %zu", iKeyCount);
		MessageBoxW(NULL, &sMessageToDisplay[0], L"Deletion Summary", MB_OK);
	}

	fido_dev_info_free(&tDevList, 64);
	return 0;
}

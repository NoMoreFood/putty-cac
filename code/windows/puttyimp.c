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

#include "cert_fido.h"

#pragma comment(lib,"setupapi.lib")
#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"crypt32.lib")
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

static BOOL GetTokenPin(CHAR *pin, int capacity, DWORD *status)
{
	if (*status != ERROR_SUCCESS) return FALSE;
	if (*pin) return TRUE;

	// Request a PIN only for operations that require one.
	CREDUI_INFOW tCredInfo;
	ZeroMemory(&tCredInfo, sizeof(CREDUI_INFOW));
	tCredInfo.cbSize = sizeof(tCredInfo);
	tCredInfo.pszCaptionText = L"Enter Token PIN";
	tCredInfo.pszMessageText = L"Enter the PIN to manage resident credentials on this FIDO token.";
	WCHAR sUserName[CREDUI_MAX_USERNAME_LENGTH + 1] = L"<Using Token>";
	WCHAR sPIN[CREDUI_MAX_PASSWORD_LENGTH + 1] = L"";
	*status = CredUIPromptForCredentialsW(&tCredInfo, L"Enter PIN", NULL, 0, &sUserName[0],
		_countof(sUserName), &sPIN[0], _countof(sPIN), NULL,
		CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_DO_NOT_PERSIST | CREDUI_FLAGS_EXCLUDE_CERTIFICATES |
		CREDUI_FLAGS_KEEP_USERNAME | CREDUI_FLAGS_ALWAYS_SHOW_UI);
	if (*status == ERROR_SUCCESS && !WideCharToMultiByte(CP_UTF8, 0, sPIN, -1, pin, capacity, NULL, NULL))
		*status = GetLastError();
	SecureZeroMemory(sPIN, sizeof(sPIN));
	return *status == ERROR_SUCCESS;
}

static BOOL EnumerationComplete(int result)
{
	return result == FIDO_OK || result == FIDO_ERR_NO_CREDENTIALS;
}

int wmain(int iArgc, WCHAR** sArgv)
{
	// parameters for argument processing
	DWORD iOperationMode = MODE_UNDEFINED;
	WCHAR targetApp[FIDO_MAX_APPID_LEN];
	BYTE targetId[FIDO_MAX_CREDID_LEN];
	DWORD targetIdLen = sizeof(targetId);
	LPCWSTR sSidToModify = NULL;

	DWORD iProcessList[] = { 0, 0 };
	if (iArgc == 1 && GetConsoleProcessList(&iProcessList[0], _countof(iProcessList)) > 1)
	{
		// assume in import mode when run from non-console apps
		iOperationMode = MODE_IMPORT;
	}
	else if ((iArgc == 2 || iArgc == 3) && _wcsicmp(sArgv[1], L"--import-fido") == 0)
	{
		iOperationMode = MODE_IMPORT;
		if (iArgc == 3) sSidToModify = sArgv[2];
	}
	else if (iArgc == 2 && _wcsicmp(sArgv[1], L"--grant-fido") == 0)
	{
		iOperationMode = MODE_GRANT;
	}
	else if ((iArgc == 4 || iArgc == 5) && _wcsicmp(sArgv[1], L"--delete-fido") == 0)
	{
		// Both identifiers are hex-encoded so application names survive command-line quoting.
		DWORD appSize = sizeof(targetApp);
		if (!CryptStringToBinaryW(sArgv[2], 0, CRYPT_STRING_HEXRAW, (BYTE *)targetApp, &appSize, NULL, NULL) ||
			appSize < 2 * sizeof(WCHAR) || appSize % sizeof(WCHAR) || targetApp[appSize / sizeof(WCHAR) - 1] ||
			(wcslen(targetApp) + 1) * sizeof(WCHAR) != appSize ||
			!CryptStringToBinaryW(sArgv[3], 0, CRYPT_STRING_HEXRAW, targetId, &targetIdLen, NULL, NULL) || !targetIdLen)
			return ERROR_INVALID_PARAMETER;
		iOperationMode = MODE_DELETE;
		if (iArgc == 5) sSidToModify = sArgv[4];
	}

	// print help if problem processing arguments
	if (iOperationMode == MODE_UNDEFINED)
	{
		wprintf(L"Syntax: --import-fido [SID]\r\n");
		wprintf(L"Syntax: --delete-fido <UTF16-App-Hex> <Credential-ID-Hex> [SID]\r\n");
		wprintf(L"Syntax: --grant-fido\r\n");
		return __LINE__;
	}


	// allocate memory to hold list of devices
	fido_dev_info_t* tDevList = fido_dev_info_new(64);
	if (tDevList == NULL) return __LINE__;

	// enumerate devices
	size_t iKeyCount = 0;
	BOOL scanComplete = TRUE, deleteAttempted = FALSE, deleted = FALSE;
	DWORD pinStatus = ERROR_SUCCESS;
	size_t iDevices = 0;
	if (fido_dev_info_manifest(tDevList, 64, &iDevices) != FIDO_OK)
	{
		if (iOperationMode != MODE_DELETE)
		{
			fido_dev_info_free(&tDevList, 64);
			return ERROR_NOT_READY;
		}
		scanComplete = FALSE;
		iDevices = 0;
	}
	for (size_t iDevice = 0; iDevice < iDevices; iDevice++)
	{
		const fido_dev_info_t* tDeviceInfo = fido_dev_info_ptr(tDevList, iDevice);
		CHAR pin[4 * CREDUI_MAX_PASSWORD_LENGTH + 1] = "";

		// get device id for sddl lookup
		if (iOperationMode == MODE_GRANT)
		{
			// parse the device id to reconstruct from the fido dev path
			CHAR sVid[9] = "", sPid[9] = "", sId[64] = "";
			if (sscanf(fido_dev_info_path(tDeviceInfo), 
				"\\\\?\\hid#%8[^&]&%8[^#]#%63[^#]#{", sVid, sPid, sId) != 3) continue;
		
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
			int rpResult = FIDO_ERR_NO_CREDENTIALS;
			if (fido_dev_supports_credman(tDevice))
			{
				rpResult = tRelyingParty ? fido_credman_get_dev_rp(tDevice, tRelyingParty, NULL) : FIDO_ERR_INTERNAL;
				if (tRelyingParty && !EnumerationComplete(rpResult) && GetTokenPin(pin, sizeof(pin), &pinStatus))
					rpResult = fido_credman_get_dev_rp(tDevice, tRelyingParty, pin);
			}
			if (!EnumerationComplete(rpResult)) scanComplete = FALSE;
			if (rpResult == FIDO_OK)
			{
				// enumerate relying parties
				const size_t iRelyingPartyCount = fido_credman_rp_count(tRelyingParty);
				for (size_t iRelyingParty = 0; iRelyingParty < iRelyingPartyCount; iRelyingParty++)
				{
					const char* sRelyingPartyId = fido_credman_rp_id(tRelyingParty, iRelyingParty);
					if (!sRelyingPartyId) { scanComplete = FALSE; continue; }
					if (_strnicmp(sRelyingPartyId, "ssh:", strlen("ssh:")) != 0) continue;

					// The registry and the authenticator must refer to the same relying party.
					WCHAR sRelyingPartyIdUnicode[FIDO_MAX_APPID_LEN];
					if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, sRelyingPartyId, -1,
						sRelyingPartyIdUnicode, _countof(sRelyingPartyIdUnicode))) continue;
					if (iOperationMode == MODE_DELETE && wcscmp(targetApp, sRelyingPartyIdUnicode)) continue;

					// get a list of resident credentials
					fido_credman_rk_t* tResidentKeyList = fido_credman_rk_new();
					int rkResult = tResidentKeyList ?
						fido_credman_get_dev_rk(tDevice, sRelyingPartyId, tResidentKeyList, NULL) : FIDO_ERR_INTERNAL;
					if (tResidentKeyList && !EnumerationComplete(rkResult) && GetTokenPin(pin, sizeof(pin), &pinStatus))
						rkResult = fido_credman_get_dev_rk(tDevice, sRelyingPartyId, tResidentKeyList, pin);
					if (!EnumerationComplete(rkResult)) scanComplete = FALSE;
					if (rkResult == FIDO_OK)
					{
						// enumerate resident keys
						const size_t iResidentKeyCount = fido_credman_rk_count(tResidentKeyList);
						if (iResidentKeyCount > 1) wprintf(L"Notice: application name '%S' has more than one key.", sRelyingPartyId);

						// enumerate resident keys for this relying party
						for (size_t iResidentKey = iResidentKeyCount; iResidentKey-- > 0;)
						{
							// get the credential structure associated with this resident key
							const fido_cred_t* tCred = fido_credman_rk(tResidentKeyList, iResidentKey);
							if (!tCred) { scanComplete = FALSE; continue; }

							// delete key if in delete mode
							if (iOperationMode == MODE_DELETE)
							{
								if (fido_cred_id_len(tCred) != targetIdLen ||
									memcmp(fido_cred_id_ptr(tCred), targetId, targetIdLen)) continue;
								deleteAttempted = TRUE;
								deleted = fido_credman_del_dev_rk(tDevice, targetId, targetIdLen, NULL) == FIDO_OK ||
									(GetTokenPin(pin, sizeof(pin), &pinStatus) &&
									 fido_credman_del_dev_rk(tDevice, targetId, targetIdLen, pin) == FIDO_OK);
								break;
							}

							// warn and skip if unsupported type
							fido_public_key_buffer_t key = { 0 };
							const int iCredAlg = fido_cred_type(tCred);
							switch (iCredAlg)
							{
							case COSE_EDDSA: key.tHeader = (BCRYPT_ECCKEY_BLOB){ BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC, 32 }; break;
							case COSE_ES256: key.tHeader = (BCRYPT_ECCKEY_BLOB){ BCRYPT_ECDSA_PUBLIC_P256_MAGIC, 32 }; break;
							case COSE_ES384: key.tHeader = (BCRYPT_ECCKEY_BLOB){ BCRYPT_ECDSA_PUBLIC_P384_MAGIC, 48 }; break;
							case COSE_ES512: key.tHeader = (BCRYPT_ECCKEY_BLOB){ BCRYPT_ECDSA_PUBLIC_P521_MAGIC, 66 }; break;
							default:
								wprintf(L"Unsupported type for relying party '%S'.", sRelyingPartyId);
								continue;
							}

							// get the public key associated with this credential 
							const unsigned char* aPubKeyData = fido_cred_pubkey_ptr(tCred);
							size_t iPubKeyLen = fido_cred_pubkey_len(tCred);
							const unsigned char* aCredId = fido_cred_id_ptr(tCred);
							size_t iCredIdLen = fido_cred_id_len(tCred);
							if (!aPubKeyData || !aCredId || !iCredIdLen || iCredIdLen > FIDO_MAX_CREDID_LEN ||
								iPubKeyLen != key.tHeader.cbKey * (iCredAlg == COSE_EDDSA ? 1 : 2)) continue;
							memcpy(key.pCoordinates, aPubKeyData, iPubKeyLen);
							if (cert_fido_update_cache(sSidToModify, sRelyingPartyIdUnicode, &key,
								(DWORD)(sizeof(key.tHeader) + iPubKeyLen), aCredId, (DWORD)iCredIdLen,
								fido_cred_prot(tCred), NULL))
								iKeyCount++;
						}
					}

					fido_credman_rk_free(&tResidentKeyList);
					if (deleteAttempted || pinStatus != ERROR_SUCCESS) break;
				}
			}

			fido_credman_rp_free(&tRelyingParty);
			fido_dev_close(tDevice);
		}
		else scanComplete = FALSE;

		fido_dev_free(&tDevice);
		SecureZeroMemory(pin, sizeof(pin));
		if (deleteAttempted || pinStatus != ERROR_SUCCESS) break;
	}

	WCHAR sMessageToDisplay[64];
	if (iOperationMode == MODE_IMPORT)
	{
		swprintf_s(&sMessageToDisplay[0], _countof(sMessageToDisplay), L"Total Keys Imported: %zu", iKeyCount);
		MessageBoxW(NULL, &sMessageToDisplay[0], L"Import Summary", MB_OK);
	}
	if (iOperationMode == MODE_DELETE)
	{
		// Cache-only credentials are removable even when no resident credential was found.
		BOOL removed = (deleted || pinStatus == ERROR_CANCELLED ||
			(scanComplete && !deleteAttempted && pinStatus == ERROR_SUCCESS)) &&
			cert_fido_update_cache(sSidToModify, targetApp, NULL, 0, targetId, targetIdLen, 0, NULL);
		LPCWSTR message;
		if (deleted)
			message = removed ? L"The selected credential was removed from the token and local cache." :
				L"The token credential was deleted. The matching cache entry could not be removed.";
		else if (!scanComplete && pinStatus != ERROR_CANCELLED)
			message = L"The token could not be checked. The saved credential was kept so you can retry.";
		else
			message = removed ? L"The selected credential was removed from the local cache only." :
				L"The selected credential could not be removed.";
		MessageBoxW(NULL, message, L"FIDO Key Delete", MB_OK | (removed ? MB_ICONINFORMATION : MB_ICONERROR));
		if (!removed) { fido_dev_info_free(&tDevList, 64); return ERROR_GEN_FAILURE; }
	}

	fido_dev_info_free(&tDevList, 64);
	return 0;
}

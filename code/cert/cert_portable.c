#ifdef PUTTY_CAC

#define CERT_PORTABLE_NO_REDEFINE

#include <windows.h>
#include <shlwapi.h>
#include <sddl.h>
#include <objbase.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "cert_portable.h"
#include "cert_fido.h"

#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib,"ole32.lib")

static const WCHAR sPuttyRoot[] = L"Software\\SimonTatham";
static const WCHAR sSoftwareRoot[] = L"Software";

static INIT_ONCE oInitOnce = INIT_ONCE_STATIC_INIT;
static HKEY hPortableRoot = NULL;
static WCHAR sPortablePath[MAX_PATH];

static BOOL cert_portable_file_exists(LPCWSTR sPath)
{
	DWORD iAttributes = GetFileAttributesW(sPath);
	return iAttributes != INVALID_FILE_ATTRIBUTES &&
		!(iAttributes & FILE_ATTRIBUTE_DIRECTORY);
}

static BOOL cert_portable_append_settings(WCHAR* sPath)
{
	size_t iLen = wcslen(sPath);
	size_t iNameLen = strlen(CERT_PORTABLE_SETTINGS);
	if (iLen == 0 || iLen + iNameLen + 2 > MAX_PATH) return FALSE;
	if (sPath[iLen - 1] != L'\\') sPath[iLen++] = L'\\';
	for (size_t i = 0; i <= iNameLen; i++)
		sPath[iLen + i] = (WCHAR)CERT_PORTABLE_SETTINGS[i];
	return TRUE;
}

static BOOL cert_portable_find_settings(WCHAR* sPath)
{
	DWORD iLen = GetModuleFileNameW(NULL, sPath, MAX_PATH);
	if (iLen > 0 && iLen < MAX_PATH)
	{
		WCHAR* sSlash = wcsrchr(sPath, L'\\');
		if (sSlash != NULL)
		{
			sSlash[1] = L'\0';
			if (cert_portable_append_settings(sPath) &&
				cert_portable_file_exists(sPath))
				return TRUE;
		}
	}

	return FALSE;
}

static void cert_portable_remove_logs(LPCWSTR sPath)
{
	const WCHAR* suffixes[] = { L".LOG1", L".LOG2" };
	for (size_t i = 0; i < _countof(suffixes); i++)
	{
		WCHAR sLog[MAX_PATH + _countof(L".LOG1")];
		swprintf_s(sLog, _countof(sLog), L"%s%s", sPath, suffixes[i]);
		DeleteFileW(sLog);
	}
}

static void cert_portable_cleanup(void)
{
	if (hPortableRoot == NULL) return;
	RegCloseKey(hPortableRoot);
	hPortableRoot = NULL;

	cert_portable_remove_logs(sPortablePath);
}

static BOOL CALLBACK cert_portable_init(PINIT_ONCE pInitOnce, PVOID pParam, PVOID* ppContext)
{
	HANDLE hMutex;
	WCHAR sPath[MAX_PATH];
	(void)pInitOnce;
	(void)pParam;
	(void)ppContext;

	hMutex = CreateMutexW(NULL, FALSE, L"Local\\PuTTYCACPortableSettings");
	if (hMutex != NULL) WaitForSingleObject(hMutex, INFINITE);

	if (cert_portable_find_settings(sPath))
	{
		LSTATUS iStatus = RegLoadAppKeyW(sPath, &hPortableRoot, KEY_ALL_ACCESS, 0, 0);
		if (iStatus == ERROR_REGISTRY_IO_FAILED)
		{
			HANDLE hFile = CreateFileW(sPath, GENERIC_READ | DELETE, 0, NULL,
				OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile != INVALID_HANDLE_VALUE)
			{
				LARGE_INTEGER iSize;
				FILE_DISPOSITION_INFO tDisposition = { TRUE };
				BOOL bDeleted = GetFileSizeEx(hFile, &iSize) && iSize.QuadPart == 0 &&
					SetFileInformationByHandle(hFile, FileDispositionInfo, &tDisposition, sizeof(tDisposition));
				CloseHandle(hFile);
				if (bDeleted) iStatus = RegLoadAppKeyW(sPath, &hPortableRoot, KEY_ALL_ACCESS, 0, 0);
			}
		}
		if (iStatus != ERROR_SUCCESS)
		{
			WCHAR sError[256] = L"";
			WCHAR sMessage[MAX_PATH + 512];
			FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
				(DWORD)iStatus, 0, sError, _countof(sError), NULL);
			swprintf_s(sMessage, _countof(sMessage),
				L"Could not load portable settings file:\n\n%s\n\n%s", sPath, sError);
			MessageBoxW(NULL, sMessage, L"PuTTY-CAC", MB_OK | MB_ICONERROR);
			ExitProcess(1);
		}
		if (hPortableRoot != NULL)
		{
			wcscpy(sPortablePath, sPath);
			atexit(cert_portable_cleanup);
		}
	}

	if (hMutex != NULL)
	{
		ReleaseMutex(hMutex);
		CloseHandle(hMutex);
	}
	return TRUE;
}

BOOL cert_portable_enabled(void)
{
	InitOnceExecuteOnce(&oInitOnce, cert_portable_init, NULL, NULL);
	return hPortableRoot != NULL;
}

static LPWSTR cert_portable_from_mb(LPCSTR sValue)
{
	if (sValue == NULL) return NULL;
	int iSize = MultiByteToWideChar(CP_ACP, 0, sValue, -1, NULL, 0);
	if (iSize == 0) return NULL;
	LPWSTR sReturn = malloc(iSize * sizeof(WCHAR));
	if (sReturn == NULL) return NULL;
	if (MultiByteToWideChar(CP_ACP, 0, sValue, -1, sReturn, iSize) == 0)
	{
		free(sReturn);
		return NULL;
	}
	return sReturn;
}


static BOOL cert_portable_path_matches(LPCWSTR sPath, LPCWSTR sPrefix)
{
	size_t iLen = wcslen(sPrefix);
	return _wcsnicmp(sPath, sPrefix, iLen) == 0 &&
		(sPath[iLen] == L'\0' || sPath[iLen] == L'\\');
}

static LPCWSTR cert_portable_hku_path(LPCWSTR sSubKey)
{
	LPCWSTR sSlash = sSubKey ? wcschr(sSubKey, L'\\') : NULL;
	return sSlash ? sSlash + 1 : NULL;
}

static BOOL cert_portable_should_redirect(LPCWSTR sSubKey)
{
	if (sSubKey == NULL) return FALSE;
	return cert_portable_path_matches(sSubKey, sPuttyRoot) ||
		_wcsicmp(sSubKey, sSoftwareRoot) == 0;
}

static BOOL cert_portable_redirect(HKEY hKey, LPCWSTR sSubKey, HKEY* phKey, LPCWSTR* psSubKey)
{
	LPCWSTR sPortableSubKey = sSubKey;

	if (!cert_portable_enabled()) return FALSE;

	if (hKey == HKEY_USERS)
		sPortableSubKey = cert_portable_hku_path(sSubKey);
	else if (hKey != HKEY_CURRENT_USER)
		return FALSE;

	if (!cert_portable_should_redirect(sPortableSubKey)) return FALSE;

	/* The hive root IS Software\SimonTatham — strip that prefix so callers
	 * address keys relative to hPortableRoot directly. */
	size_t iPrefixLen = wcslen(sPuttyRoot);
	if (_wcsnicmp(sPortableSubKey, sPuttyRoot, iPrefixLen) == 0)
	{
		sPortableSubKey += iPrefixLen;
		if (*sPortableSubKey == L'\\') sPortableSubKey++;
	}
	else
	{
		sPortableSubKey = L"";
	}

	*phKey = hPortableRoot;
	*psSubKey = sPortableSubKey;
	return TRUE;
}

static BOOL cert_portable_redirect_a(HKEY hKey, LPCSTR sSubKey, HKEY* phKey, LPCSTR* psSubKey)
{
	if (!cert_portable_enabled() || sSubKey == NULL) return FALSE;
	if (hKey == HKEY_USERS)
	{
		sSubKey = strchr(sSubKey, '\\');
		if (sSubKey == NULL) return FALSE;
		sSubKey++;
	}
	else if (hKey != HKEY_CURRENT_USER) return FALSE;

	size_t iPrefixLen = sizeof("Software\\SimonTatham") - 1;
	if (_strnicmp(sSubKey, "Software\\SimonTatham", iPrefixLen) == 0 &&
		(sSubKey[iPrefixLen] == '\0' || sSubKey[iPrefixLen] == '\\'))
	{
		sSubKey += iPrefixLen;
		if (*sSubKey == '\\') sSubKey++;
	}
	else if (_stricmp(sSubKey, "Software") == 0) sSubKey = "";
	else return FALSE;

	*phKey = hPortableRoot;
	*psSubKey = sSubKey;
	return TRUE;
}

LONG WINAPI cert_portable_RegOpenKeyW(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)
{
	return cert_portable_RegOpenKeyExW(hKey, lpSubKey, 0, KEY_READ, phkResult);
}

LONG WINAPI cert_portable_RegOpenKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult)
{
	LPWSTR sSubKey;
	LONG iResult;

	if (!cert_portable_enabled()) return RegOpenKeyA(hKey, lpSubKey, phkResult);
	sSubKey = cert_portable_from_mb(lpSubKey);
	iResult = cert_portable_RegOpenKeyW(hKey, sSubKey, phkResult);
	free(sSubKey);
	return iResult;
}

LONG WINAPI cert_portable_RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions,
	REGSAM samDesired, PHKEY phkResult)
{
	HKEY hUseKey;
	LPCWSTR sUseSubKey;

	if (cert_portable_redirect(hKey, lpSubKey, &hUseKey, &sUseSubKey))
		return RegOpenKeyExW(hUseKey, sUseSubKey, ulOptions, samDesired, phkResult);
	return RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

LONG WINAPI cert_portable_RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions,
	REGSAM samDesired, PHKEY phkResult)
{
	LPWSTR sSubKey;
	LONG iResult;

	if (!cert_portable_enabled())
		return RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
	sSubKey = cert_portable_from_mb(lpSubKey);
	iResult = cert_portable_RegOpenKeyExW(hKey, sSubKey, ulOptions, samDesired, phkResult);
	free(sSubKey);
	return iResult;
}

LONG WINAPI cert_portable_RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved,
	LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired,
	const LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)
{
	HKEY hUseKey;
	LPCWSTR sUseSubKey;

	if (cert_portable_redirect(hKey, lpSubKey, &hUseKey, &sUseSubKey))
		return RegCreateKeyExW(hUseKey, sUseSubKey, Reserved, lpClass, dwOptions, samDesired,
			lpSecurityAttributes, phkResult, lpdwDisposition);
	return RegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired,
		lpSecurityAttributes, phkResult, lpdwDisposition);
}

LONG WINAPI cert_portable_RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved,
	LPSTR lpClass, DWORD dwOptions, REGSAM samDesired,
	const LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)
{
	LPWSTR sSubKey;
	LONG iResult;

	if (!cert_portable_enabled())
		return RegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired,
			lpSecurityAttributes, phkResult, lpdwDisposition);
	sSubKey = cert_portable_from_mb(lpSubKey);
	iResult = cert_portable_RegCreateKeyExW(hKey, sSubKey, Reserved, NULL, dwOptions,
		samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
	free(sSubKey);
	return iResult;
}

LONG WINAPI cert_portable_RegDeleteKeyW(HKEY hKey, LPCWSTR lpSubKey)
{
	HKEY hUseKey;
	LPCWSTR sUseSubKey;

	if (cert_portable_redirect(hKey, lpSubKey, &hUseKey, &sUseSubKey))
		return RegDeleteKeyW(hUseKey, sUseSubKey);
	return RegDeleteKeyW(hKey, lpSubKey);
}

LONG WINAPI cert_portable_RegDeleteKeyA(HKEY hKey, LPCSTR lpSubKey)
{
	LPWSTR sSubKey;
	LONG iResult;

	if (!cert_portable_enabled()) return RegDeleteKeyA(hKey, lpSubKey);
	sSubKey = cert_portable_from_mb(lpSubKey);
	iResult = cert_portable_RegDeleteKeyW(hKey, sSubKey);
	free(sSubKey);
	return iResult;
}

LONG WINAPI cert_portable_RegDeleteTreeW(HKEY hKey, LPCWSTR lpSubKey)
{
	HKEY hUseKey;
	LPCWSTR sUseSubKey;

	if (cert_portable_redirect(hKey, lpSubKey, &hUseKey, &sUseSubKey))
		return RegDeleteTreeW(hUseKey, sUseSubKey);
	return RegDeleteTreeW(hKey, lpSubKey);
}

LONG WINAPI cert_portable_RegDeleteTreeA(HKEY hKey, LPCSTR lpSubKey)
{
	LPWSTR sSubKey;
	LONG iResult;

	if (!cert_portable_enabled()) return RegDeleteTreeA(hKey, lpSubKey);
	sSubKey = cert_portable_from_mb(lpSubKey);
	iResult = cert_portable_RegDeleteTreeW(hKey, sSubKey);
	free(sSubKey);
	return iResult;
}

LONG WINAPI cert_portable_RegDeleteKeyValueW(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName)
{
	HKEY hUseKey;
	LPCWSTR sUseSubKey;

	if (cert_portable_redirect(hKey, lpSubKey, &hUseKey, &sUseSubKey))
		return RegDeleteKeyValueW(hUseKey, sUseSubKey, lpValueName);
	return RegDeleteKeyValueW(hKey, lpSubKey, lpValueName);
}

LONG WINAPI cert_portable_RegDeleteKeyValueA(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName)
{
	LPWSTR sSubKey, sValueName;
	LONG iResult;

	if (!cert_portable_enabled())
		return RegDeleteKeyValueA(hKey, lpSubKey, lpValueName);
	sSubKey = cert_portable_from_mb(lpSubKey);
	sValueName = cert_portable_from_mb(lpValueName);
	iResult = cert_portable_RegDeleteKeyValueW(hKey, sSubKey, sValueName);
	free(sSubKey);
	free(sValueName);
	return iResult;
}

LONG WINAPI cert_portable_RegGetValueW(HKEY hkey, LPCWSTR lpSubKey, LPCWSTR lpValue,
	DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData)
{
	HKEY hUseKey;
	LPCWSTR sUseSubKey;

	if (cert_portable_redirect(hkey, lpSubKey, &hUseKey, &sUseSubKey))
		return RegGetValueW(hUseKey, sUseSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
	return RegGetValueW(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
}

LONG WINAPI cert_portable_RegGetValueA(HKEY hkey, LPCSTR lpSubKey, LPCSTR lpValue,
	DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData)
{
	HKEY hUseKey;
	LPCSTR sUseSubKey;

	if (cert_portable_redirect_a(hkey, lpSubKey, &hUseKey, &sUseSubKey))
		return RegGetValueA(hUseKey, sUseSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
	return RegGetValueA(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
}

LONG WINAPI cert_portable_RegSetKeyValueW(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName,
	DWORD dwType, LPCVOID lpData, DWORD cbData)
{
	HKEY hUseKey;
	LPCWSTR sUseSubKey;

	if (cert_portable_redirect(hKey, lpSubKey, &hUseKey, &sUseSubKey))
		return RegSetKeyValueW(hUseKey, sUseSubKey, lpValueName, dwType, lpData, cbData);
	return RegSetKeyValueW(hKey, lpSubKey, lpValueName, dwType, lpData, cbData);
}

LONG WINAPI cert_portable_RegSetKeyValueA(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName,
	DWORD dwType, LPCVOID lpData, DWORD cbData)
{
	HKEY hUseKey;
	LPCSTR sUseSubKey;

	if (cert_portable_redirect_a(hKey, lpSubKey, &hUseKey, &sUseSubKey))
		return RegSetKeyValueA(hUseKey, sUseSubKey, lpValueName, dwType, lpData, cbData);
	return RegSetKeyValueA(hKey, lpSubKey, lpValueName, dwType, lpData, cbData);
}

LPWSTR fido_get_user_id(void)
{
	HANDLE token;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return NULL;
	union { TOKEN_USER user; BYTE data[TOKEN_USER_MAX_SIZE]; } info;
	DWORD size = sizeof(info);
	LPWSTR sid = NULL;
	if (GetTokenInformation(token, TokenUser, &info, size, &size))
		ConvertSidToStringSidW(info.user.User.Sid, &sid);
	CloseHandle(token);
	return sid;
}

HANDLE cert_fido_cache_lock(LPCWSTR sid)
{
	// The importer and its caller need only wait and release rights, including across elevation.
	BOOL portable = cert_portable_enabled();
	LPWSTR current = sid ? NULL : fido_get_user_id();
	if (!sid) sid = current;
	WCHAR name[256], sddl[384];
	PSECURITY_DESCRIPTOR sd = NULL;
	BOOL ready = sid && swprintf_s(name, _countof(name), L"Global\\PuTTYCACFidoCredentialCache-%s",
		portable ? L"Portable" : sid) > 0 &&
		swprintf_s(sddl, _countof(sddl), L"D:P(A;;0x100001;;;%s)(A;;0x100001;;;BA)(A;;0x100001;;;SY)%s"
			L"S:(ML;;NW;;;ME)", sid, portable ? L"(A;;0x100001;;;IU)" : L"") > 0 &&
		ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL);
	LocalFree(current);
	if (!ready) return NULL;
	SECURITY_ATTRIBUTES sa = { sizeof(sa), sd, FALSE };
	HANDLE mutex = CreateMutexExW(&sa, name, 0, SYNCHRONIZE | MUTEX_MODIFY_STATE);
	LocalFree(sd);
	if (mutex) {
		DWORD wait = WaitForSingleObject(mutex, INFINITE);
		if (wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED) return mutex;
		CloseHandle(mutex);
	}
	return NULL;
}

void cert_fido_cache_unlock(HANDLE mutex)
{
	ReleaseMutex(mutex);
	CloseHandle(mutex);
}

BOOL cert_fido_update_cache(LPCWSTR sid, LPCWSTR app, const fido_public_key_buffer_t *key, DWORD key_len,
	const BYTE *id, DWORD id_len, DWORD verification, const CRYPT_DATA_BLOB *expected)
{
	if (!app || !id || !id_len || id_len > FIDO_MAX_CREDID_LEN ||
		(key && (key_len < sizeof(key->tHeader) || key_len > sizeof(*key)))) return FALSE;

	// Address the initiating user's cache even when the helper runs under a different account.
	WCHAR path[256] = FIDO_REG_ROOT;
	if (sid) {
		PSID parsed;
		if (!ConvertStringSidToSidW(sid, &parsed)) return FALSE;
		LocalFree(parsed);
		if (wcslen(sid) + _countof(FIDO_REG_ROOT) + 1 > _countof(path)) return FALSE;
		swprintf_s(path, _countof(path), L"%s\\%s", sid, FIDO_REG_ROOT);
	}
	HANDLE mutex = cert_fido_cache_lock(sid);
	if (!mutex) return FALSE;
	HKEY root = NULL;
	BOOL success = FALSE;
	HKEY user = sid ? HKEY_USERS : HKEY_CURRENT_USER;
	if ((key ?
		cert_portable_RegCreateKeyExW(user, path, 0, NULL, 0, KEY_READ | KEY_WRITE, NULL, &root, NULL) :
		cert_portable_RegOpenKeyExW(user, path, 0, KEY_READ | KEY_WRITE, &root)) != ERROR_SUCCESS) goto out;

	// Snapshot all three values before replacing or removing a credential.
	fido_public_key_buffer_t old_key;
	BYTE old_id[FIDO_MAX_CREDID_LEN];
	DWORD old_verification;
	struct {
		LPCWSTR name;
		DWORD type, flags;
		const void *data;
		DWORD len;
		void *old;
		DWORD old_len;
		BOOL present;
	} values[] = {
		{ L"PubKeyBlobs", REG_BINARY, RRF_RT_REG_BINARY, key, key_len, &old_key, sizeof(old_key) },
		{ L"CredIdBlobs", REG_BINARY, RRF_RT_REG_BINARY, id, id_len, old_id, sizeof(old_id) },
		{ L"UserVerification", REG_DWORD, RRF_RT_REG_DWORD, &verification, sizeof(verification),
			&old_verification, sizeof(old_verification) },
	};
	for (BOOL confirmed = FALSE; ; confirmed = TRUE) {
		for (size_t i = 0; i < _countof(values); i++) {
			BYTE now[FIDO_MAX_CREDID_LEN];
			DWORD size = confirmed ? sizeof(now) : values[i].old_len;
			LSTATUS rc = RegGetValueW(root, values[i].name, app, values[i].flags, NULL,
				confirmed ? now : values[i].old, &size);
			BOOL present = rc == ERROR_SUCCESS;
			if (!present && rc != ERROR_FILE_NOT_FOUND && rc != ERROR_PATH_NOT_FOUND) goto out;
			if (confirmed && (present != values[i].present ||
				(present && (size != values[i].old_len || memcmp(now, values[i].old, size))))) goto out;
			values[i].present = present;
			values[i].old_len = size;
		}
		DWORD old_len = values[1].present ? values[1].old_len : 0;
		if (expected && (expected->cbData != old_len || (old_len && memcmp(expected->pbData, old_id, old_len))))
			goto out;
		BOOL same_id = old_len == id_len && !memcmp(old_id, id, id_len);
		if (!key && !same_id) goto out;
		if (confirmed || !key || (expected && old_len) || (!values[0].present && !values[1].present) ||
			(same_id && values[0].present && values[0].old_len == key_len && !memcmp(&old_key, key, key_len))) break;

		// Wait for the user's decision without blocking readers, then verify the approved snapshot.
		cert_fido_cache_unlock(mutex);
		mutex = NULL;
		if (MessageBoxW(GetForegroundWindow(), L"A different FIDO credential is saved for this application. "
			L"Replace the saved credential?", L"Replace FIDO Credential", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2)
			!= IDYES || !(mutex = cert_fido_cache_lock(sid))) goto out;
	}

	// Restore completed changes if a later value cannot be written.
	for (size_t i = 0; i < _countof(values); i++) {
		if (!key && !values[i].present) continue;
		LSTATUS rc = key ? RegSetKeyValueW(root, values[i].name, app, values[i].type, values[i].data, values[i].len) :
			RegDeleteKeyValueW(root, values[i].name, app);
		if (rc == ERROR_SUCCESS) continue;
		while (i-- > 0) {
			if (values[i].present)
				RegSetKeyValueW(root, values[i].name, app, values[i].type, values[i].old, values[i].old_len);
			else
				RegDeleteKeyValueW(root, values[i].name, app);
		}
		goto out;
	}
	success = TRUE;

out:
	if (root) RegCloseKey(root);
	if (mutex) cert_fido_cache_unlock(mutex);
	return success;
}

static BOOL cert_portable_copy_to_new_file(HKEY hSrc, LPCWSTR sPath)
{
	WCHAR sTempPath[MAX_PATH];
	HKEY hDst;
	BOOL bResult = FALSE;

	// A private hive name keeps concurrent exports independent.
	GUID id;
	LPCWSTR slash = wcsrchr(sPath, L'\\');
	size_t prefix = slash ? (size_t)(slash + 1 - sPath) : 0;
	if (prefix >= _countof(sTempPath) || FAILED(CoCreateGuid(&id))) return FALSE;
	wmemcpy(sTempPath, sPath, prefix);
	if (!StringFromGUID2(&id, sTempPath + prefix, (int)(_countof(sTempPath) - prefix))) return FALSE;

	if (RegLoadAppKeyW(sTempPath, &hDst, KEY_ALL_ACCESS, 0, 0) == ERROR_SUCCESS)
	{
		bResult = SHCopyKeyW(hSrc, NULL, hDst, 0) == ERROR_SUCCESS;
		RegCloseKey(hDst);
	}

	if (bResult) bResult = MoveFileExW(sTempPath, sPath, MOVEFILE_WRITE_THROUGH);
	if (!bResult) DeleteFileW(sTempPath);
	cert_portable_remove_logs(sTempPath);
	return bResult;
}

BOOL cert_portable_get_settings_path(WCHAR* sPath)
{
	DWORD iLen = GetModuleFileNameW(NULL, sPath, MAX_PATH);
	if (iLen == 0 || iLen >= MAX_PATH) return FALSE;
	WCHAR* sSlash = wcsrchr(sPath, L'\\');
	if (sSlash == NULL) return FALSE;
	sSlash[1] = L'\0';
	return cert_portable_append_settings(sPath);
}

BOOL cert_portable_settings_exists(void)
{
	WCHAR sPath[MAX_PATH];
	return cert_portable_find_settings(sPath);
}

BOOL cert_portable_export(void)
{
	WCHAR sPath[MAX_PATH];
	if (!cert_portable_get_settings_path(sPath)) return FALSE;
	if (cert_portable_settings_exists()) return FALSE;

	HKEY hSrc;
	if (RegOpenKeyExW(HKEY_CURRENT_USER, sPuttyRoot, 0, KEY_READ, &hSrc) != ERROR_SUCCESS)
		return FALSE;

	BOOL bResult = cert_portable_copy_to_new_file(hSrc, sPath);
	RegCloseKey(hSrc);
	return bResult;
}

BOOL cert_portable_import(void)
{
	HKEY hHive = NULL;
	BOOL bShouldClose = FALSE;

	if (!cert_portable_settings_exists()) return FALSE;

	if (cert_portable_enabled())
	{
		hHive = hPortableRoot;
	}
	else
	{
		WCHAR sPath[MAX_PATH];
		if (!cert_portable_find_settings(sPath)) return FALSE;
		if (RegLoadAppKeyW(sPath, &hHive, KEY_READ, 0, 0) != ERROR_SUCCESS) return FALSE;
		bShouldClose = TRUE;
	}

	HKEY hDst;
	DWORD dwDisp;
	BOOL bResult = FALSE;
	if (RegCreateKeyExW(HKEY_CURRENT_USER, sPuttyRoot, 0, NULL,
			REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hDst, &dwDisp) == ERROR_SUCCESS)
	{
		bResult = SHCopyKeyW(hHive, NULL, hDst, 0) == ERROR_SUCCESS;
		RegCloseKey(hDst);
	}

	if (bShouldClose)
		RegCloseKey(hHive);

	return bResult;
}

#endif /* PUTTY_CAC */

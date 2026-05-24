#ifdef PUTTY_CAC

#define CERT_PORTABLE_NO_REDEFINE

#include <windows.h>
#include <shlwapi.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "cert_portable.h"

static const WCHAR sPuttyRoot[] = L"Software\\SimonTatham";
static const WCHAR sSoftwareRoot[] = L"Software";

static INIT_ONCE oInitOnce = INIT_ONCE_STATIC_INIT;
static HKEY hPortableRoot = NULL;

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

	iLen = GetEnvironmentVariableW(L"USERPROFILE", sPath, MAX_PATH);
	if (iLen > 0 && iLen < MAX_PATH &&
		cert_portable_append_settings(sPath) &&
		cert_portable_file_exists(sPath))
		return TRUE;

	WCHAR sDrive[MAX_PATH], sHome[MAX_PATH];
	DWORD iDriveLen = GetEnvironmentVariableW(L"HOMEDRIVE", sDrive, _countof(sDrive));
	DWORD iHomeLen = GetEnvironmentVariableW(L"HOMEPATH", sHome, _countof(sHome));
	if (iDriveLen < _countof(sDrive) && iHomeLen > 0 && iHomeLen < _countof(sHome) &&
		iDriveLen + iHomeLen + strlen(CERT_PORTABLE_SETTINGS) + 2 < MAX_PATH)
	{
		wcscpy(sPath, iDriveLen ? sDrive : L"");
		wcscat(sPath, sHome);
		if (cert_portable_append_settings(sPath) &&
			cert_portable_file_exists(sPath))
			return TRUE;
	}

	return FALSE;
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
			DeleteFileW(sPath);
			RegLoadAppKeyW(sPath, &hPortableRoot, KEY_ALL_ACCESS, 0, 0);
		}
		else if (iStatus != ERROR_SUCCESS)
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

static BOOL cert_portable_temp_path(LPCWSTR sPath, WCHAR* sTempPath)
{
	size_t iLen = wcslen(sPath);
	if (iLen + 4 >= MAX_PATH) return FALSE;
	wcscpy(sTempPath, sPath);
	wcscat(sTempPath, L".tmp");
	return TRUE;
}

static BOOL cert_portable_replace_file(LPCWSTR sTempPath, LPCWSTR sPath)
{
	if (MoveFileExW(sTempPath, sPath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
		return TRUE;
	DeleteFileW(sTempPath);
	return FALSE;
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

LONG WINAPI cert_portable_RegCloseKey(HKEY hKey)
{
	return RegCloseKey(hKey);
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

LONG WINAPI cert_portable_RegEnumKeyW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, DWORD cchName)
{
	return RegEnumKeyW(hKey, dwIndex, lpName, cchName);
}

LONG WINAPI cert_portable_RegEnumKeyA(HKEY hKey, DWORD dwIndex, LPSTR lpName, DWORD cchName)
{
	return RegEnumKeyA(hKey, dwIndex, lpName, cchName);
}

LONG WINAPI cert_portable_RegEnumValueW(HKEY hKey, DWORD dwIndex, LPWSTR lpValueName,
	LPDWORD lpcchValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
	return RegEnumValueW(hKey, dwIndex, lpValueName, lpcchValueName, lpReserved,
		lpType, lpData, lpcbData);
}

LONG WINAPI cert_portable_RegEnumValueA(HKEY hKey, DWORD dwIndex, LPSTR lpValueName,
	LPDWORD lpcchValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
	return RegEnumValueA(hKey, dwIndex, lpValueName, lpcchValueName, lpReserved,
		lpType, lpData, lpcbData);
}

LONG WINAPI cert_portable_RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved,
	LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
	return RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

LONG WINAPI cert_portable_RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved,
	LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
	return RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

LONG WINAPI cert_portable_RegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved,
	DWORD dwType, const BYTE *lpData, DWORD cbData)
{
	return RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

LONG WINAPI cert_portable_RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved,
	DWORD dwType, const BYTE *lpData, DWORD cbData)
{
	return RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
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
	LPWSTR sSubKey, sValue;
	LONG iResult;

	if (!cert_portable_enabled())
		return RegGetValueA(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
	sSubKey = cert_portable_from_mb(lpSubKey);
	sValue = cert_portable_from_mb(lpValue);
	iResult = cert_portable_RegGetValueW(hkey, sSubKey, sValue, dwFlags, pdwType, pvData, pcbData);
	free(sSubKey);
	free(sValue);
	return iResult;
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
	LPWSTR sSubKey, sValueName;
	LONG iResult;

	if (!cert_portable_enabled())
		return RegSetKeyValueA(hKey, lpSubKey, lpValueName, dwType, lpData, cbData);
	sSubKey = cert_portable_from_mb(lpSubKey);
	sValueName = cert_portable_from_mb(lpValueName);
	iResult = cert_portable_RegSetKeyValueW(hKey, sSubKey, sValueName, dwType, lpData, cbData);
	free(sSubKey);
	free(sValueName);
	return iResult;
}

static BOOL cert_portable_copy_to_new_file(HKEY hSrc, LPCWSTR sPath)
{
	WCHAR sTempPath[MAX_PATH];
	HKEY hDst;
	BOOL bResult = FALSE;

	if (!cert_portable_temp_path(sPath, sTempPath)) return FALSE;
	DeleteFileW(sTempPath);

	if (RegLoadAppKeyW(sTempPath, &hDst, KEY_ALL_ACCESS, 0, 0) == ERROR_SUCCESS)
	{
		bResult = SHCopyKeyW(hSrc, NULL, hDst, 0) == ERROR_SUCCESS;
		RegCloseKey(hDst);
	}

	if (!bResult)
	{
		DeleteFileW(sTempPath);
		return FALSE;
	}

	return cert_portable_replace_file(sTempPath, sPath);
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

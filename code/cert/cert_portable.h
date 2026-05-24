#pragma once

#ifdef PUTTY_CAC

#include <windows.h>

#define CERT_PORTABLE_SETTINGS "putty.dat"

BOOL cert_portable_enabled(void);

LONG WINAPI cert_portable_RegOpenKeyA(HKEY hKey, LPCSTR lpSubKey,
	PHKEY phkResult);
LONG WINAPI cert_portable_RegOpenKeyW(HKEY hKey, LPCWSTR lpSubKey,
	PHKEY phkResult);
LONG WINAPI cert_portable_RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey,
	DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
LONG WINAPI cert_portable_RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey,
	DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
LONG WINAPI cert_portable_RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey,
	DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired,
	const LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult,
	LPDWORD lpdwDisposition);
LONG WINAPI cert_portable_RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey,
	DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired,
	const LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult,
	LPDWORD lpdwDisposition);
LONG WINAPI cert_portable_RegCloseKey(HKEY hKey);
LONG WINAPI cert_portable_RegDeleteKeyA(HKEY hKey, LPCSTR lpSubKey);
LONG WINAPI cert_portable_RegDeleteKeyW(HKEY hKey, LPCWSTR lpSubKey);
LONG WINAPI cert_portable_RegDeleteTreeA(HKEY hKey, LPCSTR lpSubKey);
LONG WINAPI cert_portable_RegDeleteTreeW(HKEY hKey, LPCWSTR lpSubKey);
LONG WINAPI cert_portable_RegDeleteKeyValueA(HKEY hKey, LPCSTR lpSubKey,
	LPCSTR lpValueName);
LONG WINAPI cert_portable_RegDeleteKeyValueW(HKEY hKey, LPCWSTR lpSubKey,
	LPCWSTR lpValueName);
LONG WINAPI cert_portable_RegEnumKeyA(HKEY hKey, DWORD dwIndex, LPSTR lpName,
	DWORD cchName);
LONG WINAPI cert_portable_RegEnumKeyW(HKEY hKey, DWORD dwIndex, LPWSTR lpName,
	DWORD cchName);
LONG WINAPI cert_portable_RegEnumValueA(HKEY hKey, DWORD dwIndex,
	LPSTR lpValueName, LPDWORD lpcchValueName, LPDWORD lpReserved,
	LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
LONG WINAPI cert_portable_RegEnumValueW(HKEY hKey, DWORD dwIndex,
	LPWSTR lpValueName, LPDWORD lpcchValueName, LPDWORD lpReserved,
	LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
LONG WINAPI cert_portable_RegQueryValueExA(HKEY hKey, LPCSTR lpValueName,
	LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
LONG WINAPI cert_portable_RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName,
	LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
LONG WINAPI cert_portable_RegSetValueExA(HKEY hKey, LPCSTR lpValueName,
	DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);
LONG WINAPI cert_portable_RegSetValueExW(HKEY hKey, LPCWSTR lpValueName,
	DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);
LONG WINAPI cert_portable_RegGetValueA(HKEY hkey, LPCSTR lpSubKey,
	LPCSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData,
	LPDWORD pcbData);
LONG WINAPI cert_portable_RegGetValueW(HKEY hkey, LPCWSTR lpSubKey,
	LPCWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData,
	LPDWORD pcbData);
LONG WINAPI cert_portable_RegSetKeyValueA(HKEY hKey, LPCSTR lpSubKey,
	LPCSTR lpValueName, DWORD dwType, LPCVOID lpData, DWORD cbData);
LONG WINAPI cert_portable_RegSetKeyValueW(HKEY hKey, LPCWSTR lpSubKey,
	LPCWSTR lpValueName, DWORD dwType, LPCVOID lpData, DWORD cbData);

BOOL cert_portable_get_settings_path(WCHAR* sPath);
BOOL cert_portable_settings_exists(void);
BOOL cert_portable_export(void);
BOOL cert_portable_import(void);

#ifndef CERT_PORTABLE_NO_REDEFINE

#undef RegOpenKey
#undef RegOpenKeyA
#undef RegOpenKeyW
#undef RegOpenKeyEx
#undef RegOpenKeyExA
#undef RegOpenKeyExW
#undef RegCreateKeyEx
#undef RegCreateKeyExA
#undef RegCreateKeyExW
#undef RegCloseKey
#undef RegDeleteKey
#undef RegDeleteKeyA
#undef RegDeleteKeyW
#undef RegDeleteTree
#undef RegDeleteTreeA
#undef RegDeleteTreeW
#undef RegDeleteKeyValue
#undef RegDeleteKeyValueA
#undef RegDeleteKeyValueW
#undef RegEnumKey
#undef RegEnumKeyA
#undef RegEnumKeyW
#undef RegEnumValue
#undef RegEnumValueA
#undef RegEnumValueW
#undef RegQueryValueEx
#undef RegQueryValueExA
#undef RegQueryValueExW
#undef RegSetValueEx
#undef RegSetValueExA
#undef RegSetValueExW
#undef RegGetValue
#undef RegGetValueA
#undef RegGetValueW
#undef RegSetKeyValue
#undef RegSetKeyValueA
#undef RegSetKeyValueW

#define RegOpenKeyA cert_portable_RegOpenKeyA
#define RegOpenKeyW cert_portable_RegOpenKeyW
#define RegOpenKeyExA cert_portable_RegOpenKeyExA
#define RegOpenKeyExW cert_portable_RegOpenKeyExW
#define RegCreateKeyExA cert_portable_RegCreateKeyExA
#define RegCreateKeyExW cert_portable_RegCreateKeyExW
#define RegCloseKey cert_portable_RegCloseKey
#define RegDeleteKeyA cert_portable_RegDeleteKeyA
#define RegDeleteKeyW cert_portable_RegDeleteKeyW
#define RegDeleteTreeA cert_portable_RegDeleteTreeA
#define RegDeleteTreeW cert_portable_RegDeleteTreeW
#define RegDeleteKeyValueA cert_portable_RegDeleteKeyValueA
#define RegDeleteKeyValueW cert_portable_RegDeleteKeyValueW
#define RegEnumKeyA cert_portable_RegEnumKeyA
#define RegEnumKeyW cert_portable_RegEnumKeyW
#define RegEnumValueA cert_portable_RegEnumValueA
#define RegEnumValueW cert_portable_RegEnumValueW
#define RegQueryValueExA cert_portable_RegQueryValueExA
#define RegQueryValueExW cert_portable_RegQueryValueExW
#define RegSetValueExA cert_portable_RegSetValueExA
#define RegSetValueExW cert_portable_RegSetValueExW
#define RegGetValueA cert_portable_RegGetValueA
#define RegGetValueW cert_portable_RegGetValueW
#define RegSetKeyValueA cert_portable_RegSetKeyValueA
#define RegSetKeyValueW cert_portable_RegSetKeyValueW

#ifdef UNICODE
#define RegOpenKey cert_portable_RegOpenKeyW
#define RegOpenKeyEx cert_portable_RegOpenKeyExW
#define RegCreateKeyEx cert_portable_RegCreateKeyExW
#define RegDeleteKey cert_portable_RegDeleteKeyW
#define RegDeleteTree cert_portable_RegDeleteTreeW
#define RegDeleteKeyValue cert_portable_RegDeleteKeyValueW
#define RegEnumKey cert_portable_RegEnumKeyW
#define RegEnumValue cert_portable_RegEnumValueW
#define RegQueryValueEx cert_portable_RegQueryValueExW
#define RegSetValueEx cert_portable_RegSetValueExW
#define RegGetValue cert_portable_RegGetValueW
#define RegSetKeyValue cert_portable_RegSetKeyValueW
#else
#define RegOpenKey cert_portable_RegOpenKeyA
#define RegOpenKeyEx cert_portable_RegOpenKeyExA
#define RegCreateKeyEx cert_portable_RegCreateKeyExA
#define RegDeleteKey cert_portable_RegDeleteKeyA
#define RegDeleteTree cert_portable_RegDeleteTreeA
#define RegDeleteKeyValue cert_portable_RegDeleteKeyValueA
#define RegEnumKey cert_portable_RegEnumKeyA
#define RegEnumValue cert_portable_RegEnumValueA
#define RegQueryValueEx cert_portable_RegQueryValueExA
#define RegSetValueEx cert_portable_RegSetValueExA
#define RegGetValue cert_portable_RegGetValueA
#define RegSetKeyValue cert_portable_RegSetKeyValueA
#endif

#endif /* CERT_PORTABLE_NO_REDEFINE */

#endif /* PUTTY_CAC */

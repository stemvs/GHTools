#pragma once

#include <string>
#include <Windows.h>

typedef HMODULE(WINAPI* fc_LoadLibraryA)(LPCSTR lpLibFileName);
typedef FARPROC(WINAPI* fc_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef BOOL(WINAPI* fc_DllEntry)(HMODULE hModule, DWORD dwReason, LPVOID lpReserved);

struct ManualMap {
	LPVOID hModule;
	LPVOID mData;
	size_t size;
	bool wait;
};

namespace ptools {
	struct MANUAL_MAP_DATA {
		fc_LoadLibraryA pLoadLibraryA;
		fc_GetProcAddress pGetProcAddress;
		HMODULE* hModule;
		bool* pUnload;
	};

	bool InitManualMap(HANDLE hProc, ManualMap* mMap);
	bool InjectLoadLibrary(HANDLE hProc, const std::wstring& dllPath);
	ManualMap* ManualMapDll(HANDLE hProc, const std::wstring& dllPath);
	void UnloadManualMap(HANDLE hProc, ManualMap* mMap);
}
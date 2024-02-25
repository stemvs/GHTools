#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

namespace ptools {
	DWORD GetProcessId(const std::wstring& procName) {
		DWORD procId = 0;
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnap != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32W pe32{ sizeof(pe32) };

			if (Process32FirstW(hSnap, &pe32)) {
				do {
					if (!lstrcmpi(pe32.szExeFile, procName.c_str())) {
						procId = pe32.th32ProcessID;
						break;
					}
				} while (Process32NextW(hSnap, &pe32));
			}
			CloseHandle(hSnap);
		}
		return procId;
	}
}
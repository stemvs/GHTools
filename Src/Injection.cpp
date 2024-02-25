#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <Windows.h>
#include "Injection.h"

#define PAGE_SIZE 0x1000

#define EXIT_WAIT 1

static LPVOID __inline GetLoadLibrary() {
	HMODULE hModule = GetModuleHandleW(L"KERNELBASE");

	if (hModule) {
		return GetProcAddress(hModule, "LoadLibraryW");
	}

	return 0;
}

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#ifdef _WIN64
#define CheckPEArchitecture(pFileHeader) pFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64
#else
#define CheckPEArchitecture(pFileHeader) pFileHeader->Machine != IMAGE_FILE_MACHINE_I386
#endif

DWORD WINAPI ShellCode(ptools::MANUAL_MAP_DATA* pMData) {
	auto* modBase = reinterpret_cast<byte*>(pMData->hModule);
	auto* pOptHeader = &reinterpret_cast<IMAGE_NT_HEADERS*>\
		(modBase + reinterpret_cast<IMAGE_DOS_HEADER*>(modBase)->e_lfanew)->OptionalHeader;

	auto pLoadLibraryA = pMData->pLoadLibraryA;
	auto pGetProcAddress = pMData->pGetProcAddress;
	
	auto pDllMain = reinterpret_cast<fc_DllEntry>\
		(modBase + pOptHeader->AddressOfEntryPoint);

	// address relocation
	auto deltaBase = reinterpret_cast<UINT_PTR>\
		(modBase) - pOptHeader->ImageBase;
	if (deltaBase) {
		if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>\
				(modBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

			while (pRelocData->VirtualAddress) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				auto* pRelativeInfo = reinterpret_cast<WORD*>\
					(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if (RELOC_FLAG(*pRelativeInfo)) {
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>\
							(modBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += deltaBase;
					}
				}

				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>\
					(reinterpret_cast<byte*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	// import dependencies
	if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>\
			(modBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDesc->Name) {
			auto szMod = reinterpret_cast<LPSTR>(modBase + pImportDesc->Name);
			auto hModule = pLoadLibraryA(szMod);
			auto* pThunkRef = reinterpret_cast<ULONG_PTR*>(modBase + pImportDesc->OriginalFirstThunk);
			auto* pFuncRef = reinterpret_cast<ULONG_PTR*>(modBase + pImportDesc->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = reinterpret_cast<ULONG_PTR>\
						(pGetProcAddress(hModule, reinterpret_cast<LPSTR>(*pThunkRef & 0xFFFF)));
				}
				else {
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(modBase + (*pThunkRef));
					*pFuncRef = reinterpret_cast<ULONG_PTR>(pGetProcAddress(hModule, pImport->Name));
				}
			}
			++pImportDesc;
		}
	}

	// tls callbacks
	if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>\
			(modBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallBack = reinterpret_cast<PIMAGE_TLS_CALLBACK*>\
			(pTLS->AddressOfCallBacks);

		for (; pCallBack && *pCallBack; ++pCallBack) {
			(*pCallBack)(modBase, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	HMODULE hModule = reinterpret_cast<HMODULE>(modBase);

	pDllMain(hModule, DLL_PROCESS_ATTACH, &pMData->pUnload);

	if (pMData->pUnload) {
		return EXIT_WAIT;
	}

	return EXIT_SUCCESS;
}

static std::vector<byte> GetBinaryFileBytes(const std::wstring& path) {
	std::ifstream file(path, std::ios::binary | std::ios::ate);
	std::vector<byte> data(0);

	if (!file.is_open()) {
		// todo: better error handling
		return data;
	}

	size_t fileSize = static_cast<size_t>(file.tellg());
	data.resize(fileSize);

	file.seekg(0, std::ios::beg);
	file.read(reinterpret_cast<char*>(data.data()), fileSize);
	file.close();

	return data;
}

bool ptools::InitManualMap(HANDLE hProc, ManualMap* mMap) {
	LPVOID pSCLoadAddr = VirtualAllocEx(hProc, nullptr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pSCLoadAddr)
		return false;

	WriteProcessMemory(hProc, pSCLoadAddr, ShellCode, PAGE_SIZE, nullptr);

	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pSCLoadAddr), mMap->mData, 0, nullptr);
	if (!hThread)
		return false;

	DWORD dwExitCode;

	WaitForSingleObject(hThread, INFINITE);
	GetExitCodeThread(hThread, &dwExitCode);
	CloseHandle(hThread);
	VirtualFreeEx(hProc, pSCLoadAddr, 0, MEM_RELEASE);

	switch (dwExitCode) {
	case EXIT_SUCCESS:
		break;
	case EXIT_WAIT:
		mMap->wait = true;
		break;
	default:
		return false;
	}

	return true;
}

bool ptools::InjectLoadLibrary(HANDLE hProc, const std::wstring& dllPath) {
	// allocate memory for dll path
	LPVOID pPath = VirtualAllocEx(hProc, nullptr, (dllPath.length() + 1) * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pPath)
		return false;

	LPVOID pLoadLibrary = GetLoadLibrary();
	// write dll path into allocated memory
	if (pLoadLibrary && WriteProcessMemory(hProc, pPath, dllPath.c_str(), (dllPath.length() + 1) * sizeof(wchar_t), nullptr)) {
		HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibrary), pPath, 0, nullptr);

		if (hThread) {
			DWORD dExitCode = 0;
			// wait for thread to exit
			WaitForSingleObject(hThread, INFINITE);
			GetExitCodeThread(hThread, &dExitCode);

			VirtualFreeEx(hProc, pPath, 0, MEM_RELEASE);
			CloseHandle(hThread);

			return true;
		}
	}
	return false;
}

ManualMap* ptools::ManualMapDll(HANDLE hProc, const std::wstring& dllPath) {
	std::vector<byte> data = GetBinaryFileBytes(dllPath);
	if (data.size() == 0) {
		std::cout << "could not open file...\n";
		return nullptr;
	}

	byte* pData = data.data();

	// check dos magic
	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_magic != 0x5A4D) {
		std::cout << "missing mz signature\n";
		return nullptr;
	}

	IMAGE_NT_HEADERS* pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(pData + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew);
	IMAGE_OPTIONAL_HEADER* pOptHeader = &pNtHeaders->OptionalHeader;
	IMAGE_FILE_HEADER* pFileHeader = &pNtHeaders->FileHeader;

	if (CheckPEArchitecture(pFileHeader)) {
		return nullptr;
	}

	MANUAL_MAP_DATA mData{ 0 };

	// try to load at desired address
	byte* pLoadAddr = reinterpret_cast<byte*>(VirtualAllocEx(hProc, reinterpret_cast<LPVOID>(pOptHeader->ImageBase), pOptHeader->SizeOfImage + sizeof(mData), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pLoadAddr) {
		std::cout << "could not allocate at desired address...\n";
		pLoadAddr = reinterpret_cast<byte*>(VirtualAllocEx(hProc, nullptr, pOptHeader->SizeOfImage + sizeof(mData), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!pLoadAddr) {
			std::cout << "could not allocate memory for module\n";
			return nullptr;
		}
	}

	mData.pLoadLibraryA = LoadLibraryA;
	mData.pGetProcAddress = GetProcAddress;
	mData.hModule = reinterpret_cast<HMODULE*>(pLoadAddr);

	WriteProcessMemory(hProc, pLoadAddr, pData, PAGE_SIZE, nullptr);
	WriteProcessMemory(hProc, pLoadAddr + pOptHeader->SizeOfImage, &mData, sizeof(mData), nullptr);


	// map sections
	auto* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	for (auto i = 0; i != pFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData) {
			if (!WriteProcessMemory(hProc, pLoadAddr + pSectionHeader->VirtualAddress, pData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
				std::cout << "could not map section..." << pSectionHeader->Name << std::endl;

				VirtualFreeEx(hProc, pLoadAddr, 0, MEM_RELEASE);
				return nullptr;
			}
		}
	}

	auto* mMap = new ManualMap;

	mMap->hModule = pLoadAddr;
	mMap->mData = pLoadAddr + pOptHeader->SizeOfImage;
	mMap->size = pOptHeader->SizeOfImage + sizeof(mData);

	return mMap;
}

void ptools::UnloadManualMap(HANDLE hProc, ManualMap* mMap)
{
	VirtualFreeEx(hProc, mMap->hModule, 0, MEM_RELEASE);
}

#include <Windows.h>
#include <vector>
#include "Memory.h"

namespace mtools {
	byte* FindDMAAddy(byte* baseAddr, std::vector<uintptr_t> offsets) {
		byte* addr = baseAddr;
		for (std::vector<uintptr_t>::size_type i = 0; i < offsets.size(); i++) {
			addr = *reinterpret_cast<byte**>(addr) + offsets[i];
		}
		return addr;
	}

	byte* FindDMAAddy(HANDLE hProc, byte* baseAddr, std::vector<uintptr_t> offsets) {
		byte* addr = baseAddr;

		for (std::vector<uintptr_t>::size_type i = 0; i < offsets.size(); i++) {
			ReadProcessMemory(hProc, addr, &addr, sizeof(addr), nullptr);
			addr += offsets[i];
		}

		return addr;
	}

	void Patch(byte* dst, byte* src, size_t size) {
		DWORD oldP;
		VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldP);
		memcpy(dst, src, size);
		VirtualProtect(dst, size, oldP, &oldP);
	}

	void Patch(HANDLE hProc, byte* dst, byte* src, size_t size) {
		DWORD oldP;
		VirtualProtectEx(hProc, dst, size, PAGE_EXECUTE_READWRITE, &oldP);
		WriteProcessMemory(hProc, dst, src, size, nullptr);
		VirtualProtectEx(hProc, dst, size, oldP, &oldP);
	}

	void Nop(byte* dst, size_t size) {
		byte* nops = new byte[size];
		memset(nops, 0x90, size);
		Patch(dst, nops, size);
		delete[] nops;
	}

	void Nop(HANDLE hProc, byte* dst, size_t size) {
		byte* nops = new byte[size];
		memset(nops, 0x90, size);
		Patch(hProc, dst, nops, size);
		delete[] nops;
	}
}
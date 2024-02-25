#pragma once

#include <vector>
#include <Windows.h>

namespace mtools {
	byte* FindDMAAddy(byte* baseAddr, std::vector<uintptr_t> offsets);
	byte* FindDMAAddy(HANDLE hProc, byte* baseAddr, std::vector<uintptr_t> offsets);
	void Patch(byte* dst, byte* src, size_t size);
	void Patch(HANDLE hProc, byte* dst, byte* src, size_t size);
	void Nop(byte* dst, size_t size);
	void Nop(HANDLE hProc, byte* dst, size_t size);
}
#include <Windows.h>
#include "Memory.h"
#include "Hooking.h"

namespace htools {
#ifndef _WIN64
	bool Detour(byte* pFrom, byte* pTo, size_t size) {
		if (size < 5) {
			return false;
		}

		byte* detour = new byte[size];

		if (size > 5) {
			memset(detour + 5, 0x90, size - 5);
		}

		*detour = 0xE9; // JMP rel32
		*reinterpret_cast<DWORD*>(detour + 1) = pTo - pFrom - 5;

		mtools::Patch(pFrom, detour, size);

		delete[] detour;
		return true;
	}

	byte* Trampoline::Hook(byte* pFrom, byte* pTo, size_t size) {
		if (hooked || size < 5) {
			return 0;
		}

		gateway = reinterpret_cast<byte*>(VirtualAlloc(nullptr, size + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (gateway) {
			memcpy(gateway, pFrom, size);
			gateway[size] = 0xE9; // JMP rel32
			*reinterpret_cast<DWORD*>(gateway + size + 1) = pFrom - gateway - 5;

			if (Detour(pFrom, pTo, size)) {
				m_original = pFrom;
				m_size = size;
				hooked = true;
				return gateway;
			}

			VirtualFree(gateway, 0, MEM_RELEASE);
		}

		return 0;
	}
#else
	bool Detour(byte* pFrom, byte* pTo, size_t size) {
		if (size < 12) {
			return false;
		}
		byte* detour = new byte[size];

		if (size > 12) {
			memset(detour + 12, 0x90, size - 12);
		}
		*reinterpret_cast<WORD*>(detour) = 0xB848; // 48 B8 MOV RAX, $QWORD
		*reinterpret_cast<UINT_PTR*>(detour + 2) = reinterpret_cast<UINT_PTR>(pTo);
		*reinterpret_cast<WORD*>(detour + 10) = 0xE0FF; // FF E0 JMP RAX

		mtools::Patch(pFrom, detour, size);

		delete[] detour;
		return true;
	}

	byte* Trampoline::Hook(byte* pFrom, byte* pTo, size_t size) {
		if (hooked || size < 12) {
			return 0;
		}

		gateway = reinterpret_cast<byte*>(VirtualAlloc(nullptr, size + 12, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (gateway) {
			memcpy(gateway, pFrom, size);
			*reinterpret_cast<WORD*>(gateway) = 0xB848; // 48 B8 MOV RAX, $
			*reinterpret_cast<UINT_PTR*>(gateway + 2) = reinterpret_cast<UINT_PTR>(pFrom) + size;
			*reinterpret_cast<WORD*>(gateway + 10) = 0xE0FF; // FF E0 JMP RAX

			if (Detour(pFrom, pTo, size)) {
				m_original = pFrom;
				m_size = size;
				hooked = true;
				return gateway;
			}

			VirtualFree(gateway, 0, MEM_RELEASE);
		}

		return 0;
	}
#endif


	void Trampoline::Unhook() {
		if (hooked) {
			VirtualFree(gateway, 0, MEM_RELEASE);
			mtools::Patch(m_original, gateway, m_size);
			hooked = false;
		}
	}
}
#pragma once

#include <Windows.h>


namespace htools {
	bool Detour(byte* pFrom, byte* pTo, size_t size);

	class Trampoline {
		byte* m_original = 0;
		size_t m_size = 0;
	public:
		bool hooked = 0;
		byte* gateway = 0;
	public:
		byte* Hook(byte* pFrom, byte* pTo, size_t size);
		void Unhook();

		~Trampoline() {
			Unhook();
		}
	};
}
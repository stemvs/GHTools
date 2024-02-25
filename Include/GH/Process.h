#pragma once

#include <iostream>
#include <Windows.h>

namespace ptools {
	DWORD GetProcessId(const std::wstring& procName);
}
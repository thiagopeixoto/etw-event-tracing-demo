#pragma once

#include <Windows.h>
#include <tdh.h>
#include <memory>
#include <vector>
#include <string>
#include <atltime.h>
#include <assert.h>
#include <in6addr.h>

#pragma comment(lib, "tdh")

#ifndef _WIN32
typedef struct _GUID {
	uint32_t Data1;
	uint16_t Data2;
	uint16_t Data3;
	uint8_t Data4[8];
} GUID;
#endif

GUID StringToGuid(const std::string& str);
bool RunSession(const std::vector<GUID>& providers);
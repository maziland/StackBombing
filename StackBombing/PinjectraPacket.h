#pragma once

// Standard Include's
#include <map>
#include <string>
#include <iostream>

#include <windows.h>

// Data Types
typedef std::map<std::string, DWORD64> TStrDWORD64Map;
typedef std::pair<std::string, DWORD64> TStrDWORD64Pair;

typedef struct {
	LPVOID buffer;
	SIZE_T buffer_size;
	TStrDWORD64Map* metadata;
} PINJECTRA_PACKET;


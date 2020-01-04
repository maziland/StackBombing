#pragma once
#include<windows.h>
#include<TlHelp32.h>

typedef struct {
	HANDLE process;
	HANDLE thread;
	DWORD pid;
	DWORD tid;
} TARGET_PROCESS;

DWORD* ListProcessThreads(DWORD dwOwnerPID);

DWORD NameToPID(WCHAR* pProcessName);

BOOL GetVersionOs(OSVERSIONINFOEX* os);

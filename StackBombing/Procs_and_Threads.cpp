#define UNICODE
#include<windows.h>
#include<TlHelp32.h>


typedef void (WINAPI* RtlGetVersion_FUNC) (OSVERSIONINFOEXW*);

BOOL GetVersionOs(OSVERSIONINFOEX* os)
{
	HMODULE hMod;
	RtlGetVersion_FUNC func;
#ifdef UNICODE
	OSVERSIONINFOEXW* osw = os;
#else
	OSVERSIONINFOEXW o;
	OSVERSIONINFOEXW* osw = &o;
#endif

	hMod = LoadLibrary(L"ntdll");
	if (hMod)
	{
		func = (RtlGetVersion_FUNC)GetProcAddress(hMod, "RtlGetVersion");
		if (func == 0)
		{
			FreeLibrary(hMod);
			return FALSE;
		}
		ZeroMemory(osw, sizeof(*osw));
		osw->dwOSVersionInfoSize = sizeof(*osw);
		func(osw);
#ifndef UNICODE
		os->dwBuildNumber = osw->dwBuildNumber;
		os->dwMajorVersion = osw->dwMajorVersion;
		os->dwMinorVersion = osw->dwMinorVersion;
		os->dwPlatformId = osw->dwPlatformId;
		os->dwOSVersionInfoSize = sizeof(*os);
		DWORD sz = sizeof(os->szCSDVersion);
		WCHAR* src = osw->szCSDVersion;
		unsigned char* dtc = (unsigned char*)os->szCSDVersion;
		while (*src)
			*dtc++ = (unsigned char)*src++;
		*dtc = '\ 0';
#endif

	}
	else
		return FALSE;
	FreeLibrary(hMod);
	return TRUE;
}

DWORD* ListProcessThreads(DWORD dwOwnerPID)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	DWORD i = 0;
	DWORD* threads = (DWORD*)malloc(1000*sizeof(DWORD));
	ZeroMemory(&te32, sizeof(THREADENTRY32));

	// Take a snapshot of all running threads  
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Now walk the thread list of the system,
	// and display information about each thread
	// associated with the specified process
	do
	{
		if (te32.th32OwnerProcessID == dwOwnerPID) {
			threads[i++] = te32.th32ThreadID;
		}
	} while (Thread32Next(hThreadSnap, &te32));
	threads[i] = 0xcafebabe;
	//  Don't forget to clean up the snapshot object.
	CloseHandle(hThreadSnap);
	return threads;
}

DWORD NameToPID(WCHAR *pProcessName)
{
	HANDLE hSnap = INVALID_HANDLE_VALUE;
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	PROCESSENTRY32W ProcessStruct;
	ProcessStruct.dwSize = sizeof(PROCESSENTRY32W);
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
		return -1;
	if (Process32FirstW(hSnap, &ProcessStruct) == FALSE)
		return -1;
	do
	{
		if (wcscmp((WCHAR*)(ProcessStruct.szExeFile), pProcessName) == 0)
		{
			CloseHandle(hSnap);
			return  ProcessStruct.th32ProcessID;
			break;
		}
	} while (Process32NextW(hSnap, &ProcessStruct));
	CloseHandle(hSnap);
	return -1;
}



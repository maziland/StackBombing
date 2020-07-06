#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "Inject_and_Resume.h"
#include "Procs_and_Threads.h"

int main(int argc, char* argv[])
{
	//WCHAR procName[] = L"TestProcess.exe";
	WinExec("C:\\Windows\\System32\\notepad.exe", SW_SHOW);
	WCHAR procName[] = L"notepad.exe";

	DWORD pid = NameToPID((WCHAR*)procName);
	DWORD* threads = ListProcessThreads(pid);

	for (int i = 0; i < 10; i++)
	{
		inject(pid, threads[i]);
		Sleep(300);
	}
	
	free(threads);

	system("pause");
	return 0;
}
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "Inject_and_Resume.h"
#include "Procs_and_Threads.h"

int main(int argc, char* argv[])
{
	WCHAR procName[] = L"TestProcess.exe";  

	DWORD pid = NameToPID((WCHAR*)procName);
	DWORD* threads = ListProcessThreads(pid);
	DWORD tid = threads[0];
	free(threads);

	inject(pid, tid);
	//LOLLLLLLA
	return 0;
}
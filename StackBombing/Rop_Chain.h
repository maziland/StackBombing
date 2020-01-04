#pragma once

// Standard Include's
//#include <psapi.h>
#include <map>
#include <string>
#include <iostream>

// Local Include's
#include "PinjectraPacket.h"
#include "Procs_and_Threads.h"

PINJECTRA_PACKET* BuildPayload(TStrDWORD64Map& runtime_parameters);
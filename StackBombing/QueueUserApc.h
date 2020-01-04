#pragma once

// Local Include's
#include "WritingTechniques.h"

// Classes
class CodeViaQueueUserAPC :
	public ExecutionTechnique
{
public:
	// Constructor & Destructor
	CodeViaQueueUserAPC(SimpleMemoryWriter* memwriter)
		:m_memwriter(memwriter) { }
	~CodeViaQueueUserAPC();

	// Methods
	BOOL inject(DWORD pid, DWORD tid);

protected:
	// Members
	SimpleMemoryWriter* m_memwriter;
};


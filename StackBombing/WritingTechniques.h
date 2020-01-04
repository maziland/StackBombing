#pragma once

// Standard Include's
#include <iostream>
#include <map>
#include<string.h>

#include<windows.h>

// Local Include's
#include "PinjectraPacket.h"
#include "DynamicPayloads.h"

// Data Types
typedef struct {
	HANDLE process;
	HANDLE thread;
	LPVOID addr;
	LPVOID entry_point;
	SIZE_T tot_write;
	SIZE_T tot_alloc;
} RUNTIME_MEM_ENTRY;

typedef struct {
	HANDLE process;
	HANDLE thread;
	DWORD pid;
	DWORD tid;
} TARGET_PROCESS;

////////////////////
// Writer Classes //
////////////////////

class SimpleMemoryWriter
{
public:
	virtual RUNTIME_MEM_ENTRY* write(DWORD pid, DWORD tid) = 0;
};

class AdvanceMemoryWriter
{
public:
	virtual RUNTIME_MEM_ENTRY* writeto(HANDLE process_handle, SIZE_T additional_mem_space) = 0;
};

class ComplexMemoryWriter
{
public:
	virtual PINJECTRA_PACKET* eval_and_write(TARGET_PROCESS* target, TStrDWORD64Map* params) = 0;
};

// Base Class
class MutableAdvanceMemoryWriter :
	public AdvanceMemoryWriter
{
public:
	void* GetBuffer(void) const { return(m_buf); };
	void SetBuffer(void* buf) { m_buf = buf; };
	size_t GetBufferSize(void) const { return(m_nbyte); };
	void SetBufferSize(size_t nbyte) { m_nbyte = nbyte; };

protected:
	void* m_buf;
	size_t m_nbyte;
};

/////////////////////
// Adapter Classes //
/////////////////////

class ComplexToMutableAdvanceMemoryWriter :
	public ComplexMemoryWriter
{
public:
	// Constructor & Destructor
	ComplexToMutableAdvanceMemoryWriter(DynamicPayload* payload, MutableAdvanceMemoryWriter* writer) :
		m_payload(payload),
		m_writer(writer) { }
	~ComplexToMutableAdvanceMemoryWriter();

	// Methods
	PINJECTRA_PACKET* eval_and_write(TARGET_PROCESS* target, TStrDWORD64Map& params);

protected:
	// Members
	DynamicPayload* m_payload;
	MutableAdvanceMemoryWriter* m_writer;
};
class ExecutionTechnique
{
public:
	virtual BOOL inject(DWORD pid, DWORD tid) = 0;
};

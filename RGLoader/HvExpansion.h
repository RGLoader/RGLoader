#ifndef HVEXPANSION_H
#define HVEXPANSION_H
#include "stdafx.h"
//#include "xecrypt.h"
#include <xstring>

using namespace std;

#define EXPANSION_SIG 'HVPP'
#define EXPANSION_INST_SC 0x70
#define EXPANSION_CALL_SC 0x71
#define STATUS_MEMORY_NOT_ALLOCATED ((NTSTATUS)0xC00000A0)

typedef enum {
	PeekBYTE  = 0,
	PeekWORD  = 1,
	PeekDWORD = 2,
	PeekQWORD = 3,
	PeekBytes = 4,
	PokeBYTE  = 5,
	PokeWORD  = 6,
	PokeDWORD = 7,
	PokeQWORD = 8,
	PokeBytes = 9,
	PeekSPR   = 0xA,
	HvExecute = 0xC
};

BYTE HvPeekBYTE(QWORD Address);
WORD HvPeekWORD(QWORD Address);
DWORD HvPeekDWORD(QWORD Address);
QWORD HvPeekQWORD(QWORD Address);
NTSTATUS HvPeekBytes(QWORD Address, PVOID Buffer, DWORD Size);
NTSTATUS HvPokeBYTE(QWORD Address, BYTE Value);
NTSTATUS HvPokeWORD(QWORD Address, WORD Value);
NTSTATUS HvPokeDWORD(QWORD Address, DWORD Value);
NTSTATUS HvPokeQWORD(QWORD Address, QWORD Value);
NTSTATUS HvPokeBytes(QWORD Address, const void* Buffer, DWORD Size);
QWORD HvReadFuseRow(int row);
DWORD InstallExpansion();
BOOL DisableExpansionInstalls();
BOOL DisableShadowbooting();
BOOL LaunchXELL(LPCSTR path);
BOOL LoadApplyHV(const char* filepath);
BOOL LoadKeyVault(const char* filepath);

#endif


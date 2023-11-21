#pragma once

#define EXPANSION_SIG 'HVPP'
#define EXPANSION_SIZE 0x1000

#define EXPANSION_INST_SC 0x70
#define EXPANSION_CALL_SC 0x71
#define SET_STATE_SC      0x7B

typedef enum {
	PeekBYTE  = 0,
	PeekWORD  = 1,
	PeekDWORD = 2,
	PeekQWORD = 3,
	PeekBytes = 4,
	PeekSPR   = 0xA,
	PeekMSR   = 0xB,

	PokeBYTE  = 5,
	PokeWORD  = 6,
	PokeDWORD = 7,
	PokeQWORD = 8,
	PokeBytes = 9,

	PeekBYTEBypass = 0xC,
	PeekWORDBypass = 0xD,
	PeekDWORDBypass = 0xE,
	PeekQWORDBypass = 0xF,
	PeekBytesBypass = 0x10,

	PokeBYTEBypass  = 0x11,
	PokeWORDBypass  = 0x12,
	PokeDWORDBypass = 0x13,
	PokeQWORDBypass = 0x14,
	PokeBytesBypass = 0x15,
};

// syscalls
DWORD HvxExpansionInstall(QWORD addr, DWORD size);
QWORD HvxExpansionCall(DWORD sig, QWORD Arg1, QWORD Arg2, QWORD Arg3, QWORD Arg4);
QWORD HvxSetState(DWORD mode);

BYTE HvPeekBYTE(QWORD Address);
WORD HvPeekWORD(QWORD Address);
DWORD HvPeekDWORD(QWORD Address);
QWORD HvPeekQWORD(QWORD Address);
NTSTATUS HvPeekBytes(QWORD Address, PVOID Buffer, DWORD Size);
NTSTATUS HvPokeBYTE(QWORD Address, BYTE Value);
NTSTATUS HvPokeWORD(QWORD Address, WORD Value);
NTSTATUS HvPokeDWORD(QWORD Address, DWORD Value);
NTSTATUS HvPokeQWORD(QWORD Address, QWORD Value);
NTSTATUS HvPokeBytes(QWORD Address, PVOID Buffer, DWORD Size);
QWORD HvReadFuseRow(int row);
void HvReadCpuKey(PBYTE pbCpuKey);
DWORD InstallExpansions();
BOOL InstallSC0();
BOOL DumpExpansions();
BOOL DumpHV();
BOOL DisableExpansionInstalls();
BOOL DisableShadowbooting();
BOOL LoadApplyHV(const char* filepath);
BOOL LoadKeyVault(const char* filepath);


#pragma once

const char RPCAddr[] = "0.0.0.0";
const WORD RPCPort = 10101;
const DWORD RPCBufferSize = 2048;

#define RPCDebug TRUE
#if RPCDebug == TRUE
#define RPCDebugPrint RGLPrint
#else
#define RPCDebugPrint __noop
#endif

typedef enum {
	RPCPeekBYTE  = 0,
	RPCPeekWORD  = 1,
	RPCPeekDWORD = 2,
	RPCPeekQWORD = 3,
	RPCPeekBytes = 4,

	RPCPokeBYTE  = 5,
	RPCPokeWORD  = 6,
	RPCPokeDWORD = 7,
	RPCPokeQWORD = 8,
	RPCPokeBytes = 9,
	RPCPeekSPR   = 0xA,
	RPCHvExecute = 0xC,

	RPCGetModuleProcedureAddress = 0xD,
	RPCPerformCall = 0xE,
	RPCListModules = 0xF,
	RPCReboot = 0x10,
	RPCShutdown = 0x11
};

BOOL RPCServerStartup();
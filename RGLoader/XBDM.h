#pragma once

/*
FGetCounterValue -> 91f2a5a0
FGetImageAndDrive -> 91f44620
FGetNamedDwParam -> 91f41b38
FGetNotifySz -> 91f391f8
FGetOption -> 91f2d670

BOOL PchGetParam(LPCSTR szCommand, LPCSTR szName, BOOL bDefault) -> 0x91F41650
BOOL FGetSzParam(LPCSTR szCommand, LPCSTR szName, LPCSTR szOut, DWORD dwMaxSize) -> 0x91F41898
BOOL FGetDwParam(LPCSTR szCommand, LPCSTR szName, PDWORD pdwOut) -> 0x91F418F0
BOOL FGetQwordParam(LPCSTR szCommand, LPCSTR szName, PQWORD pqwOut) -> 0x91F41978

int SgnCompareRgch(const char* sz1, const char* sz2, int cch);
BOOL FEqualRgch(const char* sz1, const char* sz2, int cch);
DWORD DwHexFromSz(LPCSTR sz, LPCSTR* szOut);
DWORD DwFromSz(LPCSTR sz, int* pcchUsed);
const char* PchGetParam(LPCSTR szCmd, LPCSTR szKey, BOOL fNeedValue);
void GetParam(LPCSTR szLine, LPSTR szBuf, int cchBuf);
BOOL FGetSzParam(LPCSTR szLine, LPCSTR szKey, LPSTR szBuf, int cchBuf);
BOOL FGetDwParam(LPCSTR szLine, LPCSTR szKey, DWORD* pdw);
BOOL FGetQwordParam(LPCSTR szLine, LPCSTR szKey, ULARGE_INTEGER* plu) ;
BOOL FGetNamedDwParam(LPCSTR szLine, LPCSTR szKey, DWORD* pdw, LPSTR szResp);
*/

typedef enum {
	PEEK_BYTE = 0,
	PEEK_WORD,
	PEEK_DWORD,
	PEEK_QWORD,
	PEEK_BYTES,

	POKE_BYTE,
	POKE_WORD,
	POKE_DWORD,
	POKE_QWORD,
	POKE_BYTES
} PEEK_POKE_TYPE;

typedef struct {
	PEEK_POKE_TYPE pt;
	QWORD qwAddress;
	DWORD dwSize;
} PeekPokeDataStruct, *PPeekPokeDataStruct;

typedef struct {
	DWORD dwSize;
} HVExpStruct, *PHVExpStruct;

typedef struct _FileDataStruct {
	DWORD dwSize;
	PVOID pvAlloc;
	DWORD dwPosition;

	~_FileDataStruct() {
		if (pvAlloc) {
			dwSize = 0;
			dwPosition = 0;
			XPhysicalFree(pvAlloc);
			pvAlloc = NULL;
		}
	}

	PVOID GetAllocPosition() {
		return (PBYTE)pvAlloc + dwPosition;
	}
} FileDataStruct, *PFileDataStruct;

HRESULT __stdcall HrRGL(LPCSTR szCommand, LPSTR szResponse, DWORD cchResponse, PDM_CMDCONT pdmcc);

#include "stdafx.h"

#pragma region Functions
BOOL GetParam(LPCSTR szCommand, LPCSTR szName, DWORD dwSize) {
	return RGLoader->Offsets->XBDM->GetParam->Call<BOOL>(szCommand, szName, dwSize);
}

BOOL PchGetParam(LPCSTR szCommand, LPCSTR szName, BOOL bRequired) {
	return RGLoader->Offsets->XBDM->PchGetParam->Call<BOOL>(szCommand, szName, bRequired);
}

BOOL FGetSzParam(LPCSTR szCommand, LPCSTR szName, LPCSTR szOut, DWORD dwMaxSize) {
	return RGLoader->Offsets->XBDM->FGetSzParam->Call<BOOL>(szCommand, szName, szOut, dwMaxSize);
}

BOOL FGetDwParam(LPCSTR szCommand, LPCSTR szName, PDWORD pdwOut) {
	return RGLoader->Offsets->XBDM->FGetDwParam->Call<BOOL>(szCommand, szName, pdwOut);
}

BOOL FGetNamedDwParam(LPCSTR szCommand, LPCSTR szName, PDWORD pdwOut) {
	return RGLoader->Offsets->XBDM->FGetNamedDwParam->Call<BOOL>(szCommand, szName, pdwOut);
}

BOOL FGetQwordParam(LPCSTR szCommand, LPCSTR szName, PQWORD pqwOut) {
	return RGLoader->Offsets->XBDM->FGetQwordParam->Call<BOOL>(szCommand, szName, pqwOut);
}
#pragma endregion Functions

#pragma region HV Peek
HRESULT __stdcall HrHvPeek(PDM_CMDCONT pdmcc, LPSTR szResponse, DWORD cchResponse) {
	PPeekPokeDataStruct ppds = (PPeekPokeDataStruct)pdmcc->CustomData;

	if (pdmcc->BytesRemaining == 0) {
		delete ppds;
		XPhysicalFree(pdmcc->Buffer);
		return XBDM_ENDOFLIST;
	}

	if(ppds->pt == PEEK_BYTE) {
		pdmcc->DataSize = sizeof(BYTE);
		*(PBYTE)pdmcc->Buffer = HvPeekBYTE(ppds->qwAddress);
	} else if(ppds->pt == PEEK_WORD) {
		pdmcc->DataSize = sizeof(WORD);
		*(PWORD)pdmcc->Buffer = HvPeekWORD(ppds->qwAddress);
	} else if(ppds->pt == PEEK_DWORD) {
		pdmcc->DataSize = sizeof(DWORD);
		*(PDWORD)pdmcc->Buffer = HvPeekDWORD(ppds->qwAddress);
	} else if(ppds->pt == PEEK_QWORD) {
		pdmcc->DataSize = sizeof(QWORD);
		*(PQWORD)pdmcc->Buffer = HvPeekQWORD(ppds->qwAddress);
	} else if(ppds->pt == PEEK_BYTES) {
		pdmcc->DataSize = ppds->dwSize;
		HvPeekBytes(ppds->qwAddress, pdmcc->Buffer, pdmcc->DataSize);
	}

	pdmcc->BytesRemaining = 0;

	return XBDM_NOERR;
}
#pragma endregion HV Peek

#pragma region HV Poke
HRESULT __stdcall HrHvPoke(PDM_CMDCONT pdmcc, LPSTR szResponse, DWORD cchResponse) {
	PPeekPokeDataStruct ppds = (PPeekPokeDataStruct)pdmcc->CustomData;

	if (pdmcc->DataSize) {  // consume received data for poke
		if (ppds->pt == POKE_BYTE) {
			BYTE bVal = *(PBYTE)pdmcc->Buffer;
			HvPokeBYTE(ppds->qwAddress, bVal);
		} else if (ppds->pt == POKE_WORD) {
			WORD wVal = *(PWORD)pdmcc->Buffer;
			HvPokeWORD(ppds->qwAddress, wVal);
		} else if (ppds->pt == POKE_DWORD) {
			DWORD dwVal = *(PDWORD)pdmcc->Buffer;
			HvPokeDWORD(ppds->qwAddress, dwVal);
		} else if (ppds->pt == POKE_QWORD) {
			QWORD qwVal = *(PQWORD)pdmcc->Buffer;
			HvPokeQWORD(ppds->qwAddress, qwVal);
		} else if (ppds->pt == POKE_BYTES) {
			HvPokeBytes(ppds->qwAddress, pdmcc->Buffer, ppds->dwSize);
		}

		pdmcc->BytesRemaining -= pdmcc->DataSize;
	} else
		pdmcc->BytesRemaining = 0;

	if (pdmcc->BytesRemaining == 0) {
		delete ppds;
		XPhysicalFree(pdmcc->Buffer);
		return XBDM_ENDOFLIST;
	}

	return XBDM_NOERR;
}
#pragma endregion HV Poke

#pragma region Expansion
HRESULT __stdcall HrHvExpInst(PDM_CMDCONT pdmcc, LPSTR szResponse, DWORD cchResponse) {
	PHVExpStruct phvexp = (PHVExpStruct)pdmcc->CustomData;

	if (!pdmcc->BytesRemaining) {
		delete phvexp;
		free(pdmcc->Buffer);
		return XBDM_ENDOFLIST;
	}

	if (pdmcc->DataSize) {  // consume received data for poke
		pdmcc->BytesRemaining -= pdmcc->DataSize;

		RGLPrint("HrHvExpInst", "0x%X\n", phvexp->dwSize);

		PBYTE pbAlloc = (PBYTE)XPhysicalAlloc(0x1000, MAXULONG_PTR, 0, PAGE_READWRITE);
		memset(pbAlloc, 0, 0x1000);
		memcpy(pbAlloc, pdmcc->Buffer, phvexp->dwSize);
		DWORD dwRet = HvxExpansionInstall((QWORD)MmGetPhysicalAddress(pbAlloc), 0x1000);
		XPhysicalFree(pbAlloc);
	}

	return XBDM_NOERR;
}
#pragma endregion HV Poke

HRESULT __stdcall HrShadowBoot(PDM_CMDCONT pdmcc, LPSTR szResponse, DWORD cchResponse) {
	PFileDataStruct pFile = (PFileDataStruct)pdmcc->CustomData;

	if (pdmcc->DataSize) {  // consume received data for shadowboot
		pFile->dwPosition = pFile->dwSize - pdmcc->BytesRemaining;

		memcpy((PBYTE)pFile->GetAllocPosition(), pdmcc->Buffer, pdmcc->DataSize);

		pdmcc->BytesRemaining -= pdmcc->DataSize;
	}

	if (!pdmcc->BytesRemaining) {
		RGLPrint("HrShadowBoot", "Shadowbooting...\n");

		RGLoader->Offsets->KERNEL->KiShadowBoot->Call<void>(MmGetPhysicalAddress(pFile->pvAlloc), pFile->dwSize, 0x200);

		// this code should never run!
		delete pFile;
		if (pdmcc->Buffer) {
			XPhysicalFree(pdmcc->Buffer);
			pdmcc->Buffer = NULL;
		}
		return XBDM_ENDOFLIST;
	}

	return XBDM_NOERR;
}

HRESULT __stdcall HrRGL(LPCSTR szCommand, LPSTR szResponse, DWORD cchResponse, PDM_CMDCONT pdmcc) {
	CHAR pcCmd[64] = { 0 };
	if (!GetParam(szCommand, pcCmd, sizeof(pcCmd))) {
		return XBDM_INVALIDCMD;
	}

	string sCmd(pcCmd);
	if(sCmd == "rgloader!peekbyte") {
		QWORD qwAddr;
		if (!FGetQwordParam(szCommand, "addr", &qwAddr)) {
			return XBDM_INVALIDARG;
		}

		PPeekPokeDataStruct ppds = new PeekPokeDataStruct();
		ppds->pt = PEEK_BYTE;
		ppds->qwAddress = qwAddr;
		ppds->dwSize = sizeof(BYTE);

		pdmcc->HandlingFunction = HrHvPeek;
		pdmcc->BufferSize = ppds->dwSize;
		pdmcc->Buffer = XPhysicalAlloc(ppds->dwSize, MAXULONG_PTR, 0, PAGE_READWRITE);
		pdmcc->CustomData = ppds;
		pdmcc->BytesRemaining = ppds->dwSize;

		return XBDM_BINRESPONSE;
	} else if(sCmd == "rgloader!peekword") {
		QWORD qwAddr;
		if (!FGetQwordParam(szCommand, "addr", &qwAddr)) {
			return XBDM_INVALIDARG;
		}

		PPeekPokeDataStruct ppds = new PeekPokeDataStruct();
		ppds->pt = PEEK_WORD;
		ppds->qwAddress = qwAddr;
		ppds->dwSize = sizeof(WORD);

		pdmcc->HandlingFunction = HrHvPeek;
		pdmcc->BufferSize = ppds->dwSize;
		pdmcc->Buffer = XPhysicalAlloc(ppds->dwSize, MAXULONG_PTR, 0, PAGE_READWRITE);
		pdmcc->CustomData = ppds;
		pdmcc->BytesRemaining = ppds->dwSize;

		return XBDM_BINRESPONSE;
	} else if(sCmd == "rgloader!peekdword") {
		QWORD qwAddr;
		if (!FGetQwordParam(szCommand, "addr", &qwAddr)) {
			return XBDM_INVALIDARG;
		}

		PPeekPokeDataStruct ppds = new PeekPokeDataStruct();
		ppds->pt = PEEK_DWORD;
		ppds->qwAddress = qwAddr;
		ppds->dwSize = sizeof(DWORD);

		pdmcc->HandlingFunction = HrHvPeek;
		pdmcc->BufferSize = ppds->dwSize;
		pdmcc->Buffer = XPhysicalAlloc(ppds->dwSize, MAXULONG_PTR, 0, PAGE_READWRITE);
		pdmcc->CustomData = ppds;
		pdmcc->BytesRemaining = ppds->dwSize;

		return XBDM_BINRESPONSE;
	} else if(sCmd == "rgloader!peekqword") {
		QWORD qwAddr;
		if(!FGetQwordParam(szCommand, "addr", &qwAddr)) {
			return XBDM_INVALIDARG;
		}

		PPeekPokeDataStruct ppds = new PeekPokeDataStruct();
		ppds->pt = PEEK_QWORD;
		ppds->qwAddress = qwAddr;
		ppds->dwSize = sizeof(QWORD);

		pdmcc->HandlingFunction = HrHvPeek;
		pdmcc->BufferSize = ppds->dwSize;
		pdmcc->Buffer = XPhysicalAlloc(ppds->dwSize, MAXULONG_PTR, 0, PAGE_READWRITE);
		pdmcc->CustomData = ppds;
		pdmcc->BytesRemaining = ppds->dwSize;

		return XBDM_BINRESPONSE;
	} else if(sCmd == "rgloader!peekbytes") {
		QWORD qwAddr;
		DWORD dwSize;
		if (!FGetQwordParam(szCommand, "addr", &qwAddr)) {
			return XBDM_INVALIDARG;
		}
		if(!FGetDwParam(szCommand, "size", &dwSize)) {
			return XBDM_INVALIDARG;
		}

		PPeekPokeDataStruct ppds = new PeekPokeDataStruct();
		ppds->pt = PEEK_BYTES;
		ppds->qwAddress = qwAddr;
		ppds->dwSize = dwSize;

		pdmcc->HandlingFunction = HrHvPeek;
		pdmcc->BufferSize = ppds->dwSize;
		pdmcc->Buffer = XPhysicalAlloc(ppds->dwSize, MAXULONG_PTR, 0, PAGE_READWRITE);
		pdmcc->CustomData = ppds;
		pdmcc->BytesRemaining = ppds->dwSize;

		return XBDM_BINRESPONSE;
	} else if(sCmd == "rgloader!pokebyte") {
		QWORD qwAddr;
		if (!FGetQwordParam(szCommand, "addr", &qwAddr)) {
			return XBDM_INVALIDARG;
		}

		PPeekPokeDataStruct ppds = new PeekPokeDataStruct();
		ppds->pt = POKE_BYTE;
		ppds->qwAddress = qwAddr;
		ppds->dwSize = sizeof(BYTE);

		pdmcc->HandlingFunction = HrHvPoke;
		pdmcc->BufferSize = ppds->dwSize;
		pdmcc->Buffer = XPhysicalAlloc(ppds->dwSize, MAXULONG_PTR, 0, PAGE_READWRITE);
		pdmcc->CustomData = ppds;
		pdmcc->BytesRemaining = ppds->dwSize;

		return XBDM_READYFORBIN;
	} else if(sCmd == "rgloader!pokeword") {
		QWORD qwAddr;
		if (!FGetQwordParam(szCommand, "addr", &qwAddr)) {
			return XBDM_INVALIDARG;
		}

		PPeekPokeDataStruct ppds = new PeekPokeDataStruct();
		ppds->pt = POKE_WORD;
		ppds->qwAddress = qwAddr;
		ppds->dwSize = sizeof(WORD);

		pdmcc->HandlingFunction = HrHvPoke;
		pdmcc->BufferSize = ppds->dwSize;
		pdmcc->Buffer = XPhysicalAlloc(ppds->dwSize, MAXULONG_PTR, 0, PAGE_READWRITE);
		pdmcc->CustomData = ppds;
		pdmcc->BytesRemaining = ppds->dwSize;

		return XBDM_READYFORBIN;
	} else if(sCmd == "rgloader!pokedword") {
		QWORD qwAddr;
		if (!FGetQwordParam(szCommand, "addr", &qwAddr)) {
			return XBDM_INVALIDARG;
		}

		PPeekPokeDataStruct ppds = new PeekPokeDataStruct();
		ppds->pt = POKE_DWORD;
		ppds->qwAddress = qwAddr;
		ppds->dwSize = sizeof(DWORD);

		pdmcc->HandlingFunction = HrHvPoke;
		pdmcc->BufferSize = ppds->dwSize;
		pdmcc->Buffer = XPhysicalAlloc(ppds->dwSize, MAXULONG_PTR, 0, PAGE_READWRITE);
		pdmcc->CustomData = ppds;
		pdmcc->BytesRemaining = ppds->dwSize;

		return XBDM_READYFORBIN;
	} else if(sCmd == "rgloader!pokeqword") {
		QWORD qwAddr;
		if (!FGetQwordParam(szCommand, "addr", &qwAddr)) {
			return XBDM_INVALIDARG;
		}

		PPeekPokeDataStruct ppds = new PeekPokeDataStruct();
		ppds->pt = POKE_QWORD;
		ppds->qwAddress = qwAddr;
		ppds->dwSize = sizeof(QWORD);

		pdmcc->HandlingFunction = HrHvPoke;
		pdmcc->BufferSize = ppds->dwSize;
		pdmcc->Buffer = XPhysicalAlloc(ppds->dwSize, MAXULONG_PTR, 0, PAGE_READWRITE);
		pdmcc->CustomData = ppds;
		pdmcc->BytesRemaining = ppds->dwSize;

		return XBDM_READYFORBIN;
	} else if(sCmd == "rgloader!pokebytes") {
		QWORD qwAddr;
		DWORD dwSize;
		if (!FGetQwordParam(szCommand, "addr", &qwAddr)) {
			return XBDM_INVALIDARG;
		}
		if(!FGetDwParam(szCommand, "size", &dwSize)) {
			return XBDM_INVALIDARG;
		}

		PPeekPokeDataStruct ppds = new PeekPokeDataStruct();
		ppds->pt = POKE_BYTES;
		ppds->qwAddress = qwAddr;
		ppds->dwSize = dwSize;

		pdmcc->HandlingFunction = HrHvPoke;
		pdmcc->BufferSize = ppds->dwSize;
		pdmcc->Buffer = XPhysicalAlloc(ppds->dwSize, MAXULONG_PTR, 0, PAGE_READWRITE);
		pdmcc->CustomData = ppds;
		pdmcc->BytesRemaining = ppds->dwSize;

		return XBDM_READYFORBIN;
	} else if (sCmd == "rgloader!loadmodule") {
		CHAR szModPath[MAX_PATH];
		if (!FGetSzParam(szCommand, "path", szModPath, sizeof(szModPath))) {
			return XBDM_INVALIDARG;
		}

		if (FileExists(szModPath)) {
			NTSTATUS status = XexLoadImage(szModPath, XEX_MODULE_FLAG_DLL, 0, NULL);
			if (!NT_SUCCESS(status)) {
				// return HRESULT_FROM_NT(status);
				return XBDM_UNDEFINED;
			}
			return XBDM_NOERR;
		} else
			return XBDM_NOSUCHFILE;
	} else if (sCmd == "rgloader!installexpansion") {
		DWORD dwSize;
		if (!FGetDwParam(szCommand, "size", &dwSize)) {
			return XBDM_INVALIDARG;
		}

		PHVExpStruct phvexp = new HVExpStruct();
		phvexp->dwSize = dwSize;

		pdmcc->HandlingFunction = HrHvExpInst;
		pdmcc->BufferSize = phvexp->dwSize;
		pdmcc->Buffer = XPhysicalAlloc(phvexp->dwSize, MAXULONG_PTR, 0, PAGE_READWRITE);
		pdmcc->CustomData = phvexp;
		pdmcc->BytesRemaining = phvexp->dwSize;

		return XBDM_READYFORBIN;
	} else if (sCmd == "rgloader!dumpexpansions") {
		DumpExpansions();

		return XBDM_NOERR;
	/* } else if (sCmd == "rgloader!shadowboot") {
		CHAR szShadowName[MAX_PATH];
		if(!FGetSzParam(szCommand, "name", szShadowName, sizeof(szShadowName))) {
			return XBDM_INVALIDARG;
		}

		CHAR szRelativePath[MAX_PATH];
		CHAR szAbsolutePath[MAX_PATH];

		int ret = sprintf_s(szRelativePath, sizeof(szRelativePath), "Hdd:\\Shadowboots\\%s.bin", szShadowName);
		if (ret == 0)
			return XBDM_NOMEMORY;

		ret = sprintf_s(szAbsolutePath, sizeof(szAbsolutePath), "\\Device\\Harddisk0\\Partition1\\Shadowboots\\%s.bin", szShadowName);
		if (ret == 0)
			return XBDM_NOMEMORY;

		if (FileExists(szRelativePath)) {
			STRING sPath;
			sPath.Length = strlen(szAbsolutePath);
			sPath.MaximumLength = sPath.Length + 1;
			sPath.Buffer = szAbsolutePath;

			((EXPTRYTOBOOTMEDIAKERNEL)RGLoader->Offsets->KERNEL->ExpTryToBootMediaKernel)(&sPath, 0, 0);

			return XBDM_NOERR;
		} else
			return XBDM_NOSUCHFILE;

		return XBDM_NOERR; */
	} else if (sCmd == "rgloader!shadowboot") {
		DWORD dwSize;
		if (!FGetDwParam(szCommand, "size", &dwSize)) {
			return XBDM_INVALIDARG;
		}

		PFileDataStruct pFile = new FileDataStruct();
		pFile->dwSize = dwSize;
		pFile->pvAlloc = XPhysicalAllocEx(dwSize, 0x1000000, 0x1800000, 0x1000, PAGE_READWRITE);

		pdmcc->HandlingFunction = HrShadowBoot;
		pdmcc->BufferSize = 0x1000;
		pdmcc->Buffer = XPhysicalAlloc(0x1000, MAXULONG_PTR, 0, PAGE_READWRITE);
		pdmcc->CustomData = pFile;
		pdmcc->BytesRemaining = dwSize;

		return XBDM_READYFORBIN;
	}

	return XBDM_INVALIDCMD;
}
#include "stdafx.h"

DWORD __declspec(naked) HvxExpansionInstall(QWORD addr, DWORD size) {
	__asm {
		li      r0, EXPANSION_INST_SC
		sc
		blr
	}
}

QWORD __declspec(naked) HvxExpansionCall(DWORD sig, QWORD Arg1, QWORD Arg2, QWORD Arg3, QWORD Arg4) {
	__asm {
		li      r0, EXPANSION_CALL_SC
		sc
		blr
	}
}

QWORD __declspec(naked) HvxSetState(DWORD mode) {  // 2 = protection off, 3 = protection on
	__asm {
		li      r0, SET_STATE_SC
		sc
		blr
	}
}

BYTE HvPeekBYTE(QWORD Address) {
	return (BYTE)HvxExpansionCall(EXPANSION_SIG, PeekBYTEBypass, Address, 0, 0);
}

WORD HvPeekWORD(QWORD Address) {
	return (WORD)HvxExpansionCall(EXPANSION_SIG, PeekWORDBypass, Address, 0, 0);
}

DWORD HvPeekDWORD(QWORD Address) {
	return (DWORD)HvxExpansionCall(EXPANSION_SIG, PeekDWORDBypass, Address, 0, 0);
}

QWORD HvPeekQWORD(QWORD Address) {
	return HvxExpansionCall(EXPANSION_SIG, PeekQWORD, Address, 0, 0);
}

NTSTATUS HvPeekBytes(QWORD Address, PVOID Buffer, DWORD Size) {
	NTSTATUS result = STATUS_MEMORY_NOT_ALLOCATED;
	VOID* data = XPhysicalAlloc(Size, MAXULONG_PTR, 0, PAGE_READWRITE);
	if (data != NULL)
	{
		QWORD daddr = (QWORD)((DWORD)MmGetPhysicalAddress(data) & 0xFFFFFFFF);
		ZeroMemory(data, Size);
		result = (NTSTATUS)HvxExpansionCall(EXPANSION_SIG, PeekBytesBypass, Address, daddr, Size);
		if (NT_SUCCESS(result))
			memcpy(Buffer, data, Size);
		XPhysicalFree(data);
	}
	else
		RGLPrint("ERROR", "Allocating HvPeekBytes buffer failed!");
	return result;
}

NTSTATUS HvPokeBYTE(QWORD Address, BYTE Value) {
	return (NTSTATUS)HvxExpansionCall(EXPANSION_SIG, PokeBYTEBypass, Address, Value, 0);
}

NTSTATUS HvPokeWORD(QWORD Address, WORD Value) {
	return (NTSTATUS)HvxExpansionCall(EXPANSION_SIG, PokeWORDBypass, Address, Value, 0);
}

NTSTATUS HvPokeDWORD(QWORD Address, DWORD Value) {
	return (NTSTATUS)HvxExpansionCall(EXPANSION_SIG, PokeDWORDBypass, Address, Value, 0);
}

NTSTATUS HvPokeQWORD(QWORD Address, QWORD Value) {
	return (NTSTATUS)HvxExpansionCall(EXPANSION_SIG, PokeQWORDBypass, Address, Value, 0);
}

NTSTATUS HvPokeBytes(QWORD Address, PVOID Buffer, DWORD Size) {
	NTSTATUS result = STATUS_MEMORY_NOT_ALLOCATED;
	VOID* data = XPhysicalAlloc(Size, MAXULONG_PTR, 0, PAGE_READWRITE);
	if (data != NULL) {
		QWORD daddr = (QWORD)((DWORD)MmGetPhysicalAddress(data) & 0xFFFFFFFF);
		memcpy(data, Buffer, Size);
		result = (NTSTATUS)HvxExpansionCall(EXPANSION_SIG, PokeBytesBypass, Address, daddr, Size);
		XPhysicalFree(data);
	} else
		RGLPrint("ERROR", "Allocating HvPokeBytes buffer failed!");
	return result;
}

QWORD HvReadFuseRow(int row) {
	if (row < 12)
	{
		QWORD addr = 0x8000020000020000ULL | (row * 0x200);
		return HvPeekQWORD(addr);
	}
	return 0;
}

void HvReadCpuKey(PBYTE pbCpuKey) {
	QWORD aqwCpu[2];
	aqwCpu[0] = HvReadFuseRow(3) | HvReadFuseRow(4);
	aqwCpu[1] = HvReadFuseRow(5) | HvReadFuseRow(6);
	memcpy(pbCpuKey, (PBYTE)aqwCpu, sizeof(QWORD) * 2);
}

DWORD InstallExpansions() {
	// Generic HVPP
	PVOID pvSectionData;
	ULONG ulSectionSize;
	if (XGetModuleSection(RGLoader->State->Handle, MODULE_SECTION_GENERIC_HVPP, &pvSectionData, &ulSectionSize) == FALSE) {
		return ERROR_NOT_FOUND;
	}

	PBYTE pbAlloc = (PBYTE)XPhysicalAlloc(EXPANSION_SIZE, MAXULONG_PTR, 0, PAGE_READWRITE);
	memset(pbAlloc, 0, EXPANSION_SIZE);
	memcpy(pbAlloc, pvSectionData, ulSectionSize);
	DWORD dwRet = HvxExpansionInstall((QWORD)MmGetPhysicalAddress(pbAlloc), EXPANSION_SIZE);
	XPhysicalFree(pbAlloc);

	// xbO HVPP
	if (XGetModuleSection(RGLoader->State->Handle, MODULE_SECTION_XBONLINE_HVPP, &pvSectionData, &ulSectionSize) == FALSE) {
		return ERROR_NOT_FOUND;
	}

	pbAlloc = (PBYTE)XPhysicalAlloc(EXPANSION_SIZE, MAXULONG_PTR, 0, PAGE_READWRITE);
	memset(pbAlloc, 0, EXPANSION_SIZE);
	memcpy(pbAlloc, pvSectionData, ulSectionSize);
	dwRet |= HvxExpansionInstall((QWORD)MmGetPhysicalAddress(pbAlloc), EXPANSION_SIZE);
	XPhysicalFree(pbAlloc);

	return dwRet;
}

BOOL InstallSC0() {
	PVOID pvSectionData;
	ULONG ulSectionSize;
	if (XGetModuleSection(RGLoader->State->Handle, MODULE_SECTION_SC0, &pvSectionData, &ulSectionSize) == FALSE) {
		return ERROR_NOT_FOUND;
	}

	PBYTE pbAlloc = (PBYTE)XPhysicalAlloc(ulSectionSize, MAXULONG_PTR, 0, PAGE_READWRITE);
	memset(pbAlloc, 0, ulSectionSize);
	memcpy(pbAlloc, pvSectionData, ulSectionSize);

	// poke in SC0 payload
	HvPokeBytes(0xB320, pbAlloc, ulSectionSize);
	// poke in address to SC0 payload
	HvPokeDWORD(0x200015EC0, 0xB320);

	XPhysicalFree(pbAlloc);

	return TRUE;
}

BOOL DumpExpansions() {
	QWORD qwAddr = HvPeekQWORD(0x200016A08);
	QWORD qwHvTblAddr = qwAddr + 0x400;
	ExpHdr hdr;
	PBYTE pbExpCode = (PBYTE)malloc(EXPANSION_SIZE);
	CHAR szExpName[32] = { 0 };
	RGLPrint("EXPANSION", "Dumping expansions...\n");
	for (int i = 0; i < 5; i++) {
		HvPeekBytes(qwHvTblAddr + (i * sizeof(ExpHdr)), &hdr, sizeof(ExpHdr));
		if (hdr.dwMagic == 0 && hdr.dwFlags == 0 && hdr.qwAddr == 0)  // no more expansions found
			break;
		QWORD qwExpSizeAddr = hdr.qwAddr + 0x8;
		QWORD qwExpCodeAddr = hdr.qwAddr + 0x10;
		DWORD dwExpSize = HvPeekDWORD(qwExpSizeAddr);
		dwExpSize -= 4;
		if (dwExpSize > EXPANSION_SIZE)
			continue;  // expansion is too large so let's move to the next one
		memset(pbExpCode, 0, EXPANSION_SIZE);
		HvPeekBytes(qwExpCodeAddr, pbExpCode, dwExpSize);
		RtlSprintf(szExpName, "Hdd:\\Expansion%d.bin", i);
		RGLPrint("EXPANSION", "Dumping expansion ID 0x%08X to \"%s\"...\n", hdr.dwMagic, szExpName);
		WriteFile(szExpName, pbExpCode, dwExpSize);
	}
	free(pbExpCode);

	return TRUE;
}

BOOL DumpHV() {
	PBYTE pbHV = (PBYTE)malloc(0x40000);
	memset(pbHV, 0, 0x40000);
	HvPeekBytes(0, pbHV, 0x10000);
	HvPeekBytes(0x200010000, pbHV + 0x10000, 0x10000);
	HvPeekBytes(0x400020000, pbHV + 0x20000, 0x10000);
	HvPeekBytes(0x600030000, pbHV + 0x30000, 0x10000);
	WriteFile("Hdd:\\HV.bin", pbHV, 0x40000);
	free(pbHV);

	return TRUE;
}

BOOL DisableExpansionInstalls() {
	// disable expansion installs by unpatching HvxExpansionInstall
	BYTE _30BAC_orig[] = { 0x41, 0x9A, 0xFF, 0xB8 };  // beq cr6, LAB_00030b64
	BYTE _li_r3_0_blr[] = { 0x38, 0x60, 0x00, 0x00, 0x4E, 0x80, 0x00, 0x20 };  // li r3, 0; blr;
	if (NT_SUCCESS(HvPokeBytes(0x600030BAC, _30BAC_orig, 4)) &&
		NT_SUCCESS(HvPokeBytes(0x600030A98, _li_r3_0_blr, 8)))
	{
		return TRUE;
	}
	return FALSE;
}

BOOL DisableShadowbooting() {
	// disable shadowbooting by making HvxShadowboot fall through to MachineCheck
	BYTE nopCode[] = { 0x60, 0x00, 0x00, 0x00 };  // nop
	if (NT_SUCCESS(HvPokeBytes(0x60003206C, nopCode, 4)))
		return TRUE;
	return FALSE;
}

BOOL LoadApplyHV(const char* filepath) {
	LONGLONG fileSize = FileSize(filepath);
	if (fileSize == -1) {
		RGLPrint("ERROR", "Invalid HV patch path\n");
		return FALSE;
	}
	if (fileSize % 4 != 0) {
		RGLPrint("ERROR", "Invalid HV patch size\n");
		return FALSE;
	}
	BYTE* patchData = (BYTE*)XPhysicalAlloc(fileSize, MAXULONG_PTR, 0, PAGE_READWRITE);
	if (!ReadFile(filepath, patchData, fileSize)) {
		RGLPrint("ERROR", "Unable to read HV patch file\n");
		XPhysicalFree(patchData);
		return FALSE;
	}

	BYTE* saveAddr = patchData;
	for(;;)
	{
		UINT64 addr = *(UINT32*)patchData;
		if (addr == 0xFFFFFFFF)
			break;
		addr |= 0x8000000000000000ULL;
		DWORD size = *(DWORD*)(patchData + 0x4);
		BYTE* data = (BYTE*)XPhysicalAlloc(size * 4, MAXULONG_PTR, 0, PAGE_READWRITE);
		memcpy(data, patchData + 0x8, size*4);
		HvPokeBytes(addr, data, size * 4);
		XPhysicalFree(data);
		patchData += (size * 4) + 8;
	}

	// cleanup
	XPhysicalFree(saveAddr);

	return TRUE;
}

BOOL LoadKeyVault(const char* filepath) {
	DWORD fileSize = FileSize(filepath);
	if (fileSize == -1) {
		RGLPrint("ERROR", "Invalid KV path\n");
		return FALSE;
	}
	if (fileSize != 0x4000) {
		RGLPrint("ERROR", "Invalid KV size\n");
		return FALSE;
	}
	BYTE* kvData = (BYTE*)XPhysicalAlloc(fileSize, MAXULONG_PTR, 0, PAGE_READWRITE);
	if (!ReadFile(filepath, kvData, fileSize)) {
		RGLPrint("ERROR", "Unable to read KV file\n");
		XPhysicalFree(kvData);
		return FALSE;
	}

	// UPDATE THIS FOR NEW RELEASES
	// copy the console certificate to ???
	UINT32 unkData = *(UINT32*)(0x81D205C8);
	if (unkData != 0)
	{
		//unkData += 0x313C;
		memcpy((void*)(unkData + 0x313C), kvData + 0x9C8, 0x1A8);
	}
	
	// 17489 - 162E0
	QWORD kvAddr = HvPeekQWORD(0x2000162E0);
	HvPeekBytes(kvAddr + 0xF0, kvData + 0xF0, 0x10);    // abRoamableObfKey
	HvPeekBytes(kvAddr + 0x100, kvData + 0x100, 0x10);  // abDvdKey
	HvPokeBytes(kvAddr, kvData, 0x4000);

	// cleanup
	XPhysicalFree(kvData);

	return TRUE;
}


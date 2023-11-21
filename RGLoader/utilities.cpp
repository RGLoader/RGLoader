#include "stdafx.h"

char m_hookSection[0x500];
int m_hookCount;

SMC_PWR_REAS GetSmcPowerOnReason() {
	BYTE msg[0x10];
	BYTE rsp[0x10];
	memset(msg, 0, 0x10);
	msg[0] = smc_poweron_type;
	HalSendSMCMessage(msg, rsp);
	return (SMC_PWR_REAS)rsp[1];
}

SMC_TRAY_STATE GetSmcTrayState() {
	BYTE msg[0x10];
	BYTE rsp[0x10];
	memset(msg, 0, 0x10);
	msg[0] = smc_query_tray;
	HalSendSMCMessage(msg, rsp);
	return (SMC_TRAY_STATE)rsp[1];
}

void GetMountedPackages() {
	HANDLE xbdm;
	NTSTATUS ret = XexGetModuleHandle(MODULE_XBDM, (PHANDLE)&xbdm);
	PLDR_DATA_TABLE_ENTRY out;
	XexPcToFileHeader(xbdm, &out);
	DWORD XBDMRange[2] = { (DWORD)out->ImageBase, (DWORD)out->ImageBase + (DWORD)out->SizeOfFullImage };
}

void Mount(char* dev, char* mnt)
{
	ANSI_STRING asDevice, asMount;
    RtlInitAnsiString(&asDevice, dev);
	RtlInitAnsiString(&asMount, mnt);
	ObCreateSymbolicLink(&asMount, &asDevice);
}

DWORD ResolveFunction(char* modname, DWORD ord)
{
    UINT32 ptr32=0, ret=0, ptr2=0;
    ret = XexGetModuleHandle(modname, (PHANDLE)&ptr32); //xboxkrnl.exe xam.dll?
    if(ret == 0)
    {
        ret = XexGetProcedureAddress((HANDLE)ptr32, ord, &ptr2 );
        if(ptr2 != 0)
			return ptr2;
    }
    return 0; // function not found
}

VOID __declspec(naked) GLPR_FUN(VOID)
{
	__asm {
		std     r14, -0x98(sp)
		std     r15, -0x90(sp)
		std     r16, -0x88(sp)
		std     r17, -0x80(sp)
		std     r18, -0x78(sp)
		std     r19, -0x70(sp)
		std     r20, -0x68(sp)
		std     r21, -0x60(sp)
		std     r22, -0x58(sp)
		std     r23, -0x50(sp)
		std     r24, -0x48(sp)
		std     r25, -0x40(sp)
		std     r26, -0x38(sp)
		std     r27, -0x30(sp)
		std     r28, -0x28(sp)
		std     r29, -0x20(sp)
		std     r30, -0x18(sp)
		std     r31, -0x10(sp)
		stw     r12, -0x8(sp)
		blr
	}
}

DWORD InterpretBranchDestination(DWORD currAddr, DWORD brInst)
{
	DWORD ret;
	int destOff = brInst&0x3FFFFFC;
	int currOff = currAddr&~0x80000000; // make it a positive int
	if(brInst&0x2000000) // backward branch
		destOff = destOff|0xFC000000; // sign extend
	ret = (DWORD)(currOff+destOff);
	return (ret|(currAddr&0x80000000)); // put back the bit if it was used
}

DWORD FindInterpretBranch(PDWORD startAddr, DWORD maxSearch)
{
	DWORD i;
	DWORD ret = 0;
	for(i = 0; i < maxSearch; i++)
	{
		if((startAddr[i]&0xFC000000) == 0x48000000)
		{
			ret = InterpretBranchDestination((DWORD)&startAddr[i], startAddr[i]);
			i = maxSearch;
		}
	}
	return ret;
}

DWORD RelinkGPLR(int offset, PDWORD saveStubAddr, PDWORD orgAddr)
{
	DWORD inst = 0, repl;
	int i;
	PDWORD saver = (PDWORD)GLPR_FUN;
	// if the msb is set in the instruction, set the rest of the bits to make the int negative
	if (offset & 0x2000000)
		offset = offset | 0xFC000000;
	//DbgPrint("frame save offset: %08x\n", offset);
	repl = orgAddr[offset / 4];
	//DbgPrint("replacing %08x\n", repl);
	for (i = 0; i < 20; i++)
	{
		if (repl == saver[i])
		{
			int newOffset = (int)&saver[i] - (int)saveStubAddr;
			inst = 0x48000001 | (newOffset & 0x3FFFFFC);
			//DbgPrint("saver addr: %08x savestubaddr: %08x\n", &saver[i], saveStubAddr);
		}
	}
	//DbgPrint("new instruction: %08x\n", inst);
	return inst;
}

VOID HookFunctionStart(PDWORD addr, PDWORD saveStub, DWORD dest)
{
	if ((saveStub != NULL) && (addr != NULL))
	{
		int i;
		DWORD addrReloc = (DWORD)(&addr[4]);// replacing 4 instructions with a jump, this is the stub return address
		//DbgPrint("hooking addr: %08x savestub: %08x dest: %08x addreloc: %08x\n", addr, saveStub, dest, addrReloc);
		// build the stub
		// make a jump to go to the original function start+4 instructions
		DWORD writeBuffer;

		writeBuffer = 0x3D600000 + (((addrReloc >> 16) & 0xFFFF) + (addrReloc & 0x8000 ? 1 : 0)); // lis %r11, dest>>16 + 1
		saveStub[0] = writeBuffer;

		writeBuffer = 0x396B0000 + (addrReloc & 0xFFFF); // addi %r11, %r11, dest&0xFFFF
		saveStub[1] = writeBuffer;

		writeBuffer = 0x7D6903A6; // mtctr %r11
		saveStub[2] = writeBuffer;

		// instructions [3] through [6] are replaced with the original instructions from the function hook
		// copy original instructions over, relink stack frame saves to local ones
		for (i = 0; i < 4; i++)
		{
			writeBuffer = ((addr[i] & 0x48000003) == 0x48000001) ? RelinkGPLR((addr[i] & ~0x48000003), &saveStub[i + 3], &addr[i]) : addr[i];
			saveStub[i + 3] = writeBuffer;
		}
		writeBuffer = 0x4E800420; // bctr
		saveStub[7] = writeBuffer;

		doSync(saveStub);

		//DbgPrint("savestub:\n");
		//for(i = 0; i < 8; i++)
		//{
		//	DbgPrint("PatchDword(0x%08x, 0x%08x);\n", &saveStub[i], saveStub[i]);
		//}
		// patch the actual function to jump to our replaced one
		PatchInJump(addr, dest, FALSE);
	}
}

VOID UnhookFunctionStart(PDWORD addr, PDWORD oldData)
{
	if((addr != NULL) && (oldData != NULL))
	{
		int i;
		for(i = 0; i < 4; i++)
		{
			addr[i] = oldData[i];
		}
		doSync(addr);
	}
}

DWORD HookFunctionStub(PDWORD _Address, void* Function) {
	DWORD* startStub = (DWORD*)&m_hookSection[m_hookCount * 32];
	m_hookCount++;

	for (auto i = 0; i < 7; i++)
		startStub[i] = 0x60000000;
	startStub[7] = 0x4E800020;

	HookFunctionStart(_Address, startStub, (DWORD)Function);
	return (DWORD)startStub;
}

DWORD FindInterpretBranchOrdinal(PCHAR modname, DWORD ord, DWORD maxSearch)
{
	DWORD ret = 0;
	PDWORD search = (PDWORD)ResolveFunction(modname, ord);
	if(search != NULL)
		ret = FindInterpretBranch(search, maxSearch);
	return ret;
}

VOID PatchInJump(PDWORD addr, DWORD dest, BOOL linked)
{
	DWORD writeBuffer;

	writeBuffer = 0x3D600000 + (((dest >> 16) & 0xFFFF) + (dest & 0x8000 ? 1 : 0)); // lis %r11, dest>>16 + 1
	addr[0] = writeBuffer;

	writeBuffer = 0x396B0000 + (dest & 0xFFFF); // addi %r11, %r11, dest&0xFFFF
	addr[1] = writeBuffer;

	writeBuffer = 0x7D6903A6; // mtctr %r11
	addr[2] = writeBuffer;

	writeBuffer = 0x4E800420 | (linked ? 1 : 0); // bctr
	addr[3] = writeBuffer;

	doSync(addr);
}

////////////////////////////////////////////////////////////////////////
// This is the modified version of hookImpStub
// modified to work with Devkits

BOOL HookImpStubDebug(char* modname, char* impmodname, DWORD ord, DWORD patchAddr)
{
	DWORD orgAddr;
	PLDR_DATA_TABLE_ENTRY ldat;
	int i, j;
	BOOL ret = FALSE;
	// get the address of the actual function that is jumped to
	orgAddr = ResolveFunction(impmodname, ord);
	if(orgAddr != 0)
	{
		// find where kmod info is stowed
		ldat = (PLDR_DATA_TABLE_ENTRY)GetModuleHandle(modname);
		if(ldat != NULL)
		{
			// use kmod info to find xex header in memory
			PXEX_IMPORT_DESCRIPTOR imps = (PXEX_IMPORT_DESCRIPTOR)RtlImageXexHeaderField(ldat->XexHeaderBase, XEX_HEADER_IMPORTS);
			if(imps != NULL)
			{
				char* impName = (char*)(imps+1);
				PXEX_IMPORT_TABLE impTbl = (PXEX_IMPORT_TABLE)(impName + imps->NameTableSize);
				for(i = 0; i < (int)(imps->ModuleCount); i++)
				{
					// use import descriptor strings to refine table
					for(j = 0; j < impTbl->ImportCount; j++)
					{
						PDWORD add = (PDWORD)impTbl->ImportStubAddr[j];
						if(add[0] == orgAddr)
						{
							HRESULT hr;
							hr = (HRESULT) memcpy(add, (LPCVOID)patchAddr, 4);
							//DbgPrint("XTW: 2 hr = 0x%008X | at addr: 0x%08X\n", hr, add);
							BYTE data[0x10];
							PatchInJump((PDWORD)data, patchAddr, FALSE);
							hr = (HRESULT)memcpy((PDWORD)(impTbl->ImportStubAddr[j+1]), (LPCVOID)data, 0x10);
							//memcpy((PDWORD)(impTbl->ImportStubAddr[j+1]), data, 0x10);
							//DbgPrint("XTW: 2 hr = 0x%008X | at addr: 0x%08X\n", hr, (PDWORD)(impTbl->ImportStubAddr[j+1]));
							//DbgPrint("%s %s tbl %d has ord %x at tstub %d location %08x\n", modname, impName, i, ord, j, impTbl->ImportStubAddr[j+1]);
							//patchInJump((PDWORD)(impTbl->ImportStubAddr[j+1]), patchAddr, FALSE);
							j = impTbl->ImportCount;
							ret = TRUE;
						}
					}
					impTbl = (PXEX_IMPORT_TABLE)((BYTE*)impTbl+impTbl->TableSize);
					impName = impName+strlen(impName);
					while((impName[0]&0xFF) == 0x0)
						impName++;
				}
			}		
			//else DbgPrint("could not find import descriptor for mod %s\n", modname);
		}
		//else DbgPrint("could not find data table for mod %s\n", modname);
	}
	//else DbgPrint("could not find ordinal %d in mod %s\n", ord, impmodname);

	return ret;
}

DWORD MakeBranch(DWORD branchAddr, DWORD destination, BOOL linked) {
	return (0x48000000) | ((destination-branchAddr) & 0x03FFFFFF) | (DWORD)linked;
}

void SwapEndian(BYTE* src, DWORD size)
{
	BYTE* temp = new BYTE[size];
	for(int i = size - 4, b = 0; i >= 0; i -= 4, b += 4) {
		*(DWORD*)&temp[b]=(DWORD)src[i];
	}
	memcpy(src, temp, size);
	delete[size] temp;
}

void RelaunchXShell(void) {
	RGLPrint("INFO", "Thread ---------!\n");

	if(KeGetCurrentProcessType() == PROC_SYSTEM) {
		RGLPrint("INFO", "Thread is still system!\n");
	} else RGLPrint("INFO", "Attempting to launch xshell! Mounting drives..\n");


	XSetLaunchData( NULL, 0 );
	XamLoaderLaunchTitleEx("\\SystemRoot\\dash.xex", NULL, NULL, 0);

}
     
void LaunchXShell(void)
{
    if(KeGetCurrentProcessType() == PROC_SYSTEM)
    {
		RGLPrint("INFO", "System thread, attempting to launch xshell.\n");
		XSetLaunchData( NULL, 0 );

		//XamLoaderLaunchTitleEx("\\Device\\Harddisk0\\Partition1\\DEVKIT\\Utilities\\DashSelector\\DashSelector.xex", "\\Device\\Harddisk0\\Partition1\\DEVKIT\\Utilities\\DashSelector", NULL, 0);
		XamLoaderLaunchTitleEx("\\Device\\Flash\\xshell.xex", "\\Device\\Flash", NULL, 0);
    }
    else
    {
		RGLPrint("INFO", "Launching xshell!\n");
        RelaunchXShell();
    }
}

HRESULT DoDeleteLink(const char* szDrive, const char* sysStr)
{
	STRING LinkName;
	CHAR szDestinationDrive[MAX_PATH];
	sprintf_s(szDestinationDrive, MAX_PATH, sysStr, szDrive);
	RtlInitAnsiString(&LinkName, szDestinationDrive);
	return ObDeleteSymbolicLink(&LinkName);
}

HRESULT DeleteLink(const char* szDrive, BOOL both)
{
	HRESULT res = -1;
	if(both) {
		res = DoDeleteLink(szDrive, OBJ_SYS_STRING);
		res |= DoDeleteLink(szDrive, OBJ_USR_STRING);
	}
	else {
		if(KeGetCurrentProcessType() == PROC_SYSTEM)
			res = DoDeleteLink(szDrive, OBJ_SYS_STRING);
		else
			res = DoDeleteLink(szDrive, OBJ_USR_STRING);
	}
	return res;
}


HRESULT DoMountPath(const char* szDrive, const char* szDevice, const char* sysStr)
{
	STRING DeviceName, LinkName;
	CHAR szDestinationDrive[MAX_PATH];
	sprintf_s(szDestinationDrive, MAX_PATH, sysStr, szDrive);
	RtlInitAnsiString(&DeviceName, szDevice);
	RtlInitAnsiString(&LinkName, szDestinationDrive);
	ObDeleteSymbolicLink(&LinkName);
	return (HRESULT)ObCreateSymbolicLink(&LinkName, &DeviceName);
}

HRESULT MountPath(const char* szDrive, const char* szDevice, BOOL both) {
	HRESULT res = -1;
	if(both) {
		res = DoMountPath(szDrive, szDevice, OBJ_SYS_STRING);
		res |= DoMountPath(szDrive, szDevice, OBJ_USR_STRING);
	}
	else {
		if(KeGetCurrentProcessType() == PROC_SYSTEM)
			res = DoMountPath(szDrive, szDevice, OBJ_SYS_STRING);
		else
			res = DoMountPath(szDrive, szDevice, OBJ_USR_STRING);
	}
	return res;
}

int DeleteDirectory(const string& refcstrRootDirectory, bool bDeleteSubdirectories) {
	bool            bSubdirectory = false;       // Flag, indicating whether
												// subdirectories have been found
	HANDLE          hFile;                       // Handle to directory
	string     strFilePath;                 // Filepath
	string     strPattern;                  // Pattern
	WIN32_FIND_DATA FileInformation;             // File information


	strPattern = refcstrRootDirectory + "\\*.*";
	hFile = ::FindFirstFile(strPattern.c_str(), &FileInformation);
	if (hFile != INVALID_HANDLE_VALUE) {
		do {
			if (FileInformation.cFileName[0] != '.') {
				strFilePath.erase();
				strFilePath = refcstrRootDirectory + "\\" + FileInformation.cFileName;

				if (FileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
					if (bDeleteSubdirectories) {
						// Delete subdirectory
						int iRC = DeleteDirectory(strFilePath, bDeleteSubdirectories);
						if (iRC)
							return iRC;
					} else
						bSubdirectory = true;
				} else {
					// Set file attributes
					if (::SetFileAttributes(strFilePath.c_str(), FILE_ATTRIBUTE_NORMAL) == FALSE)
						return ::GetLastError();

					// Delete file
					if (::DeleteFile(strFilePath.c_str()) == FALSE)
						return ::GetLastError();
				}
			}
		} while (::FindNextFile(hFile, &FileInformation) == TRUE);

		// Close handle
		::FindClose(hFile);

		DWORD dwError = ::GetLastError();
		if (dwError != ERROR_NO_MORE_FILES)
			return dwError;
		else {
			if (!bSubdirectory) {
				// Set directory attributes
				if (::SetFileAttributes(refcstrRootDirectory.c_str(), FILE_ATTRIBUTE_NORMAL) == FALSE)
					return ::GetLastError();

				// Delete directory
				if (::RemoveDirectory(refcstrRootDirectory.c_str()) == FALSE)
					return ::GetLastError();
			}
		}
	}

	return 0;
}

int CopyDirectory(const string &refcstrSourceDirectory, const string &refcstrDestinationDirectory) {
	string strSource;						 // Source file
	string strDestination;				 // Destination file
	string strPattern;					 // Pattern
	HANDLE      hFile;				     // Handle to file
	WIN32_FIND_DATA FileInformation;				 // File information

	strPattern = refcstrSourceDirectory + "\\*.*";

	// Create destination directory
	::CreateDirectory(refcstrDestinationDirectory.c_str(), 0);

	hFile = ::FindFirstFile(strPattern.c_str(), &FileInformation);
	if (hFile != INVALID_HANDLE_VALUE) {
		do {
			if (FileInformation.cFileName[0] != '.') {
				strSource.erase();
				strDestination.erase();

				strSource = refcstrSourceDirectory + "\\" + FileInformation.cFileName;
				strDestination = refcstrDestinationDirectory + "\\" + FileInformation.cFileName;

				if (FileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
					// Copy subdirectory
					if (CopyDirectory(strSource, strDestination))
						return 1;
				}
				else {
					// Copy file
					if (::CopyFile(strSource.c_str(), strDestination.c_str(), TRUE) == FALSE)
						return ::GetLastError();
				}
			}
		} while (::FindNextFile(hFile, &FileInformation) == TRUE);

		// Close handle
		::FindClose(hFile);

		DWORD dwError = ::GetLastError();
		if (dwError != ERROR_NO_MORE_FILES)
			return dwError;
	}

	return 0;
}

void RGLPrint(const PCHAR cat, const PCHAR fmt, ...) {
	CHAR pcBuf1[512] = { 0 };
	va_list args;
	va_start(args, fmt);
	RtlVsnprintf(pcBuf1, 512, fmt, args);
	va_end(args);
	
	char pcBuf2[512] = { 0 };
	RtlSprintf(pcBuf2, "[RGLoader] [%s] %s", cat, pcBuf1);

	OutputDebugStringA(pcBuf2);
}

void RGLNewLine() {
	OutputDebugStringA("\n");
}

void HexPrint(PBYTE pbData, DWORD dwLen) {
	PCHAR pcBuf = (PCHAR)malloc((dwLen * 2) + 1);
	memset(pcBuf, 0, (dwLen * 2) + 1);
	for (int i = 0; i < dwLen; i++) {
		RtlSprintf(&pcBuf[i * 2], "%02X", pbData[i]);
	}
	OutputDebugStringA(pcBuf);
	free(pcBuf);
}

void RGLHexPrint(const PCHAR cat, PBYTE pbData, DWORD dwLen) {
	CHAR pcBuf[64] = { 0 };
	RtlSprintf(pcBuf, "[RGLoader] [%s] ", cat);
	OutputDebugStringA(pcBuf);
	HexPrint(pbData, dwLen);
	RGLNewLine();
}

string PathJoin(const string& szPath0, const string& szPath1) {
	string szPath0_0 = szPath0;
	string szPath1_0 = szPath1;

	// remove path separator from end of szPath0
	if (szPath0_0.back() == '\\' || szPath0_0.back() == '/') {
		szPath0_0 = szPath0_0.substr(0, szPath0_0.size() - 1);
	}
	// remove path separator from beginning of szPath1
	if (szPath1_0.front() == '\\' || szPath1_0.front() == '/') {
		szPath1_0 = szPath1_0.substr(1);
	}
	szPath0_0 += '\\';
	szPath0_0 += szPath1;
	return szPath0_0;
}

vector<string> ListFiles(const string& szPathWithPattern) {
	vector<string> vFiles;
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind;

	hFind = FindFirstFile(szPathWithPattern.c_str(), &FindFileData);
	while (hFind != INVALID_HANDLE_VALUE) {
		vFiles.push_back(FindFileData.cFileName);

		if (!FindNextFile(hFind, &FindFileData))
			hFind = INVALID_HANDLE_VALUE;
	}
	return vFiles;
}

BOOL FileExists(LPCSTR szPath) {
	WIN32_FILE_ATTRIBUTE_DATA fad;
	if (!GetFileAttributesExA(szPath, GetFileExInfoStandard, &fad))
		return FALSE; // error condition, could call GetLastError to find out more
	return TRUE;
}

BOOL DirectoryExists(LPCSTR szPath) {
	WIN32_FILE_ATTRIBUTE_DATA fad;
	if (!GetFileAttributesEx(szPath, GetFileExInfoStandard, &fad))
		return FALSE; // error condition, could call GetLastError to find out more
	return (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
}

LONGLONG FileSize(LPCSTR szPath)
{
	WIN32_FILE_ATTRIBUTE_DATA fad;
	if (!GetFileAttributesEx(szPath, GetFileExInfoStandard, &fad))
		return -1; // error condition, could call GetLastError to find out more
	LARGE_INTEGER size;
	size.HighPart = fad.nFileSizeHigh;
	size.LowPart = fad.nFileSizeLow;
	return size.QuadPart;
}

BOOL ReadFile(LPCSTR path, PVOID buffer, DWORD size)
{
	HANDLE file = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		// InfoPrint("Couldn't open %s\n", filename);
		return false;
	}
	DWORD noBytesRead;
	ReadFile(file, buffer, size, &noBytesRead, NULL);
	CloseHandle(file);
	if (noBytesRead <= 0)
		return FALSE;
	return TRUE;
}

BOOL WriteFile(LPCSTR path, PVOID buffer, DWORD size)
{
	HANDLE file = CreateFile(path, GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		// InfoPrint("Couldn't open %s\n", filename);
		return FALSE;
	}
	DWORD noBytesWritten;
	WriteFile(file, buffer, size, &noBytesWritten, NULL);
	CloseHandle(file);
	if (noBytesWritten != size)
		return FALSE;
	return TRUE;
}

PWCHAR CharToWChar(const PCHAR text, PWCHAR stackPtr) {
	const size_t size = strlen(text) + 1;
	mbstowcs(stackPtr, text, size);
	return stackPtr;
}

PCHAR WCharToChar(const PWCHAR text, PCHAR stackPtr) {
	const size_t size = lstrlenW(text) + 1;
	wcstombs(stackPtr, text, size);
	return stackPtr;
}

string StrToLower(const string& str) {
	string result;
	for(size_t i = 0; i < str.length(); ++i) {
		char c = str[i];
		if(c >= 'A' && c <= 'Z') {
			result += c + ('a' - 'A');
		} else {
			result += c;
		}
	}
	return result;
}

vector<string> StrSplit(string s, string delimiter) {
	size_t pos_start = 0, pos_end, delim_len = delimiter.length();
	string token;
	vector<string> res;

	while ((pos_end = s.find(delimiter, pos_start)) != string::npos) {
		token = s.substr(pos_start, pos_end - pos_start);
		pos_start = pos_end + delim_len;
		res.push_back(token);
	}

	res.push_back(s.substr(pos_start));
	return res;
}

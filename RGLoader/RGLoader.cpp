// XtweakXam.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include <xbdm.h>
#include <fstream>
#include <string>
#include <stdio.h>
#include "INIReader.h"
#include "xam.h"
#include "HUD.h"
#include "xshell.h"
#include "HvExpansion.h"
#include "OffsetManager.h"
#include "RPC.h"
// #include "sysext.h"

using namespace std;

static bool fKeepMemory = true;
static bool fExpansionEnabled = false;
static INIReader* reader;
static OffsetManager offsetmanager;
// static DWORD TitleID = 0;

#define setmem(addr, data) { DWORD d = data; memcpy((LPVOID)addr, &d, 4);}

#define XexLoadExecutableOrd 408
#define XexLoadImageOrd 409
#define XEXLOADIMAGE_MAX_SEARCH 9

#define XEXLOAD_DASH    "\\Device\\Flash\\dash.xex"
#define XEXLOAD_DASH2   "\\SystemRoot\\dash.xex"
#define XEXLOAD_SIGNIN  "signin.xex"
#define XEXLOAD_CREATE  "createprofile.xex"
#define XEXLOAD_HUD	    "hud.xex"
#define XEXLOAD_XSHELL  "xshell.xex"
#define XEXLOAD_DEFAULT "default.xex"

/*void setmem(DWORD addr, DWORD data) {
	UINT64 d = data;
	if(addr < 0x40000)
	{
		// hv patch
		if(fExpansionEnabled)
		{
			printf("     (hv patch)\n");
			addr = addr | 0x8000000000000000ULL;
			BYTE* newdata = (BYTE*)XPhysicalAlloc(sizeof(DWORD), MAXULONG_PTR, 0, PAGE_READWRITE);
			memcpy(newdata, &d, sizeof(DWORD));
			writeHVPriv(newdata, addr, sizeof(DWORD));
			XPhysicalFree(newdata);
		}
		else
			printf("     (hv patch, but expansion didn't install :( )\n");
	}
	else
		DmSetMemory((LPVOID)addr, 4, &d, NULL);
}*/

BOOL ExpansionStuff() {
	/*
	0xC8007000 // address alignment fail
	0xC8007001 // size alignment fail
	0xC8007002 // magic/rsa sanity fail
	0xC8007003 // flags/size sanity fail
	0xC8007004 // inner header fail
	0xC8007005 // ...
	*/

	RGLPrint("EXPANSION", "Checking if the HVPP expansion is installed...\n");
	if (HvPeekWORD(0) != 0x5E4E) {
		// install signed and encrypted HVPP expansion
		RGLPrint("EXPANSION", "Installing HVPP expansion...\n");
		DWORD ret = InstallExpansion();
		if (ret != ERROR_SUCCESS) {
			RGLPrint("EXPANSION", "InstallExpansion: %04X\n", ret);
			return FALSE;
		}
		RGLPrint("EXPANSION", "Done!\n");
	}
	else
		RGLPrint("EXPANSION", "Expansion is already installed, skipping...\n");

	return TRUE;
}

BOOL CPUStuff() {
	RGLPrint("CPU", "CPU key: ");
	BYTE CPUKeyHV[0x10];
	HvPeekBytes(0x20, CPUKeyHV, 0x10);
	HexPrint(CPUKeyHV, 0x10);
	printf("\n");

	return TRUE;
}

BOOL FuseStuff() {
	QWORD fuselines[12];
	for (int i = 0; i < 12; i++) {
		fuselines[i] = HvPeekQWORD(0x8000020000020000 + (i * 0x200));
	}
	for (int i = 0; i < 12; i++) {
		HexPrint((PBYTE)&fuselines[i], 8);
		printf("\n");
	}

	return TRUE;
}

BOOL KeyVaultStuff() {
	BYTE cpuKey[0x10] = { 0 };
	BYTE kvBuf[0x4000] = { 0 };
	BYTE kvHash[0x14] = { 0 };
	PBYTE kvData = kvBuf + 0x18;

	// 17489/21256.18
	QWORD ppKvAddr = 0x2000162E0;
	QWORD pMasterPub = 0x200011008;

	QWORD pKvAddr = HvPeekQWORD(ppKvAddr);  // keyvault pointer in HV
	// grab the CPU key and KV from the HV
	// there's way better ways to grab the CPU key than this!
	HvPeekBytes(0x18, cpuKey, 0x10);
	// grab the KV
	HvPeekBytes(pKvAddr, kvBuf, 0x4000);

	// calculate the KV hash
	XeCryptHmacSha(cpuKey, 0x10, kvData + 4, 0xD4, kvData + 0xE8, 0x1CF8, kvData + 0x1EE0, 0x2108, kvHash, 0x14);

	BYTE masterPub[sizeof(XECRYPT_RSAPUB_2048)];
	// master public key in the HV
	HvPeekBytes(pMasterPub, masterPub, sizeof(XECRYPT_RSAPUB_2048));

	RGLPrint("KV", "Console Serial: %s\n", kvBuf + 0xB0);

	if (XeCryptBnDwLePkcs1Verify(kvHash, kvData + 0x1DE0, sizeof(XECRYPT_SIG)) == TRUE)
		RGLPrint("WARNING", "KV hash is valid for this console!\n");
	else
		RGLPrint("WARNING", "KV hash is invalid for this console!\n");

	return TRUE;
}

void PatchBlockLIVE(){
	RGLPrint("PROTECTIONS", " * Blocking Xbox Live DNS\r\n");

	char* nullStr = "NO.%sNO.NO\0";
	DWORD nullStrSize = 18;

	XAMOffsets* offsets = offsetmanager.GetXAMOffsets();
	if(!offsets)
	{
		RGLPrint("ERROR", "Failed to load DNS offsets!\r\n");
		return;
	}

	// null out xbox live dns tags
	if(offsets->live_siflc)  //FIXME: check the others
		memcpy( (LPVOID)offsets->live_siflc, (LPCVOID)nullStr, nullStrSize);
	memcpy((LPVOID)offsets->live_piflc, (LPCVOID)nullStr, nullStrSize);
	memcpy((LPVOID)offsets->live_notice, (LPCVOID)nullStr, nullStrSize);
	memcpy((LPVOID)offsets->live_xexds, (LPCVOID)nullStr, nullStrSize);
	memcpy((LPVOID)offsets->live_xetgs, (LPCVOID)nullStr, nullStrSize);
	memcpy((LPVOID)offsets->live_xeas, (LPCVOID)nullStr, nullStrSize);
	memcpy((LPVOID)offsets->live_xemacs, (LPCVOID)nullStr, nullStrSize);
}

// Enable USBMASS0-2 in neighborhood
void PatchMapUSB(void) {

	XBDMOffsets* offsets = offsetmanager.GetXBDMOffsets();
	if(!offsets)
	{
		RGLPrint("ERROR", "Failed to load XBDM offsets!\n");
		return;
	}

	RGLPrint("INFO", " * Adding extra devices to xbox neighborhood\r\n");
	DWORD MapInternalDrivesAddr = 0x91F2F0F8;
	typedef VOID(*MAPINTERNALDRIVES)(VOID);
	MAPINTERNALDRIVES MapInternalDrives = (MAPINTERNALDRIVES)MapInternalDrivesAddr;
	DWORD addr = MapInternalDrivesAddr + (sizeof(DWORD) * 3); // skip three instructions from the function start
	while(true) {
		// grab in blocks of 6 instructions
		DWORD inst0 = *(PDWORD)addr;  // lis r11, -0x6800
		DWORD inst1 = *(PDWORD)(addr + sizeof(DWORD));  // lis r10, -0x6800
		DWORD inst2 = *(PDWORD)(addr + (sizeof(DWORD) * 2));  // addi r4, r11, (stack offset)
		DWORD inst3 = *(PDWORD)(addr + (sizeof(DWORD) * 3));  // addi r3, r10, (stack offset)
		DWORD inst4 = *(PDWORD)(addr + (sizeof(DWORD) * 4));  // li r5, 0x0 or li r5, 0x1
		DWORD inst5 = *(PDWORD)(addr + (sizeof(DWORD) * 5));  // bl MapDebugDrive
		
		// sanity checks
		if (inst0 != 0x3D609800 || inst1 != 0x3D409800)  // lis r11, -0x6800 && lis r10, -0x6800
			break;
		if ((WORD)((inst2 >> 16) & 0xFFFF) != 0x388B || (WORD)((inst3 >> 16) & 0xFFFF) != 0x386A)
			break;
		if ((WORD)((inst5 >> 16) & 0xFFFF) != 0x4BFF)
			break;
		if(inst4 == 0x38A00000) // li r5, 0
			*(PDWORD)addr = 0x38A00001;  // li r5, 1

		addr += (sizeof(DWORD) * 6);
	}
	MapInternalDrives();

	/* typedef VOID(*MAPDEBUGDRIVE)(PCHAR mntName, PCHAR mntPath, BYTE mntEnable);
	MAPDEBUGDRIVE MapDebugDrive = (MAPDEBUGDRIVE)0x91F2EF60;

	MapDebugDrive((PCHAR)(0x98002058 - 0x6100000), (PCHAR)(0x980008b4 - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98002054 - 0x6100000), (PCHAR)(0x9800094c - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98002050 - 0x6100000), (PCHAR)(0x9800092c - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98002048 - 0x6100000), (PCHAR)(0x98000970 - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98002040 - 0x6100000), (PCHAR)(0x98000904 - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98002038 - 0x6100000), (PCHAR)(0x98000918 - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x9800202c - 0x6100000), (PCHAR)(0x98000980 - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98002020 - 0x6100000), (PCHAR)(0x98000990 - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98002014 - 0x6100000), (PCHAR)(0x980009a0 - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98002008 - 0x6100000), (PCHAR)(0x980009ec - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98001ffc - 0x6100000), (PCHAR)(0x98000a08 - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98001ff0 - 0x6100000), (PCHAR)(0x98000a30 - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98001fe8 - 0x6100000), (PCHAR)(0x98000a58 - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98001fdc - 0x6100000), (PCHAR)(0x98000a78 - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98001fcc - 0x6100000), (PCHAR)(0x98000a9c - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98001fbc - 0x6100000), (PCHAR)(0x98000ac4 - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98001fb4 - 0x6100000), (PCHAR)(0x98000aec - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98001fa8 - 0x6100000), (PCHAR)(0x98000b0c - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98001f98 - 0x6100000), (PCHAR)(0x98000b30 - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98001f88 - 0x6100000), (PCHAR)(0x98000b58 - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98001f80 - 0x6100000), (PCHAR)(0x98000b80 - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98001f78 - 0x6100000), (PCHAR)(0x98000b94 - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98001f6c - 0x6100000), (PCHAR)(0x98000bac - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98001f5c - 0x6100000), (PCHAR)(0x98000bc0 - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98001f50 - 0x6100000), (PCHAR)(0x98000bd8 - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98001f44 - 0x6100000), (PCHAR)(0x98000bfc - 0x6100000), 1);
	MapDebugDrive((PCHAR)(0x98001f34 - 0x6100000), (PCHAR)(0x98000c20 - 0x6100000), 1); */
}

//21076
// Changes the default dashboard
void PatchDefaultDash(string path) {
	RGLPrint("INFO", " * Reconfiguring default dash to: %s\n", path);
	
	ofstream dashxbx;

	//dashxbx.open("Hdd:\\Filesystems\14719-dev\dashboard.xbx", ofstream::out);
	dashxbx.open("Root:\\dashboard.xbx", ofstream::out);

	if(dashxbx.is_open()) {
		dashxbx << path;
		for(int i = path.length(); i < 0x100; i++)
			dashxbx << '\0';
		dashxbx.close();
	} else {
		RGLPrint("ERROR", "unable to write dashboard.xbx\n");
	}
}

bool StrCompare(char* one, char* two, int len) {
	for(int i = 0; i < len; i++){
		if(i > 0 && (one[i] == '\0' || two[i] == '\0'))
			return true; 
		if(one[i] != two[i])
			return false;
	}
	return true;
}

VOID __declspec(naked) XexpLoadImageSaveVar(VOID)
{
	__asm{
		li r3, 454 //make this unique for each hook
		nop
		nop
		nop
		nop
		nop
		nop
		blr
	}
}

NTSTATUS XexpLoadImageHook(LPCSTR xexName, DWORD typeInfo, DWORD ver, PHANDLE modHandle);
typedef NTSTATUS (*XEXPLOADIMAGEFUN)(LPCSTR xexName, DWORD typeInfo, DWORD ver, PHANDLE modHandle); // XexpLoadImage
int PatchHookXexLoad(void) {
	//printf(" * Hooking xeximageload for persistant patches\n");
	//hookImpStubDebug("xam.xex", "xboxkrnl.exe", XexLoadExecutableOrd, (DWORD)XexLoadExecutableHook);
	//hookImpStubDebug("xam.xex", "xboxkrnl.exe", XexLoadImageOrd, (DWORD)XexLoadImageHook);
	
	PDWORD xexLoadHookAddr = (PDWORD)FindInterpretBranchOrdinal("xboxkrnl.exe", XexLoadImageOrd, XEXLOADIMAGE_MAX_SEARCH);
	// InfoPrint("  - Found addr\r\n");
	if(xexLoadHookAddr != NULL)
	{
		//printf("  - Applying hook at %08X  with  save @ %08X\r\n", xexLoadHookAddr, (PDWORD)XexpLoadImageSaveVar);
		HookFunctionStart(xexLoadHookAddr, (PDWORD)XexpLoadImageSaveVar, (DWORD)XexpLoadImageHook);
	}

	return 1;
}

XEXPLOADIMAGEFUN XexpLoadImageSave = (XEXPLOADIMAGEFUN)XexpLoadImageSaveVar;
NTSTATUS XexpLoadImageHook(LPCSTR xexName, DWORD typeInfo, DWORD ver, PHANDLE modHandle) {
	NTSTATUS ret = XexpLoadImageSave(xexName, typeInfo, ver, modHandle);

	// DWORD tid = XamGetCurrentTitleId();

	// InfoPrint("New Title ID: 0x%04X\n", tid);

	if (ret >= 0) {
		if (stricmp(xexName, XEXLOAD_HUD) == 0) {
			// printf("\n\n ***RGLoader.xex*** \n   -Re-applying patches to: %s!\n\n", xexName);
			
			bool hudJumpToXShell = reader->GetBoolean("Expansion", "HudJumpToXShell", true);
			if (hudJumpToXShell) {
				// printf("     * Replacing family settings button with \"Jump to XShell\"");
				PatchHudReturnToXShell();
			}
		} else if (stricmp(xexName, XEXLOAD_XSHELL) == 0) {
			// printf("\n\n ***RGLoader.xex*** \n   -Re-applying patches to: %s!\n\n", xexName);
	
			string redirectXShellButton = reader->GetString("Config", "RedirectXShellButton", "none");
			if(redirectXShellButton != "none" && FileExists(redirectXShellButton.c_str())) {
				// printf("     * Remapping xshell start button to %s.\n\n", rTemp.c_str());
				PatchXShellStartPath(redirectXShellButton);
			}
		} else if (stricmp(xexName, XEXLOAD_SIGNIN) == 0) {
			//printf("\n\n ***RGLoader.xex*** \n   -Re-applying patches to: %s!\n", xexName);

			bool noSignInNotice = reader->GetBoolean("Config", "NoSignInNotice", false);
			if(noSignInNotice) {
				// printf("     * Disabling xbox live sign in notice.\n\n");
				SIGNINOffsets* offsets = offsetmanager.GetSigninOffsets();
				if (offsets != NULL) {
					setmem(offsets->NoSignInNotice, 0x38600000);
				} else {
					RGLPrint("ERROR", "Failed to load signin offsets!\r\n");
				}
			}
		}
	}
	return ret;
}

DWORD PatchApplyBinary(string filepath) {
	DWORD fileSize = (DWORD)FileSize(filepath.c_str());
	if (fileSize == -1) {
		RGLPrint("ERROR", "Invalid patch path\n");
		return FALSE;
	}
	if (fileSize % 4 != 0) {
		RGLPrint("ERROR", "Invalid patch size\n");
		return FALSE;
	}
	BYTE* patchData = new BYTE[fileSize];
	if (!ReadFile(filepath.c_str(), patchData, fileSize)) {
		RGLPrint("ERROR", "Unable to read patch file\n");
		return FALSE;
	}

	DWORD offset = 0;
	DWORD patchesApplied = 0;
	if(*(DWORD*)&patchData[offset] == 0x52474C50)  // RGLP
		offset += 4;
	DWORD dest = *(DWORD*)&patchData[offset];
	offset += 4;

	while(dest != 0xFFFFFFFF && offset < fileSize){
		DWORD numPatches = *(DWORD*)&patchData[offset];
		offset += 4;
		for(DWORD i = 0; i < numPatches; i++, offset += 4, dest += 4) {
			// printf("     %08X  -> 0x%08X\n", dest, *(DWORD*)&buffer[offset]);
			setmem(dest, *(DWORD*)&patchData[offset]);
		}
		dest = *(DWORD*)&patchData[offset];
		offset += 4;
		patchesApplied++;
	}
	return patchesApplied;
}


void PatchSearchBinary(void) {
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind;

	RGLPrint("INFO", " * Searching for additional RGLP binary patch files\n");

	// HDD
	hFind = FindFirstFile("HDD:\\*.rglp", &FindFileData);
	while (hFind != INVALID_HANDLE_VALUE) {
		RGLPrint("INFO", "  **located binary: %s\n", FindFileData.cFileName);

		if (PatchApplyBinary("HDD:\\" + (string)FindFileData.cFileName) <= 0)
			RGLPrint("ERROR", "Cannot apply patch\n");

		if (!FindNextFile(hFind, &FindFileData))
			hFind = INVALID_HANDLE_VALUE;
	}

	// USB
	hFind = FindFirstFile("Mass0:\\*.rglp", &FindFileData);
	while (hFind != INVALID_HANDLE_VALUE) {
		RGLPrint("INFO", "  **located binary: %s\n", FindFileData.cFileName);

		if (PatchApplyBinary("Mass0:\\" + (string)FindFileData.cFileName) <= 0)
			RGLPrint("ERROR", "Cannot apply patch\n");

		if (!FindNextFile(hFind, &FindFileData))
			hFind = INVALID_HANDLE_VALUE;
	}
}

VOID LoadPlugins() {
	string temp = reader->GetString("Plugins", "Plugin1", "none");
	if(temp != "none" && FileExists(temp.c_str())) {
		if (XexLoadImage(temp.c_str(), 8, 0, NULL))
			RGLPrint("ERROR", "Failed to load %s", temp.c_str());
	}
	temp = reader->GetString("Plugins", "Plugin2", "none");
	if (temp != "none" && FileExists(temp.c_str())) {
		if (XexLoadImage(temp.c_str(), 8, 0, NULL))
			RGLPrint("ERROR", "Failed to load %s", temp.c_str());
	}
	temp = reader->GetString("Plugins", "Plugin3", "none");
	if (temp != "none" && FileExists(temp.c_str())) {
		if (XexLoadImage(temp.c_str(), 8, 0, NULL))
			RGLPrint("ERROR", "Failed to load %s", temp.c_str());
	}
	temp = reader->GetString("Plugins", "Plugin4", "none");
	if (temp != "none" && FileExists(temp.c_str())) {
		if (XexLoadImage(temp.c_str(), 8, 0, NULL))
			RGLPrint("ERROR", "Failed to load %s", temp.c_str());
	}
	temp = reader->GetString("Plugins", "Plugin5", "none");
	if (temp != "none" && FileExists(temp.c_str())) {
		if(XexLoadImage(temp.c_str(), 8, 0, NULL))
			RGLPrint("ERROR", "Failed to load %s", temp.c_str());
	}
}

BOOL Initialize(HANDLE hModule) {
	RGLPrint("INFO", "===RGLoader Runtime Patcher - Version 02===\n");

	Mount("\\Device\\Harddisk0\\Partition1", "\\System??\\Hdd:");
	Mount("\\Device\\Harddisk0\\Partition1", "\\System??\\HDD:");

	Mount("\\Device\\Mass0", "\\System??\\Mass0:");
	Mount("\\Device\\Mass1", "\\System??\\Mass1:");
	Mount("\\Device\\Mass2", "\\System??\\Mass2:");

	Mount("\\SystemRoot", "\\System??\\Root:");

	// install the expansion
	fExpansionEnabled = (ExpansionStuff() == TRUE);
	
	// check for ini
	reader = new INIReader("Mass0:\\rgloader.ini");
	if(reader->ParseError() < 0)
		reader = new INIReader("Mass1:\\rgloader.ini");
	if(reader->ParseError() < 0)
		reader = new INIReader("Mass2:\\rgloader.ini");
	if(reader->ParseError() < 0)
		reader = new INIReader("Hdd:\\rgloader.ini");

	if(reader->ParseError() < 0) {
		RGLPrint("ERROR", "Unable to open ini file!\r\n");
		PatchMapUSB();
		fKeepMemory = false;
		return FALSE;
	}

	/* DWORD dbgMemStatus;
	if (DmGetConsoleDebugMemoryStatus(&dbgMemStatus) == XBDM_NOERR) {
		if (dbgMemStatus == DM_CONSOLEMEMCONFIG_ADDITIONALMEMENABLED) {
			DWORD dbgMemSize;
			if (DmGetDebugMemorySize(&dbgMemSize) == XBDM_NOERR) {
				if (dbgMemSize > 0) {
					RGLPrint("XDK-GB", "0x%04X\r\n", dbgMemSize);
					PBYTE dbgMem = (PBYTE)DmDebugAlloc(4096);
					RGLPrint("XDK-GB", "0x%04X\r\n", dbgMem);
					memset(dbgMem, 0xAA, 4096);
					DmDebugFree(dbgMem);
				}
			}
		}
	} */

	/*
	char* SysExtPath = "HDD:\\Filesystems\\17489-dev\\$SystemUpdate";
	if (FileExists(SysExtPath)) {
		printf(" * Attemping to install system extended partion from %s\n", SysExtPath);

		if (setupSysPartitions(SysExtPath) == ERROR_SEVERITY_SUCCESS)
			printf("  -Success!\n");
		else
			printf("  -Failed\n");

		printf(" * Fixing XAM FEATURES\n");
#define XamFeatureEnableDisable 0x817483A8
		((void(*)(...))XamFeatureEnableDisable)(1, 2);
		((void(*)(...))XamFeatureEnableDisable)(1, 3);
		((void(*)(...))XamFeatureEnableDisable)(1, 4);

		((void(*)(...))XamFeatureEnableDisable)(0, 1);
		((void(*)(...))XamFeatureEnableDisable)(0, 5);
		((void(*)(...))XamFeatureEnableDisable)(0, 6);
		((void(*)(...))XamFeatureEnableDisable)(0, 7);
		((void(*)(...))XamFeatureEnableDisable)(0, 0x21);
		((void(*)(...))XamFeatureEnableDisable)(0, 0x22);
		((void(*)(...))XamFeatureEnableDisable)(0, 0x23);
		((void(*)(...))XamFeatureEnableDisable)(0, 0x24);
		((void(*)(...))XamFeatureEnableDisable)(0, 0x26);
		((void(*)(...))XamFeatureEnableDisable)(0, 0x27);
	}
	else {
		printf(" * No system extended files found, skipping..\n");
	}
	*/

	// booleans - config
	if (!reader->GetBoolean("Config", "NoRGLP", false))
		PatchSearchBinary();
	if (reader->GetBoolean("Config", "RPC", false)) {
		if (fExpansionEnabled)
			RPCServerStartup();
		else
			RGLPrint("INFO", "RPC is enabled in the config but the expansion isn't installed!\n");
	}
	// booleans - expansion
	if (reader->GetBoolean("Expansion", "MapUSBMass", false))
		PatchMapUSB();
	if (reader->GetBoolean("Expansion", "PersistentPatches", false))
		PatchHookXexLoad();
	if (reader->GetBoolean("Expansion", "BootAnimation", false) && FileExists("Root:\\RGL_bootanim.xex"))
		PatchDefaultDash("\\SystemRoot\\RGL_bootanim.xex");
	if (reader->GetBoolean("Expansion", "RetailProfileEncryption", false))
		XamProfileCryptoHookSetup();
	// booleans - protections
	if (reader->GetBoolean("Protections", "BlockLiveDNS", false))
		PatchBlockLIVE();
	bool disableExpansionInstall = reader->GetBoolean("Protections", "DisableExpansionInstall", true);
	bool disableShadowboots = reader->GetBoolean("Protections", "DisableShadowboot", true);
	
	// strings
	string defaultDashboard = reader->GetString("Config", "DefaultDashboard", "none");
	if (defaultDashboard != "none" && FileExists(defaultDashboard.c_str()))
		PatchDefaultDash(defaultDashboard);

	RGLPrint("INFO", "Patches successfully applied!\n");

	/* if(fExpansionEnabled)
	{
		bool ret = LoadKV("Mass0:\\rgkv.bin");
		if(!ret) ret = LoadKV("Mass1:\\rgkv.bin");
		if(!ret) ret = LoadKV("Mass2:\\rgkv.bin");
		if(!ret) ret = LoadKV("Hdd:\\rgkv.bin");
	} */

	if (fExpansionEnabled) {
		CPUStuff();
		// FuseStuff();
		KeyVaultStuff();

		if (disableExpansionInstall) {
			if (DisableExpansionInstalls() == TRUE)
				RGLPrint("PROTECTIONS", "HvxExpansionInstall unpatched successfully!\n");
		}

		if (disableShadowboots) {
			if (DisableShadowbooting() == TRUE)
				RGLPrint("PROTECTIONS", "HvxShadowboot disabled!\n");
		}
	}

	// skip plugin loading
	DVD_TRAY_STATE dts = XamLoaderGetDvdTrayState();
	if (dts == DVD_TRAY_STATE_OPENING || dts == DVD_TRAY_STATE_OPEN) {
		RGLPrint("INFO", "Skipping RGLoader plugin init...\n");
		return TRUE;
	}

	// register for title ID changes
	// ExRegisterThreadNotification(&xThreadReg, TRUE);

	// load plugins after expansion shit
	RGLPrint("INFO", "Loading plugins...\n");
	LoadPlugins();

	return TRUE;
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved) {
	if(dwReason == DLL_PROCESS_ATTACH) {
		Initialize(hModule);

		//set load count to 1
		if(!fKeepMemory) {
			*(WORD*)((DWORD)hModule + 64) = 1;
			return FALSE;
		} else return TRUE;
	}
	return TRUE;
}




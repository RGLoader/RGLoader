#include "stdafx.h"

BOOL MountStuff() {
	Mount("\\Device\\Harddisk0\\Partition1", "\\System??\\Hdd:");
	// Mount("\\Device\\Harddisk0\\Partition1", "\\System??\\HDD:");
	Mount("\\Device\\Mass0", "\\System??\\Mass0:");

	return TRUE;
}

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
		DWORD ret = InstallExpansions();
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

BOOL FuseStuff() {
	QWORD aqwFuses[0xC];

	for (int i = 0; i < 0xC; i++) {
		aqwFuses[i] = HvReadFuseRow(i);
	}

	for (int i = 0; i < 12; i++) {
		RGLPrint("FUSE", "0x%02X: ", i + 1);
		HexPrint((PBYTE)&aqwFuses[i], sizeof(QWORD));
		RGLNewLine();
	}

	QWORD aqwCpu[2];
	aqwCpu[0] = aqwFuses[3] | aqwFuses[4];
	aqwCpu[1] = aqwFuses[5] | aqwFuses[6];

	RGLPrint("FUSE", "CPU Key: ");
	HexPrint((PBYTE)aqwCpu, sizeof(QWORD) * 2);
	RGLNewLine();

	return TRUE;
}

BOOL KeyVaultStuff() {
	BYTE pbCpuKey[0x10] = { 0 };
	BYTE pbKvBuf[0x4000] = { 0 };
	BYTE pbKvHash[0x14] = { 0 };
	// PBYTE pbKvData = pbKvBuf + 0x18;

	PKEY_VAULT pKV = (PKEY_VAULT)pbKvBuf;

	// 17489/21256.18
	QWORD ppKvAddr = 0x2000162E0;
	QWORD pMasterPub = 0x200011008;

	QWORD pKvAddr = HvPeekQWORD(ppKvAddr);  // keyvault pointer in HV
	// grab the CPU key and KV from the HV
	// there's way better ways to grab the CPU key than this!
	HvPeekBytes(0x18, pbCpuKey, 0x10);
	// grab the KV
	HvPeekBytes(pKvAddr, pbKvBuf, 0x4000);

	// calculate the KV hash
	XeCryptHmacSha(pbCpuKey, 0x10, (PBYTE)&pKV->oddFeatures, 0xD4, pKV->dvdKey, 0x1CF8, pKV->cardeaCertificate, 0x2108, pbKvHash, 0x14);

	// BYTE pbMasterPub[sizeof(XECRYPT_RSAPUB_2048)];
	// master public key in the HV
	// HvPeekBytes(pMasterPub, pbMasterPub, sizeof(XECRYPT_RSAPUB_2048));

	RGLPrint("KV", "Console Serial: %s\n", pKV->consoleSerialNumber);
	RGLPrint("KV", "DVD Key: ");
	HexPrint(pKV->dvdKey, 0x10);
	RGLNewLine();

	if (XeCryptBnDwLePkcs1Verify(pbKvHash, pKV->keyVaultSignature, sizeof(XECRYPT_SIG)) == TRUE)
		RGLPrint("WARNING", "KV hash is valid for this console!\n");
	else
		RGLPrint("WARNING", "KV hash is invalid for this console!\n");

	return TRUE;
}

VOID PatchBlockLIVE(){
	RGLPrint("PROTECTIONS", " * Blocking Xbox Live DNS\n");

	char* nullStr = "NO.%sNO.NO\0";
	DWORD nullStrSize = 18;

	// XAMOffsets* offsets = offsetmanager.GetXAMOffsets();
	if(!RGLoader->Offsets->XAM)
	{
		RGLPrint("ERROR", "Failed to load DNS offsets!\n");
		return;
	}

	// null out xbox live dns tags
	if(RGLoader->Offsets->XAM->live_siflc)  //FIXME: check the others
		memcpy( (LPVOID)RGLoader->Offsets->XAM->live_siflc, (LPCVOID)nullStr, nullStrSize);
	memcpy((LPVOID)RGLoader->Offsets->XAM->live_piflc, (LPCVOID)nullStr, nullStrSize);
	memcpy((LPVOID)RGLoader->Offsets->XAM->live_notice, (LPCVOID)nullStr, nullStrSize);
	memcpy((LPVOID)RGLoader->Offsets->XAM->live_xexds, (LPCVOID)nullStr, nullStrSize);
	memcpy((LPVOID)RGLoader->Offsets->XAM->live_xetgs, (LPCVOID)nullStr, nullStrSize);
	memcpy((LPVOID)RGLoader->Offsets->XAM->live_xeas, (LPCVOID)nullStr, nullStrSize);
	memcpy((LPVOID)RGLoader->Offsets->XAM->live_xemacs, (LPCVOID)nullStr, nullStrSize);
}

// 21076
// Changes the default dashboard
VOID PatchDefaultDash(string path) {
	RGLPrint("INFO", " * Reconfiguring default dash to: %s\n", path);
	
	WriteFile("Root:\\dashboard.xbx", (char*)path.c_str(), path.size());
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
	if(*(DWORD*)&patchData[offset] == RGLP_MAGIC)  // RGLP
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

/* VOID FixSysAuxAndExt() {
	// Thanks to Diamond!
	DeleteLink("SysExt:", FALSE);
	DeleteLink("SysAux:", FALSE);

	char* extPath = "\\Device\\Harddisk0\\Partition1\\fs\\ext\\";
	char* auxPath = "\\Device\\Harddisk0\\Partition1\\fs\\aux\\";

	// create the directories used for aux/ext/flash
	CreateDirectory("\\Device\\Harddisk0\\Partition1\\fs\\", NULL);
	CreateDirectory(extPath, NULL);
	CreateDirectory(auxPath, NULL);

	// set paths
	strcpy((PCHAR)0x816090A8, "\\Device\\Harddisk0\\Partition1\\fs\\ext");
	strcpy((PCHAR)0x816090D0, "\\Device\\Harddisk0\\Partition1\\fs\\aux");
	strcpy((PCHAR)0x816106E0, extPath);
	strcpy((PCHAR)0x81610744, auxPath);
} */

VOID PatchSearchBinary() {
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
	if(RGLoader->Config->Plugins->Plugin1 != "none" && FileExists(RGLoader->Config->Plugins->Plugin1.c_str())) {
		if (XexLoadImage(RGLoader->Config->Plugins->Plugin1.c_str(), XEX_MODULE_FLAG_DLL, 0, NULL))
			RGLPrint("ERROR", "Failed to load %s", RGLoader->Config->Plugins->Plugin1.c_str());
	}
	if (RGLoader->Config->Plugins->Plugin2 != "none" && FileExists(RGLoader->Config->Plugins->Plugin2.c_str())) {
		if (XexLoadImage(RGLoader->Config->Plugins->Plugin2.c_str(), XEX_MODULE_FLAG_DLL, 0, NULL))
			RGLPrint("ERROR", "Failed to load %s", RGLoader->Config->Plugins->Plugin2.c_str());
	}
	if (RGLoader->Config->Plugins->Plugin3 != "none" && FileExists(RGLoader->Config->Plugins->Plugin3.c_str())) {
		if (XexLoadImage(RGLoader->Config->Plugins->Plugin3.c_str(), XEX_MODULE_FLAG_DLL, 0, NULL))
			RGLPrint("ERROR", "Failed to load %s", RGLoader->Config->Plugins->Plugin3.c_str());
	}
	if (RGLoader->Config->Plugins->Plugin4 != "none" && FileExists(RGLoader->Config->Plugins->Plugin4.c_str())) {
		if (XexLoadImage(RGLoader->Config->Plugins->Plugin4.c_str(), XEX_MODULE_FLAG_DLL, 0, NULL))
			RGLPrint("ERROR", "Failed to load %s", RGLoader->Config->Plugins->Plugin4.c_str());
	}
	if (RGLoader->Config->Plugins->Plugin5 != "none" && FileExists(RGLoader->Config->Plugins->Plugin5.c_str())) {
		if(XexLoadImage(RGLoader->Config->Plugins->Plugin5.c_str(), XEX_MODULE_FLAG_DLL, 0, NULL))
			RGLPrint("ERROR", "Failed to load %s", RGLoader->Config->Plugins->Plugin5.c_str());
	}
}

void Initialize() {
	RGLPrint("INFO", "=== RGLoader Runtime Patcher - Version 02 ===\n");

	// get power-on reason and tray state
	SMC_PWR_REAS res = GetSmcPowerOnReason();
	SMC_TRAY_STATE sta = GetSmcTrayState();

	RGLPrint("SMC", "GetSmcPowerOnReason: 0x%X\n", res);
	RGLPrint("SMC", "GetSmcTrayState:     0x%X\n", sta);

	// shutdown if console was started with eject or the tray is open
	if(res == SMC_PWR_REAS_12_EJECT || sta == SMC_TRAY_OPEN) {
		RGLPrint("INFO", "Console was started with eject or the tray was open, bailing!\n");
		return;
	}

	// disable was set so exit RGL
	if(RGLoader->Config->Disable) {
		RGLPrint("INFO", "Disable was set in the config, bailing!\n");
		return;
	}

	// install the expansion
	RGLoader->State->ExpansionEnabled = ExpansionStuff();

	// booleans - config
	if(!RGLoader->Config->NoRGLP)
		PatchSearchBinary();
	// booleans - expansion
	if(RGLoader->Config->Expansion->MountAllDrives)
		MountAllDrives();
	if(RGLoader->Config->Expansion->PersistentPatches)
		KernelHooksSetup();
	if(RGLoader->Config->Expansion->BootAnimation)
		PatchDefaultDash("\\SystemRoot\\RGL_bootanim.xex");
	if(RGLoader->Config->Expansion->ProfileEncryptionType == "retail" || RGLoader->Config->Expansion->ProfileEncryptionType == "devkit")
		XamProfileCryptoHookSetup();
	// booleans - protections
	if(RGLoader->Config->Protections->BlockLiveDNS)
		PatchBlockLIVE();
	// strings - config
	if (RGLoader->Config->DefaultDashboard != "none" && FileExists(RGLoader->Config->DefaultDashboard.c_str()))
		PatchDefaultDash(RGLoader->Config->DefaultDashboard);

	RGLPrint("INFO", "Patches successfully applied!\n");

	if (RGLoader->State->ExpansionEnabled) {
		FuseStuff();
		KeyVaultStuff();

		if (RGLoader->Config->Protections->DisableExpansionInstall) {
			if (DisableExpansionInstalls() == TRUE)
				RGLPrint("PROTECTIONS", "HvxExpansionInstall unpatched successfully!\n");
		}

		if (RGLoader->Config->Protections->DisableShadowboot) {
			if (DisableShadowbooting() == TRUE)
				RGLPrint("PROTECTIONS", "HvxShadowboot disabled!\n");
		}
	}

	if (RGLoader->Config->RPC) {
		RGLPrint("RPC", "RGLoader RPC started!\n");
		DmRegisterCommandProcessor("rgloader", HrRGL);
	}

	// XHTTP hooks to bypass XAUTH security
	XamNetworkingHookSetup();

	// load plugins after expansion shit
	RGLPrint("INFO", "Loading plugins...\n");
	LoadPlugins();
}

BOOL Shutdown() {
	delete RGLoader;

	return TRUE;
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved) {
	switch (dwReason) {
		case DLL_PROCESS_ATTACH: {
			// mount virtual drives
			MountStuff();

			// Initialize globals
			RGLoader = new Globals();
			RGLoader->State->Handle = hModule;

			HANDLE hThread; DWORD hThreadID;
			ExCreateThread(&hThread, 32 * 1024, &hThreadID, (PVOID)XapiThreadStartup, (LPTHREAD_START_ROUTINE)Initialize, NULL, 0x1C000427);
			XSetThreadProcessor(hThread, 4);
			ResumeThread(hThread);
			CloseHandle(hThread);

			return TRUE;
		}
		case DLL_PROCESS_DETACH: {
			HalReturnToFirmware(HalFatalErrorRebootRoutine);
			break;
		}
	}

	*(WORD*)((DWORD)hModule + 64) = 1;
	return FALSE;
}

#include "stdafx.h"

#pragma region Kernel
NTSTATUS XexpLoadImageHook(LPCSTR xexName, DWORD typeInfo, DWORD ver, PHANDLE modHandle) {
	NTSTATUS ret = RGLoader->Offsets->KERNEL->XexpLoadImage->Call<NTSTATUS>(xexName, typeInfo, ver, modHandle);

	if(ret >= 0) {
		if(stricmp(xexName, XEXLOAD_HUD) == 0) {
			// printf("\n\n ***RGLoader->xex*** \n   -Re-applying patches to: %s!\n\n", xexName);

			if(RGLoader->Config->Expansion->HudJumpToXShell) {
				// printf("     * Replacing family settings button with \"Jump to XShell\"");
				PatchHudReturnToXShell();
			}
		} else if(stricmp(xexName, XEXLOAD_XSHELL) == 0) {
			// printf("\n\n ***RGLoader->xex*** \n   -Re-applying patches to: %s!\n\n", xexName);

			if(RGLoader->Config->RedirectXShellButton != "none" && FileExists(RGLoader->Config->RedirectXShellButton.c_str())) {
				// printf("     * Remapping xshell start button to %s.\n\n", rTemp.c_str());
				PatchXShellStartPath(RGLoader->Config->RedirectXShellButton);
			}
		} else if(stricmp(xexName, XEXLOAD_SIGNIN) == 0) {
			//printf("\n\n ***RGLoader->xex*** \n   -Re-applying patches to: %s!\n", xexName);

			if(RGLoader->Config->NoSignInNotice) {
				// printf("     * Disabling xbox live sign in notice.\n\n");
				// SIGNINOffsets* offsets = offmgr.GetSigninOffsets();
				if(RGLoader->Offsets->SIGNIN) {
					setmem(RGLoader->Offsets->SIGNIN->NoSignInNotice, 0x38600000);
				} else {
					RGLPrint("ERROR", "Failed to load signin offsets!\r\n");
				}
			}
		}
	}

	return ret;
}

BOOL XeKeysUnObfuscateHook(XEKEY_OBFUSCATE keySel, const PBYTE pbInp1, DWORD cbInp1, PBYTE pbOut, PDWORD cbOut) {
	BYTE HmacKey[0x10];
	if (RGLoader->Config->Expansion->ProfileEncryptionType == "retail")
		memcpy(HmacKey, RetailKey, 0x10);
	else if (RGLoader->Config->Expansion->ProfileEncryptionType == "devkit")
		memcpy(HmacKey, DevkitKey, 0x10);
	else
		return RGLoader->Offsets->KERNEL->XeKeysUnObfuscate->Call<BOOL>(keySel, pbInp1, cbInp1, pbOut, cbOut);

	if(keySel == XEKEY_OBFUSCATE_ROAM) // From tests I did, profiles only called when set to 1
	{
		// Try with original key
		BOOL ret = RGLoader->Offsets->KERNEL->XeKeysUnObfuscate->Call<BOOL>(keySel, pbInp1, cbInp1, pbOut, cbOut);
		if(ret) // If pass: continue
			return ret;
		else // fail: swap key and try again
		{
			XECRYPT_RC4_STATE rc4State;
			BYTE hash[0x18];
			BYTE newHash[0x10];
			BYTE rc4Key[0x10];
			memcpy(hash, pbInp1, 0x18);
			memcpy(pbOut, pbInp1 + 0x18, cbInp1 - 0x18);
			XeCryptHmacSha((const PBYTE)HmacKey, 0x10, hash, 0x10, 0, 0, 0, 0, rc4Key, 0x10);
			XeCryptRc4Key(&rc4State, rc4Key, 0x10);
			XeCryptRc4Ecb(&rc4State, hash + 0x10, 0x8);
			XeCryptRc4Ecb(&rc4State, (BYTE*)pbOut, cbInp1 - 0x18);
			XeCryptHmacSha((const PBYTE)HmacKey, 0x10, hash + 0x10, 8, (const PBYTE)pbOut, cbInp1 - 0x18, 0, 0, newHash, 0x10);
			int result = memcmp(hash, newHash, 0x10);
			if(result == 0)
				return TRUE;
			return FALSE;
		}
	} else
		return RGLoader->Offsets->KERNEL->XeKeysUnObfuscate->Call<BOOL>(keySel, pbInp1, cbInp1, pbOut, cbOut);
}


BOOL XeKeysObfuscateHook(XEKEY_OBFUSCATE keySel, const PBYTE pbInp1, DWORD cbInp1, PBYTE pbOut, PDWORD cbOut) {
	BYTE HmacKey[0x10];
	if(RGLoader->Config->Expansion->ProfileEncryptionType == "retail")
		memcpy(HmacKey, RetailKey, 0x10);
	else if(RGLoader->Config->Expansion->ProfileEncryptionType == "devkit")
		memcpy(HmacKey, DevkitKey, 0x10);
	else
		return RGLoader->Offsets->KERNEL->XeKeysObfuscate->Call<BOOL>(keySel, pbInp1, cbInp1, pbOut, cbOut);

	if(keySel == XEKEY_OBFUSCATE_ROAM) {
		//copy decrypted data to 0x18+ of buffer
		memcpy(pbOut + 0x18, pbInp1, cbInp1);
		*cbOut = cbInp1 + 0x18;
		// Create random data then copy to 0x10
		XeCryptRandom(pbOut + 0x10, 8);
		// create a Hmac-Sha hash of the random data & decrypted data
		XeCryptHmacSha((BYTE*)HmacKey, 0x10, pbOut + 0x10, *cbOut - 0x10, 0, 0, 0, 0, pbOut, 0x10);
		BYTE rc4Key[0x10];
		// Hash previously created hash to make the RC4 key
		XeCryptHmacSha((BYTE*)HmacKey, 0x10, pbOut, 0x10, 0, 0, 0, 0, (BYTE*)rc4Key, 0x10);
		// Encrypt the data
		XeCryptRc4((const PBYTE)rc4Key, 0x10, pbOut + 0x10, *cbOut - 0x10);

		return TRUE;
	} else
		return RGLoader->Offsets->KERNEL->XeKeysObfuscate->Call<BOOL>(keySel, pbInp1, cbInp1, pbOut, cbOut);
}

HRESULT XexStartExecutableHook(FARPROC TitleProcessInitThreadProc) {
	// auto res = XexStartExecutableOrig(TitleProcessInitThreadProc);
	auto res = RGLoader->Offsets->KERNEL->XexStartExecutable->Call<HRESULT>(TitleProcessInitThreadProc);

	PLDR_DATA_TABLE_ENTRY pDTE = (PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle;
	XEX_EXECUTION_ID* pExeId = (XEX_EXECUTION_ID*)RtlImageXexHeaderField(pDTE->XexHeaderBase, XEX_HEADER_EXECUTION_ID);

	CHAR szTitlePluginPath0[MAX_PATH] = { 0 };
	CHAR szTitlePluginPattern[MAX_PATH] = { 0 };
	CHAR szTitlePluginPath1[MAX_PATH] = { 0 };
	sprintf(szTitlePluginPath0, "Hdd:\\Plugins\\Titles\\%08X\\", pExeId->TitleID);
	sprintf(szTitlePluginPattern, "Hdd:\\Plugins\\Titles\\%08X\\*.xex", pExeId->TitleID);

	if (!DirectoryExists(szTitlePluginPath0))
		return res;

	vector<string> vFiles = ListFiles(szTitlePluginPattern);
	for (int i = 0; i < vFiles.size(); i++) {
		string szFile = vFiles[i];

		memset(szTitlePluginPath1, 0, sizeof(szTitlePluginPath1));
		sprintf(szTitlePluginPath1, "Hdd:\\Plugins\\Titles\\%08X\\%s", pExeId->TitleID, szFile.c_str());

		if (!FileExists(szTitlePluginPath1))
			continue;

		RGLPrint("TITLE", "Loading title module from \"%s\" for Title ID 0x%08X...\n", szTitlePluginPath1, pExeId->TitleID);
		XexLoadImage(szTitlePluginPath1, XEX_MODULE_FLAG_DLL, 0, NULL);
	}

	return res;
}

BOOL KernelHooksSetup() {
	RGLoader->Offsets->KERNEL->XexpLoadImage->Hook(XexpLoadImageHook);

	RGLoader->Offsets->KERNEL->XexStartExecutable->Hook(XexStartExecutableHook);

	return TRUE;
}
#pragma endregion Kernel

#pragma region XAM
HRESULT XampXAuthStartupHook(XAUTH_SETTINGS* Settings) {
	Settings->Flags |= XAUTH_FLAG_BYPASS_SECURITY;
	return RGLoader->Offsets->XAM->XampXAuthStartup->Call<HRESULT>(Settings);
}

DWORD XamFindOrCreateInternalPassportAccountHook(PBYTE bCountryId, FILETIME fileTime, PWCHAR pwchGamertag, PVOID PassportSessionToken) {
	if(RGLoader->Config->Passport->Email == "none" || RGLoader->Config->Passport->Password == "none")
		goto XamFindOrCreateInternalPassportAccountHookEnd;

	if(RGLoader->Config->Passport->Email.size() > 64 || RGLoader->Config->Passport->Password.size() > 64)
		goto XamFindOrCreateInternalPassportAccountHookEnd;

	PCHAR cEmail = (PCHAR)RGLoader->Config->Passport->Email.c_str();
	PCHAR cPass = (PCHAR)RGLoader->Config->Passport->Password.c_str();

	WCHAR pwchEmail[64];
	WCHAR pwchPass[64];

	CharToWChar(cEmail, pwchEmail);
	CharToWChar(cPass, pwchPass);

	RGLPrint("PASSPORT", "Gamertag: %ws\n", pwchGamertag);
	RGLPrint("PASSPORT", "Email:    %s\n", cEmail);
	RGLPrint("PASSPORT", "Password: %s\n", cPass);

	DWORD dwAddr0 = 0x8160D8E4;
	DWORD dwAddr1 = 0x8160E254;
	DWORD dwAddr2 = 0x8160D858;
	DWORD dwAddr3 = 0x8160E23C;

	size_t sz0 = strlen((const PCHAR)dwAddr0);  // %ws@xboxtest.com (16)
	size_t sz1 = wcslen((const PWCHAR)dwAddr1);  // %s@xboxtest.com (30)
	size_t sz2 = strlen((const PCHAR)dwAddr2);  // supersecret (11)
	size_t sz3 = wcslen((const PWCHAR)dwAddr3);  // supersecret (22)

	if((0 < strlen(cEmail) <= sz0) &&
	   (0 < wcslen(pwchEmail) <= sz1) &&
	   (0 < strlen(cPass) <= sz2) &&
	   (0 < wcslen(pwchPass) <= sz3)) {

		FillMemory((PBYTE)dwAddr0, 0, sz0);
		FillMemory((PBYTE)dwAddr1, 0, sz1);
		FillMemory((PBYTE)dwAddr2, 0, sz2);
		FillMemory((PBYTE)dwAddr3, 0, sz3);

		strcpy((PCHAR)dwAddr0, cEmail);
		wcscpy((PWCHAR)dwAddr1, pwchEmail);
		strcpy((PCHAR)dwAddr2, cPass);
		wcscpy((PWCHAR)dwAddr3, pwchPass);
	} else {
		RGLPrint("PASSPORT", "Failed to create gamertag, email and password length check failed!\n");
	}
XamFindOrCreateInternalPassportAccountHookEnd:

	return RGLoader->Offsets->XAM->XamFindOrCreateInternalPassportAccount->Call<DWORD>(bCountryId, fileTime, pwchGamertag, PassportSessionToken);
}

BOOL XamNetworkingHookSetup() {
	RGLoader->Offsets->XAM->XampXAuthStartup->Hook(XampXAuthStartupHook);
	return TRUE;
}

BOOL XamProfileCryptoHookSetup() {
	RGLoader->Offsets->KERNEL->XeKeysObfuscate->HookImportStub(MODULE_XAM, MODULE_KERNEL, 0x254, XeKeysObfuscateHook);
	RGLoader->Offsets->KERNEL->XeKeysUnObfuscate->HookImportStub(MODULE_XAM, MODULE_KERNEL, 0x255, XeKeysUnObfuscateHook);
	return TRUE;
}

BOOL XamFindOrCreateInternalPassportAccountHookSetup() {
	RGLoader->Offsets->XAM->XamFindOrCreateInternalPassportAccount->Hook(XamFindOrCreateInternalPassportAccountHook);
	return TRUE;
}
#pragma endregion XAM

#pragma region XBDM
void MapDebugDriveHook(const PCHAR szMntName, const PCHAR szMntPath, BOOL bEnable) {
	return RGLoader->Offsets->XBDM->MapDebugDrive->Call<void>(szMntName, szMntPath, TRUE);
}

// Enable USBMASS0-2 in neighborhood
void MountAllDrives() {
	RGLPrint("INFO", " * Adding extra devices to xbox neighborhood\r\n");
	RGLoader->Offsets->XBDM->MapDebugDrive->Hook(MapDebugDriveHook);
	RGLoader->Offsets->XBDM->MapInternalDrives->Call<void>();
}
#pragma endregion XBDM

#pragma region HUD
DWORD HudBootToDashHelperHook(DWORD* _XUIOBJ, _XDASHLAUNCHDATA* LaunchData, DWORD* cstr, DWORD* r6, DWORD* r7) {
	/*printf("\n\n ***RGLoader.xex*** \n");
	printf("  -LaunchData- \n");
	printf("      dwVersion: 0x%X\n", LaunchData->dwVersion);
	printf("      dwCommand: 0x%X\n", LaunchData->dwCommand);
	printf("      dwUserIndex: 0x%X\n", LaunchData->dwUserIndex);*/

	// HUDOffsets* offsets = offmgr.GetHUDOffsets();
	if(!RGLoader->Offsets->HUD)
		return -1;

	if(LaunchData->dwCommand == (DWORD)RGLoader->Offsets->HUD->LaunchData_FamilySettings) {
		RGLPrint("HUD", "Jumping back to xshell!\n");
		XSetLaunchData(NULL, 0);

		XamLoaderLaunchTitleEx("\\SystemRoot\\xshell.xex", "\\SystemRoot", NULL, 0);

		// close HUD menu
		setmemdm((DWORD)((unsigned long)0x60 + (unsigned long)r7), 0);
		setmemdm((DWORD)((unsigned long)0x5C + (unsigned long)r7), 0);
		return 0;
	} else {
		return RGLoader->Offsets->HUD->BootToDashHelper->Call<DWORD>(_XUIOBJ, LaunchData, cstr, r6, r7);
	}
}
#pragma endregion HUD
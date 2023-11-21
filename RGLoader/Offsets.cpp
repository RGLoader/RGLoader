#include "stdafx.h"

PSOffsets PopulateOffsets() {
	PSOffsets offs = new SOffsets();

	offs->KERNEL->KiShadowBoot = new SCallable(0x800966A0);
	offs->KERNEL->XexpLoadImage = new SCallable(MODULE_KERNEL, XexLoadImageOrd, XEXLOADIMAGE_MAX_SEARCH);
	offs->KERNEL->XexStartExecutable = new SCallable((DWORD)XexStartExecutable);
	offs->KERNEL->XeKeysObfuscate = new SCallable((DWORD)XeKeysObfuscate);
	offs->KERNEL->XeKeysUnObfuscate = new SCallable((DWORD)XeKeysUnObfuscate);

	offs->XAM->live_siflc = 0x8161EB14;
	offs->XAM->live_piflc = 0x8161EB2C;
	offs->XAM->live_notice = 0x8161EB44;
	offs->XAM->live_xexds = 0x8161EB58;
	offs->XAM->live_xetgs = 0x8161EB70;
	offs->XAM->live_xeas = 0x8161EB88;
	offs->XAM->live_xemacs = 0x8161EB9C;
	offs->XAM->XampXAuthStartup = new SCallable(0x819AECE8);
	offs->XAM->XamFindOrCreateInternalPassportAccount = new SCallable(MODULE_XAM, 0x4E5);

	offs->SIGNIN->NoSignInNotice = 0x9011841C;

	offs->XSHELL->loc1 = 0x9203EC14;
	offs->XSHELL->loc2 = 0x9204A564;
	offs->XSHELL->loc3 = 0x9204D734;
	offs->XSHELL->loc4 = 0x92065454;

	offs->HUD->FamilySettings_LaunchStr = 0x913F12D4;
	offs->HUD->BootToDashHelper_Jump = 0x913E7498;
	offs->HUD->LaunchData_FamilySettings = 0x14;
	offs->HUD->BootToDashHelper = new SCallable(0x913E72C0);
	offs->HUD->FamilySettings_Str1 = 0x119B8;
	offs->HUD->FamilySettings_Str2 = 0x11F02;

	offs->XBDM->MapDebugDrive = new SCallable(0x91F2EF60);
	offs->XBDM->MapInternalDrives = new SCallable(0x91F2F0F8);
	offs->XBDM->GetParam = new SCallable(0x91F41800);
	offs->XBDM->PchGetParam = new SCallable(0x91F41650);
	offs->XBDM->FGetSzParam = new SCallable(0x91F41898);
	offs->XBDM->FGetDwParam = new SCallable(0x91F418F0);
	offs->XBDM->FGetNamedDwParam = new SCallable(0x91F41B38);
	offs->XBDM->FGetQwordParam = new SCallable(0x91F41978);

	return offs;
}
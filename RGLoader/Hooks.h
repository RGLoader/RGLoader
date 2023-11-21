#pragma once

#pragma region Kernel
static BYTE RetailKey[0x10] = { 0xE1, 0xBC, 0x15, 0x9C, 0x73, 0xB1, 0xEA, 0xE9, 0xAB, 0x31, 0x70, 0xF3, 0xAD, 0x47, 0xEB, 0xF3 };  // retail key
static BYTE DevkitKey[0x10] = { 0xDA, 0xB6, 0x9A, 0xD9, 0x8E, 0x28, 0x76, 0x4F, 0x97, 0x7E, 0xE2, 0x48, 0x7E, 0x4F, 0x3F, 0x68 };  // devkit key

static XEXPLOADIMAGE XexpLoadImageOrig;
static XEXSTARTEXECUTABLE XexStartExecutableOrig;

BOOL KernelHooksSetup();
#pragma endregion Kernel

#pragma region XAM
static XAMPXAUTHSTARTUP XampXAuthStartupOrig;
static XAMFINDORCREATEINTERNALPASSPORTACCOUNT XamFindOrCreateInternalPassportAccountOrig;

BOOL XamProfileCryptoHookSetup();
BOOL XamNetworkingHookSetup();
BOOL XamFindOrCreateInternalPassportAccountHookSetup();
#pragma endregion XAM

#pragma region XBDM
static MAPDEBUGDRIVE MapDebugDriveOrig;

void MountAllDrives();
#pragma endregion XBDM

#pragma region HUD
DWORD HudBootToDashHelperHook(DWORD* _XUIOBJ, _XDASHLAUNCHDATA* LaunchData, DWORD* cstr, DWORD* r6, DWORD* r7);

int PatchHudReturnToXShell();
#pragma endregion HUD
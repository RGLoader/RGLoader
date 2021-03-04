#include "OffsetManager.h"

// XBDM offsets
XBDMOffsets XBDM_17489 = {
	// mass0
	0x91F96F68,
	(0x91F96F68 + 0x28),
	0x91F00980,
	// mass1
	0x91F96F94,
	(0x91F96F94 + 0x28),
	0x91F00990,
	// mass2
	0x91F96FC0,
	(0x91F96FC0 + 0x28),
	0x91F009A0,
	// flash
	0x91F96EE4,
	(0x91F96EE4 + 0x28),
	0x91F00970,
	// hddsysext
	0x91F97044,
	(0x91F97044 + 0x28),
	0x91F00A08,
	// intusbsysext
	0x91F970C8,
	(0x91F970C8 + 0x28),
	0x91F00A9C,
	// hddsysaux
	0x91F97070,
	(0x91F97070 + 0x28),
	0x91F00A30,
	// Y
	0x91F96E8C,
	(0x91F96E8C + 0x28),
	0x91F0094C,
	// check
	0x91F329DC
};
//XBDMOffsets xbdm_17502 = xbdm_17489;
//XBDMOffsets xbdm_17511 = xbdm_17489;
//XBDMOffsets xbdm_17526 = xbdm_17489;

// XAM offsets
XAMOffsets XAM_17489 = {
	0x8161EB14, // siflc
	0x8161EB2C, // piflc
	0x8161EB44, // notice
	0x8161EB58, // xexds
	0x8161EB70, // xetgs
	0x8161EB88, // xeas
	0x8161EB9C, // xemacs
};
//XAMOffsets xam_17502 = xam_17489;
//XAMOffsets xam_17511 = xam_17489;
//XAMOffsets xam_17526 = xam_17489;

// Signin offsets
SIGNINOffsets Signin_17489 = {
	0x9011841C
};
//SIGNINOffsets signin_17502 = signin_17489;
//SIGNINOffsets signin_17511 = signin_17489;
//SIGNINOffsets signin_17526 = signin_17489;

// XShell offsets
XSHELLOffsets XShell_17489 = {
	0x9203EC14,
	0x9204A564,
	0x9204D734,
	0x92065454,
};
//XSHELLOffsets xshell_17502 = xshell_17489;
//XSHELLOffsets xshell_17511 = xshell_17489;
//XSHELLOffsets xshell_17526 = xshell_17489;

// HUD offsets
HUDOffsets HUD_17489 = {
	0x913F12D4, //FamilySettings_LaunchStr
	0x913E7498, //BootToDashHelper_Jump 
	0x14, //LaunchData_FAMILYSETTINGS
	0x913E72C0, //HUD_BootToDashHelper_Func
	0x119B8, //FamilySettings_Str1
	0x11F02, //FamilySettings_Str2
};
//HUDOffsets hud_17502 = hud_17489;
//HUDOffsets hud_17511 = hud_17489;
//HUDOffsets hud_17526 = hud_17489;

//const short kernels = 4;
//const short kernelversions[kernels] = {17489, 17502, 17511, 17526};
//XBDMOffsets* xbdmoffsets[kernels] = {&xbdm_17489, &xbdm_17502, &xbdm_17511, &xbdm_17526};
//XAMOffsets* xamoffsets[kernels] = {&xam_17489, &xam_17502, &xam_17511, &xam_17526};
//SIGNINOffsets* signinoffsets[kernels] = {&signin_17489, &signin_17502, &signin_17511, &signin_17526};
//XSHELLOffsets* xshelloffsets[kernels] = {&xshell_17489, &xshell_17502, &xshell_17511, &xshell_17526};
//HUDOffsets* hudoffsets[kernels] = {&hud_17489, &hud_17502, &hud_17511, &hud_17526};

OffsetManager::OffsetManager()
{
	_kernel = GetKernelVersion();
}

short OffsetManager::GetKernelVersion()
{
	__asm
	{
		li r0, 0
		sc
		srwi r3, r3, 16
	}
}

XBDMOffsets* OffsetManager::GetXBDMOffsets()
{
	/*
	for(int i = 0; i < kernels; i++)
	{
		if(kernelversions[i] == _kernel)
		{
			return xbdmoffsets[i];
		}
	}
	*/
	if (_kernel >= 17489)
		return &XBDM_17489;
	return NULL;
}

XAMOffsets* OffsetManager::GetXAMOffsets()
{
	/*
	for(int i = 0; i < kernels; i++)
	{
		if(kernelversions[i] == _kernel)
		{
			return xamoffsets[i];
		}
	}
	*/
	if (_kernel >= 17489)
		return &XAM_17489;
	return NULL;
}

SIGNINOffsets* OffsetManager::GetSigninOffsets()
{
	/*
	for(int i = 0; i < kernels; i++)
	{
		if(kernelversions[i] == _kernel)
		{
			return signinoffsets[i];
		}
	}
	*/
	if (_kernel >= 17489)
		return &Signin_17489;
	return NULL;
}

XSHELLOffsets* OffsetManager::GetXShellOffsets()
{
	/*
	for(int i = 0; i < kernels; i++)
	{
		if(kernelversions[i] == _kernel)
		{
			return xshelloffsets[i];
		}
	}
	*/
	if (_kernel >= 17489)
		return &XShell_17489;
	return NULL;
}

HUDOffsets* OffsetManager::GetHUDOffsets()
{
	/*
	for(int i = 0; i < kernels; i++)
	{
		if(kernelversions[i] == _kernel)
		{
			return hudoffsets[i];
		}
	}
	*/
	if (_kernel >= 17489)
		return &HUD_17489;
	return NULL;
}
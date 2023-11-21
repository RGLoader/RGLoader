#pragma once

typedef struct _State {
	HANDLE Handle;
	BOOL ExpansionEnabled;
} SState, * PSState;

typedef struct _Config {
	bool Disable;
	bool NoRGLP;
	bool NoSignInNotice;
	bool RPC;
	string RedirectXShellButton;
	string DefaultDashboard;

	typedef struct _Expansion {
		bool MountAllDrives;
		bool PersistentPatches;
		bool BootAnimation;
		bool HudJumpToXShell;
		string ProfileEncryptionType;
	} SExpansion, * PSExpansion;

	typedef struct _Protections {
		bool BlockLiveDNS;
		bool DisableExpansionInstall;
		bool DisableShadowboot;
	} SProtections, * PSProtections;

	typedef struct _Plugins {
		string Plugin1;
		string Plugin2;
		string Plugin3;
		string Plugin4;
		string Plugin5;
	} SPlugins, * PSPlugins;

	typedef struct _Passport {
		string Email;
		string Password;
	} SPassport, * PSPassport;

	PSExpansion Expansion;
	PSProtections Protections;
	PSPlugins Plugins;
	PSPassport Passport;

	_Config() {
		Expansion = new SExpansion();
		Protections = new SProtections();
		Plugins = new SPlugins();
		Passport = new SPassport();
	}

	~_Config() {
		delete Expansion;
		delete Protections;
		delete Plugins;
		delete Passport;
	}
} SConfig, * PSConfig;

typedef struct _Callable {
	DWORD dwOrigAddress;
	DWORD dwHookAddress;

	/*_Callable() { }*/

	_Callable(DWORD dwAddress) {
		this->dwOrigAddress = dwAddress;
	}

	/// <summary>
	/// This uses "Resolve(PCHAR szModule, DWORD dwOrdinal)" to populate the struct fields
	/// </summary>
	/// <param name="szModule"></param>
	/// <param name="dwOrdinal"></param>
	_Callable(PCHAR szModule, DWORD dwOrdinal) {
		this->Resolve(szModule, dwOrdinal);
	}

	/// <summary>
	/// This uses FindInterpretBranchOrdinal to populate the struct fields
	/// </summary>
	/// <param name="szModule"></param>
	/// <param name="dwOrdinal"></param>
	/// <param name="dwMaxSearch"></param>
	_Callable(PCHAR szModule, DWORD dwOrdinal, DWORD dwMaxSearch) {
		this->FindInterpretBranchOrdinal(szModule, dwOrdinal, dwMaxSearch);
	}

	BOOL Resolve(PCHAR szModule, DWORD dwOrdinal) {
		DWORD ptr32 = 0, ret = 0, ptr2 = 0;
		ret = XexGetModuleHandle((char*)szModule, (PHANDLE)&ptr32);
		if (ret == 0) {
			ret = XexGetProcedureAddress((HANDLE)ptr32, dwOrdinal, &ptr2);
			if (ptr2 != 0) {
				this->dwOrigAddress = ptr2;
				return TRUE;
			}
		}
		return FALSE;
	}

	BOOL FindInterpretBranchOrdinal(PCHAR szModule, DWORD dwOrdinal, DWORD dwMaxSearch) {
		this->dwOrigAddress = ::FindInterpretBranchOrdinal(szModule, dwOrdinal, dwMaxSearch);
		return TRUE;
	}

	BOOL Hook(PVOID pvHookAddress) {
		this->dwHookAddress = (DWORD)pvHookAddress;
		this->dwOrigAddress = (DWORD)HookFunctionStub((PDWORD)this->dwOrigAddress, pvHookAddress);
		return TRUE;
	}

	BOOL HookImportStub(PCHAR szModule, PCHAR szImpModule, DWORD dwOrdinal, PVOID pvHookAddress) {
		return HookImpStubDebug(szModule, szImpModule, dwOrdinal, (DWORD)pvHookAddress);
	}

	// No C++11 :(
	template<typename T>
	T Call() { return ((T(*)())this->dwOrigAddress)(); }

	template<typename T, typename P1>
	T Call(P1 p1) { return ((T(*)(P1))this->dwOrigAddress)(p1); }

	template<typename T, typename P1, typename P2>
	T Call(P1 p1, P2 p2) { return ((T(*)(P1, P2))this->dwOrigAddress)(p1, p2); }

	template<typename T, typename P1, typename P2, typename P3>
	T Call(P1 p1, P2 p2, P3 p3) { return ((T(*)(P1, P2, P3))this->dwOrigAddress)(p1, p2, p3); }

	template<typename T, typename P1, typename P2, typename P3, typename P4>
	T Call(P1 p1, P2 p2, P3 p3, P4 p4) { return ((T(*)(P1, P2, P3, P4))this->dwOrigAddress)(p1, p2, p3, p4); }

	template<typename T, typename P1, typename P2, typename P3, typename P4, typename P5>
	T Call(P1 p1, P2 p2, P3 p3, P4 p4, P5 p5) { return ((T(*)(P1, P2, P3, P4, P5))this->dwOrigAddress)(p1, p2, p3, p4, p5); }

	template<typename T, typename P1, typename P2, typename P3, typename P4, typename P5, typename P6>
	T Call(P1 p1, P2 p2, P3 p3, P4 p4, P5 p5, P6 p6) { return ((T(*)(P1, P2, P3, P4, P5, P6))this->dwOrigAddress)(p1, p2, p3, p4, p5, p6); }

	template<typename T, typename P1, typename P2, typename P3, typename P4, typename P5, typename P6, typename P7>
	T Call(P1 p1, P2 p2, P3 p3, P4 p4, P5 p5, P6 p6, P7 p7) { return ((T(*)(P1, P2, P3, P4, P5, P6, P7))this->dwOrigAddress)(p1, p2, p3, p4, p5, p6, p7); }

	template<typename T, typename P1, typename P2, typename P3, typename P4, typename P5, typename P6, typename P7, typename P8>
	T Call(P1 p1, P2 p2, P3 p3, P4 p4, P5 p5, P6 p6, P7 p7, P8 p8) { return ((T(*)(P1, P2, P3, P4, P5, P6, P7, P8))this->dwOrigAddress)(p1, p2, p3, p4, p5, p6, p7, p8); }

	template<typename T, typename P1, typename P2, typename P3, typename P4, typename P5, typename P6, typename P7, typename P8, typename P9>
	T Call(P1 p1, P2 p2, P3 p3, P4 p4, P5 p5, P6 p6, P7 p7, P8 p8, P9 p9) { return ((T(*)(P1, P2, P3, P4, P5, P6, P7, P8, P9))this->dwOrigAddress)(p1, p2, p3, p4, p5, p6, p7, p8.p9); }

	template<typename T, typename P1, typename P2, typename P3, typename P4, typename P5, typename P6, typename P7, typename P8, typename P9, typename P10>
	T Call(P1 p1, P2 p2, P3 p3, P4 p4, P5 p5, P6 p6, P7 p7, P8 p8, P9 p9, P10 p10) { return ((T(*)(P1, P2, P3, P4, P5, P6, P7, P8, P9, P10))this->dwOrigAddress)(p1, p2, p3, p4, p5, p6, p7, p8, p9, p10); }
} SCallable, *PSCallable;

typedef struct _Offsets {
	typedef struct _KernelOffsets {
		PSCallable KiShadowBoot;
		PSCallable XexpLoadImage;
		PSCallable XexStartExecutable;
		PSCallable XeKeysObfuscate;
		PSCallable XeKeysUnObfuscate;
	} SKernelOffsets, *PSKernelOffsets;

	typedef struct _XAMOffsets {
		DWORD live_siflc;
		DWORD live_piflc;
		DWORD live_notice;
		DWORD live_xexds;
		DWORD live_xetgs;
		DWORD live_xeas;
		DWORD live_xemacs;
		PSCallable XampXAuthStartup;
		PSCallable XamFindOrCreateInternalPassportAccount;
	} SXAMOffsets, * PSXAMOffsets;

	typedef struct _SIGNINOffsets {
		DWORD NoSignInNotice;
	} SSIGNINOffsets, * PSSIGNINOffsets;

	typedef struct _XSHELLOffsets {
		DWORD loc1;
		DWORD loc2;
		DWORD loc3;
		DWORD loc4;
	} SXSHELLOffsets, * PSXSHELLOffsets;

	typedef struct _HUDOffsets {
		DWORD FamilySettings_LaunchStr;
		DWORD BootToDashHelper_Jump;
		DWORD LaunchData_FamilySettings;
		PSCallable BootToDashHelper;
		DWORD FamilySettings_Str1;
		DWORD FamilySettings_Str2;
	} SHUDOffsets, * PSHUDOffsets;

	typedef struct _XBDMOffsets {
		PSCallable MapDebugDrive;
		PSCallable MapInternalDrives;
		PSCallable GetParam;
		PSCallable PchGetParam;
		PSCallable FGetSzParam;
		PSCallable FGetDwParam;
		PSCallable FGetNamedDwParam;
		PSCallable FGetQwordParam;
	} SXBDMOffsets, *PSXBDMOffsets;

	PSKernelOffsets KERNEL;
	PSXAMOffsets XAM;
	PSSIGNINOffsets SIGNIN;
	PSXSHELLOffsets XSHELL;
	PSHUDOffsets HUD;
	PSXBDMOffsets XBDM;

	_Offsets() {
		KERNEL = new SKernelOffsets();
		XAM = new SXAMOffsets();
		SIGNIN = new SSIGNINOffsets();
		XSHELL = new SXSHELLOffsets();
		HUD = new SHUDOffsets();
		XBDM = new SXBDMOffsets();
	}

	~_Offsets() {
		delete KERNEL;
		delete XAM;
		delete SIGNIN;
		delete XSHELL;
		delete HUD;
		delete XBDM;
	}
} SOffsets, *PSOffsets;

typedef struct _ExpHdr {
	DWORD dwMagic;
	DWORD dwFlags;
	QWORD qwAddr;
} ExpHdr, * PExpHdr;

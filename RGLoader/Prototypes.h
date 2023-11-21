#pragma once

#pragma region Kernel
typedef NTSTATUS(*XEXPLOADIMAGE)(LPCSTR xexName, DWORD typeInfo, DWORD ver, PHANDLE modHandle); // XexpLoadImage
typedef HRESULT(*XEXSTARTEXECUTABLE)(FARPROC TitleProcessInitThreadProc); // XexStartExecutable
typedef void(*KISHADOWBOOT)(PVOID pvData, DWORD dwSize, DWORD dwUnk0);  // KiShadowBoot
#pragma endregion Kernel

#pragma region XAM
typedef HRESULT(*XAMPXAUTHSTARTUP)(const XAUTH_SETTINGS* Settings);
typedef DWORD(*XAMFINDORCREATEINTERNALPASSPORTACCOUNT)(PBYTE bCountryId, FILETIME fileTime, PWCHAR pwchGamertag, PVOID PassportSessionToken);
#pragma endregion XAM

#pragma region XBDM
typedef VOID(*MAPDEBUGDRIVE)(const PCHAR pchMntName, const PCHAR pchMntPath, BOOL bEnable);
typedef VOID(*MAPINTERNALDRIVES)(VOID);

typedef BOOL(*GETPARAM)(LPCSTR szCommand, LPCSTR szName, DWORD dwSize);
typedef BOOL(*PCHGETPARAM)(LPCSTR szCommand, LPCSTR szName, BOOL bRequired);
typedef BOOL(*FGETSZPARAM)(LPCSTR szCommand, LPCSTR szName, LPCSTR szOut, DWORD dwMaxSize);
typedef BOOL(*FGETDWPARAM)(LPCSTR szCommand, LPCSTR szName, PDWORD pdwOut);
typedef BOOL(*FGETNAMEDDWPARAM)(LPCSTR szCommand, LPCSTR szName, PDWORD pdwOut);
typedef BOOL(*FGETQWORDPARAM)(LPCSTR szCommand, LPCSTR szName, PQWORD pqwOut);
#pragma endregion XBDM

#pragma region HUD
typedef DWORD(*HUD_FILLLAUNCHDATA)(DWORD* XDashLaunchData, DWORD r4, DWORD selection);
typedef DWORD(*HUD_BOOTTODASHHELPER)(DWORD* _XUIOBJ, _XDASHLAUNCHDATA* LaunchData, DWORD* cstr, DWORD* r6, DWORD* r7);
#pragma endregion HUD
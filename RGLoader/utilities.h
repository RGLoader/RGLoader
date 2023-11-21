#pragma once

#include "stdafx.h"

#ifdef __cplusplus
extern "C" {
#endif
     //   UINT32 __stdcall XexGetModuleHandle(char* module, PVOID hand);
     //   UINT32 __stdcall XexGetProcedureAddress(UINT32 hand ,UINT32, PVOID);
#ifdef __cplusplus
}
#endif

#define setmemdm(addr, data) { DWORD d = data; memcpy((LPVOID)addr, &d, 4); }

UINT32 __declspec() HvxSetState(UINT32 mode);
#define PROTECT_OFF		0
#define PROTECT_ON		1
#define SET_PROT_OFF	2
#define SET_PROT_ON		3

#define __isync() __emit(0x4C00012C)

#define doSync(addr) \
	do { \
	__dcbst(0, addr); \
	__sync(); \
	__isync(); \
	} while (0)

#define doLightSync(addr) \
	do { \
	__dcbst(0, addr); \
	__sync(); \
	} while (0)

// hooking
DWORD ResolveFunction(char* modname, DWORD ord);
DWORD InterpretBranchDestination(DWORD currAddr, DWORD brInst);
VOID HookFunctionStart(PDWORD addr, PDWORD saveStub, DWORD dest);
VOID UnhookFunctionStart(PDWORD addr, PDWORD oldData);
DWORD HookFunctionStub(PDWORD _Address, void* Function);
DWORD RelinkGPLR(int offset, PDWORD saveStubAddr, PDWORD orgAddr);
DWORD FindInterpretBranch(PDWORD startAddr, DWORD maxSearch);
DWORD FindInterpretBranchOrdinal(PCHAR modname, DWORD ord, DWORD maxSearch);
VOID PatchInJump(DWORD* addr, DWORD dest, BOOL linked);
BOOL HookImpStubDebug(char* modname, char* impmodname, DWORD ord, DWORD patchAddr);
DWORD MakeBranch(DWORD branchAddr, DWORD destination, BOOL linked=false);

// mounting
void Mount(char* dev, char* mnt);
HRESULT DoDeleteLink(const char* szDrive, const char* sysStr);
HRESULT DeleteLink(const char* szDrive, BOOL both);
HRESULT MountPath(const char* szDrive, const char* szDevice, BOOL both);

// printing
void RGLPrint(const PCHAR cat, const PCHAR fmt, ...);
void RGLNewLine();
void HexPrint(PBYTE pbData, DWORD dwLen);
void RGLHexPrint(const PCHAR cat, PBYTE pbData, DWORD dwLen);

// I/O
string PathJoin(const string& szPath0, const string& szPath1);
vector<string> ListFiles(const string& szPathWithPattern);
LONGLONG FileSize(LPCSTR path);
BOOL ReadFile(LPCSTR path, PVOID buffer, DWORD size);
BOOL WriteFile(LPCSTR path, PVOID buffer, DWORD size);
BOOL FileExists(LPCSTR szPath);
BOOL DirectoryExists(LPCSTR szPath);
int DeleteDirectory(const string& refcstrRootDirectory, bool bDeleteSubdirectories = true);
int CopyDirectory(const string& refcstrSourceDirectory, const string& refcstrDestinationDirectory);

// misc.
SMC_PWR_REAS GetSmcPowerOnReason();
SMC_TRAY_STATE GetSmcTrayState();
void SwapEndian(BYTE* src, DWORD size);
void LaunchXShell(void);

// strings
PWCHAR CharToWChar(const PCHAR text, PWCHAR stackPtr);
PCHAR WCharToChar(const PWCHAR text, PCHAR stackPtr);
string StrToLower(const string& str);
vector<string> StrSplit(string s, string delimiter);
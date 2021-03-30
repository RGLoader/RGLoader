#pragma once

#ifndef UTIL_H
#define UTIL_H

#include "stdafx.h"
#include <string>
//#include "XexLoadImage.h"
//#include "KernelExports.h"


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

#define __isync()		__emit(0x4C00012C)

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

void Mount(char* dev, char* mnt);
DWORD ResolveFunction(char* modname, DWORD ord);
DWORD InterpretBranchDestination(DWORD currAddr, DWORD brInst);
VOID HookFunctionStart(PDWORD addr, PDWORD saveStub, PDWORD oldData, DWORD dest);
VOID UnhookFunctionStart(PDWORD addr, PDWORD oldData);
DWORD RelinkGPLR(int offset, PDWORD saveStubAddr, PDWORD orgAddr);
DWORD FindInterpretBranch(PDWORD startAddr, DWORD maxSearch);
DWORD FindInterpretBranchOrdinal(PCHAR modname, DWORD ord, DWORD maxSearch);
VOID PatchInJump(DWORD* addr, DWORD dest, BOOL linked);
BOOL HookImpStubDebug(char* modname, char* impmodname, DWORD ord, DWORD patchAddr);
DWORD MakeBranch(DWORD branchAddr, DWORD destination, BOOL linked=false);
BOOL FileExists(LPCSTR lpFileName);
void dprintf(const char* s, ...);
void SwapEndian(BYTE* src, DWORD size);
void LaunchXShell(void);
HRESULT DoDeleteLink(const char* szDrive, const char* sysStr);
HRESULT DeleteLink(const char* szDrive, BOOL both);
HRESULT MountPath(const char* szDrive, const char* szDevice, BOOL both);
int DeleteDirectory(const std::string &refcstrRootDirectory, bool bDeleteSubdirectories = true);
BOOL FileExists(const char* path);
BOOL WriteBufToFile(const char* szPath, PBYTE pbData, DWORD dwLen, BOOL wRemoveExisting);
PBYTE ReadFileToBuf(const char* szPath, PDWORD size);
int CopyDirectory(const std::string &refcstrSourceDirectory, const std::string &refcstrDestinationDirectory);

void RGLPrint(const char* category, const char* data, ...);
void HexPrint(BYTE* data, size_t len);
QWORD FileSize(LPCSTR filename);
bool ReadFile(LPCSTR filename, PVOID buffer, DWORD size);
bool WriteFile(LPCSTR filename, PVOID buffer, DWORD size);

// HANDLE RGLCreateThread(LPVOID startAddr, LPVOID parameters);

#endif
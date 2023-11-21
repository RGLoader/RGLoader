#include "stdafx.h"

HANDLE SearchForHandle(const char* mName) {

	PLDR_DATA_TABLE_ENTRY curTab = (PLDR_DATA_TABLE_ENTRY)GetModuleHandle("xboxkrnl.exe");
	PXEX_HEADER_STRING peName;

	curTab = (PLDR_DATA_TABLE_ENTRY)curTab->InLoadOrderLinks.Flink;

	while(curTab != NULL)
	{
		//printf("Current handle: %08X\n", curTab);
		peName = (PXEX_HEADER_STRING)RtlImageXexHeaderField(curTab->XexHeaderBase, 0x000183FF);

		//if((curTab->BaseDllName.Buffer != NULL) && (curTab->BaseDllName.Buffer[0] != 0))
			//printf("\tBaseName       : %S\r\n", curTab->BaseDllName.Buffer);

		if((peName != NULL) && (peName->Data[0] != 0)){
			if(stricmp((char*)peName->Data, mName) == 0){
				HANDLE ret = (HANDLE)curTab;
				//printf("Found module %s:  %08X\n", mName, ret);
				return ret;
			}
		}
		curTab = (PLDR_DATA_TABLE_ENTRY)curTab->InLoadOrderLinks.Flink;
	}
	return INVALID_HANDLE_VALUE;
}


void ReplaceHudString( const char* newtext, DWORD addr, int length){
	char* temp = new char[length+1];
	for(int i=0; i<length; i++) temp[i]=' ';
	temp[length]='\0';

	int nLen=strlen(newtext);
	for(int i=0; i<nLen; i++)temp[i]=newtext[i];

	memcpy((LPVOID)addr, temp, length+1);
}

void PatchHudStrings(void){

	HANDLE hModule = SearchForHandle( "hud.dll" );
	if(hModule == INVALID_HANDLE_VALUE){
		RGLPrint("HUD", "ERROR: Unable to get handle to hud.dll\n");
	}

	VOID* pSectionData;
	DWORD dwSectionSize;
	if( !XGetModuleSection(hModule ,"hud", &pSectionData, &dwSectionSize ) ){
		RGLPrint("HUD", "ERROR: Unable to get module section data from hud.dll\n");
	}

	// HUDOffsets* offsets = offsetmanager.GetHUDOffsets();

	if(!RGLoader->Offsets->HUD)
		return;

	ReplaceHudString(HUD_FamilySettings_String, (DWORD)pSectionData + RGLoader->Offsets->HUD->FamilySettings_Str1, HUD_FamilySettings_Len);
	ReplaceHudString(HUD_FamilySettings_String, (DWORD)pSectionData + RGLoader->Offsets->HUD->FamilySettings_Str2, HUD_FamilySettings_Len);
}

BOOL HudPatchInJump(DWORD destination, BOOL linked=false){

	if(!RGLoader->Offsets->HUD)
		return -1;

	setmemdm(RGLoader->Offsets->HUD->BootToDashHelper_Jump, MakeBranch(RGLoader->Offsets->HUD->BootToDashHelper_Jump, (RGLoader->Offsets->HUD->FamilySettings_LaunchStr)+0x4, true));
	//setmem( HUD_BootToDashHelper_Jump, 0x60000000);

	//setmem(HUD_FamilySettings_LaunchStr, 0x4800001C);
	setmemdm(RGLoader->Offsets->HUD->FamilySettings_LaunchStr, 0x4E800020); //blr
	BYTE data[0x10];
	PatchInJump((PDWORD)data, (DWORD)destination, linked);
	HRESULT hr;
	hr = (HRESULT)memcpy((PDWORD)((RGLoader->Offsets->HUD->FamilySettings_LaunchStr)+4), (LPCVOID)data, 0x10);
	//return hr;
	return 1;
}


int PatchHudReturnToXShell(){
	char* newLabel = "RGLoader\0\0";
	HudPatchInJump((DWORD)HudBootToDashHelperHook);
	PatchHudStrings();
	
	return 1;
}
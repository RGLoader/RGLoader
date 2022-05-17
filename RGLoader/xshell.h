#pragma once

#include "stdafx.h"
#include <xbdm.h>
#include <stdio.h>
//#include "xecrypt.h"
#include "utilities.h"
#include "OffsetManager.h"
#include <string>

static char* startXex;
static char* startPath;

//#define XSHELL_SETUP_DRIVE_LETTER_FUNC_ADDR 0x921295E0

//typedef DWORD (*XSHELL_SETUP_DRIVE_LETTER)(DWORD* r3, char* driveletter, DWORD r5);

//static XSHELL_SETUP_DRIVE_LETTER Xshell_Setup_Drive_Letter = (XSHELL_SETUP_DRIVE_LETTER)XSHELL_SETUP_DRIVE_LETTER_FUNC_ADDR;

int PatchXShellStartPath(std::string newpath);
#pragma once

static bool fKeepMemory = true;

#define setmem(addr, data) { DWORD d = data; memcpy((LPVOID)addr, &d, 4);}

#define XexLoadExecutableOrd 408
#define XexLoadImageOrd 409
#define XEXLOADIMAGE_MAX_SEARCH 9

#define XEXLOAD_DASH    "\\Device\\Flash\\dash.xex"
#define XEXLOAD_DASH2   "\\SystemRoot\\dash.xex"
#define XEXLOAD_SIGNIN  "signin.xex"
#define XEXLOAD_CREATE  "createprofile.xex"
#define XEXLOAD_HUD	    "hud.xex"
#define XEXLOAD_XSHELL  "xshell.xex"
#define XEXLOAD_DEFAULT "default.xex"

#define MODULE_SECTION_GENERIC_HVPP  "52474C00"
#define MODULE_SECTION_XBONLINE_HVPP "52474C01"
#define MODULE_SECTION_SC0           "52474C02"
#define MODULE_SECTION_DEFAULT_INI   "52474C03"

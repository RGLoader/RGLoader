// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#pragma warning(disable : 4244)
#pragma warning(disable : 4172)
#pragma warning(disable : 4800)
#pragma warning(disable : 4018)
#pragma warning(disable : 4554)
#pragma warning(disable : 4826)
#pragma warning(disable : 4200)
#pragma warning(disable : 4293)
#pragma warning(disable : 4307)
#pragma warning(disable : 4804)

#include <xtl.h>
#include <xboxmath.h>
#include <stddef.h>
#include <xbdm.h>
#pragma comment(lib, "xbdm")
//#include <xstring>
//#include <iostream>
//#include <fstream>
//#include <sstream>
//#include <string>
#include <vector>
#include <stdio.h>
#include <ppcintrinsics.h>
#include <xauth.h>

using namespace std;

// TODO: reference additional headers your program requires here
#include "xkelib.h"
#include "types.h"
#include "Prototypes.h"
#include "INIReader.h"
#include "Utilities.h"
#include "Structs.h"
#include "Config.h"
#include "Offsets.h"
#include "Globals.h"
#include "RGLoader.h"
#include "Hooks.h"

#include "HV.h"
#include "HUD.h"
#include "xshell.h"
#include "Flash.h"
#include "XBDM.h"
#include "KeyVault.h"

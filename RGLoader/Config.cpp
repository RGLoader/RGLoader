#include "stdafx.h"

PSConfig PopulateConfig() {
	// create default config if necessary
	CreateDefaultConfigIfNeeded();

	INIReader* ini = new INIReader("Mass0:\\rgloader.ini");
	if(ini->ParseError() < 0)
		ini = new INIReader("Hdd:\\rgloader.ini");
	if(ini->ParseError() < 0) {
		RGLPrint("ERROR", "Unable to open ini file!\n");
		return NULL;
	}

	PSConfig cfg = new SConfig();

	// booleans - config
	cfg->Disable = ini->GetBoolean("Config", "Disable", false);
	cfg->NoRGLP = ini->GetBoolean("Config", "NoRGLP", false);
	cfg->NoSignInNotice = ini->GetBoolean("Config", "NoSignInNotice", false);
	cfg->RPC = ini->GetBoolean("Config", "RPC", false);
	// booleans - expansion
	cfg->Expansion->MountAllDrives = ini->GetBoolean("Expansion", "MountAllDrives", false);
	cfg->Expansion->PersistentPatches = ini->GetBoolean("Expansion", "PersistentPatches", false);
	cfg->Expansion->BootAnimation = ini->GetBoolean("Expansion", "BootAnimation", false);
	cfg->Expansion->HudJumpToXShell = ini->GetBoolean("Expansion", "HudJumpToXShell", true);
	// booleans - protections
	cfg->Protections->BlockLiveDNS = ini->GetBoolean("Protections", "BlockLiveDNS", false);
	cfg->Protections->DisableExpansionInstall = ini->GetBoolean("Protections", "DisableExpansionInstall", true);
	cfg->Protections->DisableShadowboot = ini->GetBoolean("Protections", "DisableShadowboot", true);
	// strings - config
	cfg->DefaultDashboard = ini->GetString("Config", "DefaultDashboard", "none");
	cfg->RedirectXShellButton = ini->GetString("Config", "RedirectXShellButton", "none");
	// strings - expansion
	cfg->Expansion->ProfileEncryptionType = ini->GetString("Expansion", "ProfileEncryptionType", "none");
	cfg->Expansion->ProfileEncryptionType = StrToLower(cfg->Expansion->ProfileEncryptionType);  // needs to be lowercase!
	// strings - plugins
	cfg->Plugins->Plugin1 = ini->GetString("Plugins", "Plugin1", "none");
	cfg->Plugins->Plugin2 = ini->GetString("Plugins", "Plugin2", "none");
	cfg->Plugins->Plugin3 = ini->GetString("Plugins", "Plugin3", "none");
	cfg->Plugins->Plugin4 = ini->GetString("Plugins", "Plugin4", "none");
	cfg->Plugins->Plugin5 = ini->GetString("Plugins", "Plugin5", "none");
	// strings - passport
	cfg->Passport->Email = ini->GetString("Passport", "Email", "none");
	cfg->Passport->Password = ini->GetString("Passport", "Password", "none");

	return cfg;
}

void CreateDefaultConfigIfNeeded() {
	if (FileExists("Hdd:\\rgloader.ini") || FileExists("Mass0:\\rgloader.ini"))
		return;

	RGLPrint("CONFIG", "Creating default config \"Hdd:\\rgloader.ini\"...");

	PVOID pvSectionData;
	ULONG ulSectionSize;
	if (XGetModuleSection(RGLoader->State->Handle, MODULE_SECTION_DEFAULT_INI, &pvSectionData, &ulSectionSize) == FALSE) {
		return;
	}

	WriteFile("Hdd:\\rgloader.ini", pvSectionData, ulSectionSize);
}
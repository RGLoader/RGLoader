#include "stdafx.h"

Globals* RGLoader;

Globals::Globals(HANDLE hModule) {
	this->State = new SState();
	this->State->Handle = hModule;
	this->Config = PopulateConfig();
	this->Offsets = PopulateOffsets();
}

Globals::~Globals() {
	delete this->State;
	delete this->Config;
	delete this->Offsets;
}
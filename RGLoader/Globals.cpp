#include "stdafx.h"

Globals* RGLoader;

Globals::Globals() {
	this->State = new SState();
	this->Config = PopulateConfig();
	this->Offsets = PopulateOffsets();
}

Globals::~Globals() {
	delete this->State;
	delete this->Config;
	delete this->Offsets;
}
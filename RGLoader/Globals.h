#pragma once

class Globals {
public:
	Globals(HANDLE hModule);
	~Globals();

	PSState State;
	PSConfig Config;
	PSOffsets Offsets;
private:
	// hi
};

extern Globals* RGLoader;
#pragma once

class Globals {
public:
	Globals();
	~Globals();

	PSState State;
	PSConfig Config;
	PSOffsets Offsets;
private:
	// hi
};

extern Globals* RGLoader;
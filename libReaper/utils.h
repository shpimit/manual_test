#pragma once
#include <Windows.h>
#include <string>

class utils
{
public:
	utils();
	~utils();

	std::string getTempPathA();
	std::wstring getTempPathW();
};
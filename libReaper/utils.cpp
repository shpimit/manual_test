#include "utils.h"

utils::utils()
{

}

utils::~utils()
{

}

std::string utils::getTempPathA()
{
	std::string retPath;
	CHAR chPath[256] = { 0, };

	GetTempPathA(256, chPath);
	retPath = chPath;

	return retPath;
}

std::wstring utils::getTempPathW()
{
	std::wstring retPath;
	WCHAR chPath[256] = { 0, };

	GetTempPathW(256, chPath);
	retPath = chPath;

	return retPath;
}
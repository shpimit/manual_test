#pragma once
#include <windows.h>
#include <string>
#include <vector>

class info
{
public:
	info();
	~info();

	std::string pcname();
	std::string os();
	std::string user();
	std::string language();
	std::string time();

private:
	bool isOpen();
	bool open();
	void close();

private:
	HKEY m_hKey;
};
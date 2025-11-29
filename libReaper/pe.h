#pragma once
#include <Windows.h>

class pe
{
public:
	pe(PBYTE peBuffer, SIZE_T peSize);

	~pe();

	bool isParse();

	ULONG imageSize();
	ULONG addressOfEntryPoint();
	USHORT numberOfSection();
	ULONG_PTR getFirstSection();
	ULONG_PTR getNextSection(ULONG_PTR currentSection);
	LONG_PTR getRelativeOffset(ULONG_PTR imagebase);
	void setImagebase(LONG_PTR imagebase);

	ULONG_PTR memAlloc(SIZE_T size);
	PVOID getAddress(HMODULE Module, char* FunctionName);
	bool resolveIAT(ULONG_PTR imageBase);
	void relocate(ULONG_PTR buildAddr, ULONG_PTR imageBase);
	void memFree(ULONG_PTR buildAddr);

	PBYTE peHeader();
	ULONG peHeaderSize();

private:
	PBYTE m_peBuffer;
	PIMAGE_DOS_HEADER m_pDosHeader;
	PIMAGE_NT_HEADERS m_pNTHeader;
};
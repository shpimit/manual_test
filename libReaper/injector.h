#pragma once
#include <Windows.h>

class injector
{
public:
	injector(HANDLE processHandle = NULL);
	~injector();

	ULONG_PTR alloc(SIZE_T size, ULONG_PTR baseAddress = 0, bool directSyscall = false);
	bool write(ULONG_PTR dstAddress, ULONG_PTR srcAddress, SIZE_T size, bool directSyscall = false);

	void writeHeader(ULONG_PTR dstAddress, ULONG_PTR srcAddress, ULONG srcSize);
	void writeSection(ULONG_PTR dstAddress, ULONG_PTR srcAddress, ULONG_PTR sectionAddress);

	ULONG callEntryPoint(ULONG_PTR baseAddress, ULONG addressOfEntryPoint);
	bool execute(ULONG_PTR dstAddress, bool directSyscall = false);
	void free();

private:
	ULONG callEntryPoint_(ULONG_PTR baseAddress, ULONG addressOfEntryPoint, ULONG reason);

private:
	bool m_remote;
	HANDLE m_process;
	ULONG_PTR m_allocAddress;
	ULONG m_entrypointOffset;
};
#include "injector.h"

#include "pe.h"
#include "directsyscall.h"

injector::injector(HANDLE processHandle)
{
	if (processHandle)
	{
		m_process = processHandle;
		m_remote = true;
	}
	else
	{
		m_remote = false;
	}
	m_allocAddress = 0;
	m_entrypointOffset = 0;
}

injector::~injector()
{
	free();
}

ULONG_PTR injector::alloc(SIZE_T size, ULONG_PTR baseAddress, bool directSyscall)
{
	ULONG_PTR retAddress = 0;
	NTSTATUS status = 0;
	PVOID dsBaseAddress = (PVOID)baseAddress;
	SIZE_T dsSize = size;

	if (!m_remote)
	{
		m_process = m_process = GetCurrentProcess();
	}	

	if (directSyscall)
	{
		status = (ULONG_PTR)DirectNtAllocateVirtualMemory(m_process, &dsBaseAddress, 0, &dsSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (status == 0)
			retAddress = (ULONG_PTR)dsBaseAddress;
	}
	else
	{
		retAddress = (ULONG_PTR)VirtualAllocEx(m_process, (LPVOID)baseAddress, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}

	if (!m_remote)
	{
		if (retAddress != NULL)
			ZeroMemory((PVOID)retAddress, size);
	}

	m_allocAddress = retAddress;

	return retAddress;
}

bool injector::write(ULONG_PTR dstAddress, ULONG_PTR srcAddress, SIZE_T size, bool directSyscall)
{
	SIZE_T writtenSize = 0;

	if (directSyscall)
	{
		if (!DirectNtWriteVirtualMemory(m_process, (PVOID)dstAddress, (PBYTE)srcAddress, (ULONG)size, (PULONG)&writtenSize))
			return false;
	}
	else
	{
		if (!WriteProcessMemory(m_process, (PVOID)dstAddress, (PBYTE)srcAddress, size, &writtenSize))
			return false;
	}

	return true;
}

void injector::writeHeader(ULONG_PTR dstAddress, ULONG_PTR srcAddress, ULONG srcSize)
{
	RtlCopyMemory((PVOID)dstAddress, (PVOID)srcAddress, srcSize);
}

void injector::writeSection(ULONG_PTR dstAddress, ULONG_PTR srcAddress, ULONG_PTR sectionAddress)
{
	PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)sectionAddress;

	RtlCopyMemory(
		((PBYTE)dstAddress + pSection->VirtualAddress),
		((PBYTE)srcAddress + pSection->PointerToRawData),
		pSection->SizeOfRawData
	);
}

ULONG injector::callEntryPoint(ULONG_PTR baseAddress, ULONG addressOfEntryPoint)
{
	m_entrypointOffset = addressOfEntryPoint;
	return callEntryPoint_(baseAddress, addressOfEntryPoint, DLL_PROCESS_ATTACH);
}

ULONG injector::callEntryPoint_(ULONG_PTR baseAddress, ULONG addressOfEntryPoint, ULONG reason)
{
	typedef ULONG(APIENTRY* PFN_DLL_MAIN)(HMODULE DllHandle, ULONG Reason, LPVOID Reserved);

	ULONG Result = ((PFN_DLL_MAIN)((char*)baseAddress + addressOfEntryPoint)) (
		(HMODULE)baseAddress,
		reason,
		NULL
		);

	return 0;
}

bool injector::execute(ULONG_PTR dstAddress, bool directSyscall)
{
	HANDLE hThread = NULL;

	if (!m_remote)
	{
		hThread = CreateRemoteThread(m_process, NULL, 0, (LPTHREAD_START_ROUTINE)dstAddress, NULL, 0, NULL);
	}
	else
	{
		hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)dstAddress, NULL, 0, NULL);
	}

	if (hThread != NULL)
	{
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
		return true;
	}

	return false;
}

void injector::free()
{
	if (m_allocAddress)
	{
		callEntryPoint_(m_allocAddress, m_entrypointOffset, DLL_PROCESS_DETACH);

		if (VirtualFreeEx(m_process, (PVOID)m_allocAddress, 0, MEM_RELEASE))
		{
			if (m_remote)
			{
				CloseHandle(m_process);
				m_process = NULL;
				m_remote = false;
			}
			m_allocAddress = 0;
			m_entrypointOffset = 0;
		}
	}
}
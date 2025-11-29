#include "process_.h"
#include "nt.h"
#include "directsyscall.h"

#pragma comment(lib, "ntdll.lib")

process::process() : 
	m_activate(false),
	m_thread(NULL),
	m_process(NULL),
	m_pthreadContext(NULL),
	m_processImageBase(0)
{
}

process::~process()
{
	close();
}

bool process::isActivate()
{
	if (m_activate)
		return true;

	return false;
}

HANDLE process::handle()
{
	if (!isActivate())
		return NULL;

	return m_process;
}

bool process::create(PWCHAR pwszProcessPath, bool bSuspended, bool bDirectSyscall)
{
	STARTUPINFO si = { 0, };
	PROCESS_INFORMATION pi = { 0, };
	ULONG CreateFlag = bSuspended == true ? CREATE_SUSPENDED : 0;
	NTSTATUS status = STATUS_SUCCESS;
	PROCESS_BASIC_INFORMATION ProcessBasicInfo = { 0, };
	PEB ProcessPeb = { 0, };
	ULONG ulProcessInfoLength = 0;
	SIZE_T ulPebLength = 0;

	si.cb = sizeof(STARTUPINFO);

	if (!CreateProcess(NULL, pwszProcessPath, NULL, NULL, FALSE, CreateFlag, NULL, NULL, &si, &pi))
	{
		return false;
	}

	m_thread = pi.hThread;
	m_process = pi.hProcess;

	if (bSuspended)
		getThreadContext();

	if (bDirectSyscall)
	{
		status = DirectNtQueryInformationProcess(
			m_process,
			ProcessBasicInformation,
			&ProcessBasicInfo,
			sizeof(PROCESS_BASIC_INFORMATION),
			&ulProcessInfoLength
		);
	}
	else
	{
		status = NtQueryInformationProcess(
			m_process,
			ProcessBasicInformation,
			&ProcessBasicInfo,
			sizeof(PROCESS_BASIC_INFORMATION),
			&ulProcessInfoLength
		);
	}


	if (status != STATUS_SUCCESS)
	{
		return false;
	}

	if (bDirectSyscall)
	{
		status = DirectNtReadVirtualMemory(
			m_process,
			(PVOID)ProcessBasicInfo.PebBaseAddress,
			&ProcessPeb,
			sizeof(ProcessPeb),
			(PULONG)&ulPebLength
		);
	}
	else
	{
		status = NtReadVirtualMemory(
			m_process,
			(PVOID)ProcessBasicInfo.PebBaseAddress,
			&ProcessPeb,
			sizeof(ProcessPeb),
			(PULONG)&ulPebLength
		);
	}

	if (status != STATUS_SUCCESS)
	{
		return false;
	}

	m_processImageBase = (ULONG_PTR)ProcessPeb.ImageBaseAddress;

	m_activate = true;

    return true;
}

ULONG_PTR process::imagebase()
{
	if (!isActivate())
		return 0;

	return m_processImageBase;
}

bool process::unmap(ULONG_PTR imagebase, bool bDirectSyscall)
{
	NTSTATUS status = STATUS_SUCCESS;

	if (bDirectSyscall)
	{
		status = DirectNtUnmapViewOfSection(m_process, (PVOID)imagebase);
	}
	else
	{
		status = NtUnmapViewOfSection(m_process, (PVOID)imagebase);
	}
	

	if (status != STATUS_SUCCESS)
	{
		return false;
	}

	return true;
}

bool process::patchEntryPoint(ULONG_PTR baseAddress, ULONG_PTR addressOfEntryPoint)
{
#ifdef _M_IX86
	m_pthreadContext->Eax = baseAddress + addressOfEntryPoint;
#else
	m_pthreadContext->Rcx = baseAddress + addressOfEntryPoint;
#endif

	if (SetThreadContext(m_thread, m_pthreadContext))
		return true;

	return false;
}

void process::resume()
{
	ResumeThread(m_thread);
	WaitForSingleObject(m_thread, INFINITE);
}

void process::close()
{
	if (isActivate())
	{
		if (m_thread != NULL)
		{
			CloseHandle(m_thread);
			m_thread = NULL;
		}			

		if (m_process != NULL)
		{
			CloseHandle(m_process);
			m_process = NULL;
		}				

		if (m_pthreadContext != NULL)
		{
			HeapFree(GetProcessHeap(), 0, m_pthreadContext);
			m_pthreadContext = NULL;
		}			
	}
}

bool process::getThreadContext()
{
	m_pthreadContext = (LPCONTEXT)HeapAlloc(GetProcessHeap(), 0, sizeof(CONTEXT));

	if (m_pthreadContext == NULL)
		return false;

	memset(m_pthreadContext, 0, sizeof(CONTEXT));

	m_pthreadContext->ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(m_thread, m_pthreadContext))
	{
		return false;
	}	

	return true;
}
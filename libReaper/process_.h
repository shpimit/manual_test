#pragma once
#include <Windows.h>

class process
{
public:
	process();
	~process();

	bool isActivate();

	HANDLE handle();

	bool create(PWCHAR pwszProcessPath, bool bSuspended = false, bool bDirectSyscall = false);
	ULONG_PTR imagebase();
	bool unmap(ULONG_PTR imagebase, bool bDirectSyscall = false);
	bool patchEntryPoint(ULONG_PTR baseAddress, ULONG_PTR addressOfEntryPoint);
	void resume();
	
	void close();

private:
	bool getThreadContext();

private:
	bool m_activate;
	HANDLE m_thread;
	HANDLE m_process;
	LPCONTEXT m_pthreadContext;
	ULONG_PTR m_processImageBase;
};
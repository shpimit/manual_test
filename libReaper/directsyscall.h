#pragma once
#include "nt.h"

EXTERN_C NTSTATUS NTAPI	DirectNtAllocateVirtualMemory(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
);

EXTERN_C NTSTATUS NTAPI DirectNtUnmapViewOfSection(
	HANDLE ProcessHandle,
	PVOID BaseAddress
);

EXTERN_C NTSTATUS NTAPI DirectNtQueryInformationProcess(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
);

EXTERN_C NTSTATUS NTAPI DirectNtReadVirtualMemory(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToRead,
	PULONG NumberOfBytesReaded OPTIONAL
);

EXTERN_C NTSTATUS NTAPI DirectNtWriteVirtualMemory(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToWrite,
	PULONG NumberOfBytesWritten OPTIONAL
);
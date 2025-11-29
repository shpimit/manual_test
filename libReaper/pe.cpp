#include "pe.h"

pe::pe(PBYTE peBuffer, SIZE_T peSize) :
	m_pDosHeader(NULL),
	m_pNTHeader(NULL)
{
	m_peBuffer = (PBYTE)VirtualAllocEx(GetCurrentProcess(), NULL, peSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (m_peBuffer != NULL)
	{
		ZeroMemory(m_peBuffer, peSize);
		CopyMemory(m_peBuffer, peBuffer, peSize);

		m_pDosHeader = (PIMAGE_DOS_HEADER)m_peBuffer;
		m_pNTHeader = (PIMAGE_NT_HEADERS)&m_peBuffer[m_pDosHeader->e_lfanew];
	}
}

pe::~pe()
{
	if (m_peBuffer != NULL)
	{
		VirtualFreeEx(GetCurrentProcess(), (PVOID)m_peBuffer, 0, MEM_RELEASE);
		m_peBuffer = NULL;
	}
}

bool pe::isParse()
{
	if (m_pDosHeader != NULL &&
		m_pNTHeader != NULL)
	{
		return true;
	}

	return false;
}

ULONG pe::imageSize()
{
	if (!isParse())
		return 0;

	return (ULONG)m_pNTHeader->OptionalHeader.SizeOfImage;
}

ULONG pe::addressOfEntryPoint()
{
	if (!isParse())
		return 0;

	return (ULONG)m_pNTHeader->OptionalHeader.AddressOfEntryPoint;
}

USHORT pe::numberOfSection()
{
	if (!isParse())
		return 0;

	return (USHORT)m_pNTHeader->FileHeader.NumberOfSections;
}

ULONG_PTR pe::getFirstSection()
{
	if (!isParse())
		return NULL;

	return (ULONG_PTR)IMAGE_FIRST_SECTION(m_pNTHeader);
}

ULONG_PTR pe::getNextSection(ULONG_PTR currentSection)
{
	if (!isParse())
		return NULL;

	return (ULONG_PTR)((PBYTE)currentSection + sizeof(IMAGE_SECTION_HEADER));
}

LONG_PTR pe::getRelativeOffset(ULONG_PTR imagebase)
{
	if (!isParse())
		return 0;

	return (LONG_PTR)imagebase - m_pNTHeader->OptionalHeader.ImageBase;
}

void pe::setImagebase(LONG_PTR imagebase)
{
	m_pNTHeader->OptionalHeader.ImageBase = (LONG_PTR)imagebase;
}

ULONG_PTR pe::memAlloc(SIZE_T size)
{
	ULONG_PTR retAddress = 0;

	retAddress = (ULONG_PTR)VirtualAllocEx(GetCurrentProcess(), NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (retAddress == NULL)
		return 0;

	ZeroMemory((PVOID)retAddress, size);

	return retAddress;
}

PVOID pe::getAddress(HMODULE Module, char* FunctionName)
{
	LPBYTE lpModule = (LPBYTE)Module;
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)lpModule;
	PIMAGE_NT_HEADERS NTHeaders = (PIMAGE_NT_HEADERS)(lpModule + DosHeader->e_lfanew);

	PIMAGE_DATA_DIRECTORY DataDirectories = NULL;

	DataDirectories = &NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	if (DataDirectories->VirtualAddress == 0 || DataDirectories->Size == 0)
	{
		return NULL;
	}

	PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(lpModule + DataDirectories->VirtualAddress);

	PULONG ExportFunctionRVA = NULL;
	PULONG ExportFunctionNameRVA = NULL;
	PUSHORT ExportFunctionOridinal = NULL;

	BOOLEAN LookupByName = (ULONG_PTR)FunctionName > USHRT_MAX;
	ULONG FunctionIndex = 0;
	ULONG FunctionRVA = 0;

	if (ExportDirectory->AddressOfFunctions == 0)
		return NULL;

	ExportFunctionRVA = (PULONG)(lpModule + ExportDirectory->AddressOfFunctions);

	if (LookupByName)
	{
		ULONG NameIndex;

		if (FunctionName[0] == '\0')
			return NULL;

		if (ExportDirectory->AddressOfNames)
			ExportFunctionNameRVA = (PULONG)(lpModule + ExportDirectory->AddressOfNames);
		if (ExportDirectory->AddressOfNameOrdinals)
			ExportFunctionOridinal = (PUSHORT)(lpModule + ExportDirectory->AddressOfNameOrdinals);

		if (ExportFunctionNameRVA == NULL || ExportFunctionOridinal == NULL)
			return NULL;

		for (NameIndex = 0; NameIndex < ExportDirectory->NumberOfNames; NameIndex++)
		{
			PCSTR Name = (PCSTR)(lpModule + ExportFunctionNameRVA[NameIndex]);
			if (Name)
			{
				if (strncmp(Name, FunctionName, 0x7fff) == 0)
				{
					FunctionIndex = ExportFunctionOridinal[NameIndex];
					if (ExportDirectory->NumberOfFunctions <= FunctionIndex)
						return NULL;

					FunctionRVA = ExportFunctionRVA[FunctionIndex];
					break;
				}
			}
		}
	}
	else
	{
		ULONG Ordinal = (USHORT)(ULONG_PTR)FunctionName;
		if (Ordinal < ExportDirectory->Base)
			return NULL;

		FunctionIndex = Ordinal - ExportDirectory->Base;
		if (ExportDirectory->NumberOfFunctions <= FunctionIndex)
			return NULL;

		FunctionRVA = ExportFunctionRVA[FunctionIndex];
	}

	if (FunctionRVA == 0)
		return NULL;

	return (FARPROC)(lpModule + FunctionRVA);
}


bool pe::resolveIAT(ULONG_PTR imageBase)
{
	PIMAGE_DATA_DIRECTORY DataDirectories = &m_pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (DataDirectories->VirtualAddress != 0 &&
		DataDirectories->Size != 0)
	{
		PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor =
			(PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)imageBase + DataDirectories->VirtualAddress);

		while (ImportDescriptor->Name)
		{
			char* ModuleName = ((char*)imageBase + ImportDescriptor->Name);
			HMODULE hModule = LoadLibraryA(ModuleName);

			if (hModule == NULL)
			{
				return false;
			}

			PIMAGE_THUNK_DATA ThunkData = (PIMAGE_THUNK_DATA)((PBYTE)imageBase + ImportDescriptor->OriginalFirstThunk);
			PIMAGE_THUNK_DATA IATThunkData = (PIMAGE_THUNK_DATA)((PBYTE)imageBase + ImportDescriptor->FirstThunk);

			while (ThunkData->u1.AddressOfData)
			{
				if (ThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					IATThunkData->u1.AddressOfData = (DWORD_PTR)GetProcAddress(hModule, (LPCSTR)IMAGE_ORDINAL(ThunkData->u1.Ordinal));
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)((char*)imageBase + ThunkData->u1.AddressOfData);
					IATThunkData->u1.AddressOfData = (DWORD_PTR)GetProcAddress(hModule, (LPCSTR)ImportByName->Name);
				}

				ThunkData++;
				IATThunkData++;
			}

			ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((char*)ImportDescriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR));
		}

		return true;
	}

	return false;
}

void pe::relocate(ULONG_PTR buildAddr, ULONG_PTR relativeOffset)
{
	if (buildAddr != 0 && relativeOffset != 0)
	{
		PIMAGE_DATA_DIRECTORY pDataDirectory = 
			(PIMAGE_DATA_DIRECTORY)(&m_pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

		if (pDataDirectory->VirtualAddress != 0 &&
			pDataDirectory->Size != 0)
		{
			PIMAGE_BASE_RELOCATION pBaseRelocation =
				(PIMAGE_BASE_RELOCATION)(buildAddr + pDataDirectory->VirtualAddress);

			while (pBaseRelocation->SizeOfBlock)
			{
				PBYTE VirtualAddress = (PBYTE)buildAddr + pBaseRelocation->VirtualAddress;
				DWORD dwEntryCount = (pBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				PWORD pRelocEntry = (PWORD)((PBYTE)pBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));

				while (dwEntryCount--)
				{
					WORD Type = (*pRelocEntry & 0xF000) >> 12;
					WORD Offset = *pRelocEntry & 0xFFF;

					switch (Type)
					{
					case IMAGE_REL_BASED_HIGH:
						*(ULONGLONG*)(VirtualAddress + Offset) += HIWORD(relativeOffset);
						break;
					case IMAGE_REL_BASED_LOW:
						*(ULONGLONG*)(VirtualAddress + Offset) += LOWORD(relativeOffset);
						break;
					case IMAGE_REL_BASED_HIGHLOW:
						*(DWORD*)(VirtualAddress + Offset) += (DWORD)relativeOffset;
						break;
					case IMAGE_REL_BASED_DIR64:
						*(ULONGLONG*)(VirtualAddress + Offset) += (ULONGLONG)relativeOffset;
						break;
					}

					pRelocEntry++;
				}

				pBaseRelocation = (PIMAGE_BASE_RELOCATION)((PBYTE)pBaseRelocation + pBaseRelocation->SizeOfBlock);
			}
		}
	}
}

void pe::memFree(ULONG_PTR buildAddr)
{
	if (buildAddr != NULL)
	{
		VirtualFreeEx(GetCurrentProcess(), (PVOID)buildAddr, 0, MEM_RELEASE);
		buildAddr = NULL;
	}
}

PBYTE pe::peHeader()
{
	return (PBYTE)m_peBuffer;
}

ULONG pe::peHeaderSize()
{
	if (!isParse())
		return 0;

	return (ULONG)m_pNTHeader->OptionalHeader.SizeOfHeaders;
}
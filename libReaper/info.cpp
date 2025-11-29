#include "info.h"

info::info()
{
	open();
}

info::~info()
{
	close();
}

bool info::isOpen()
{
	if (m_hKey == NULL)
		return false;
	return true;
}

bool info::open()
{
	LONG ret;
	ret = RegOpenKeyExA(
		HKEY_LOCAL_MACHINE,
		"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
		0, KEY_QUERY_VALUE, &m_hKey
	);

	if (ret != ERROR_SUCCESS)
	{
		return false;
	}

	return true;
}

std::string info::pcname()
{
	std::string retinfo;
	std::vector<CHAR> buffer(256);
	DWORD dwLength = 256;

	if (GetComputerNameA(&buffer[0], &dwLength))
	{
		retinfo.append(&buffer[0]);
		return retinfo;
	}

	return "";
}

std::string info::os()
{
	LONG ret = 0;
	DWORD dwLength = 0;
	std::string retinfo;
	std::vector<CHAR> ProductName(256);
	std::vector<CHAR> DisplayName(100);
	std::vector<CHAR> CurrentBuildNumber(100);	

	if (isOpen())
	{
		ret = RegQueryValueExA(m_hKey, "ProductName", NULL, NULL, (LPBYTE)&ProductName[0], &dwLength);

		if(ret == ERROR_MORE_DATA)
		{
			std::vector<CHAR> tmp;
			tmp.resize(dwLength);
			ret = RegQueryValueExA(m_hKey, "ProductName", NULL, NULL, (LPBYTE)&tmp[0], &dwLength);

			if (ret == ERROR_SUCCESS)
			{
				retinfo.append(tmp.data());
			}
		}
		else
		{
			retinfo.append(&ProductName[0]);
		}

		ret = RegQueryValueEx(m_hKey, L"DisplayVersion", NULL, NULL, (LPBYTE)&DisplayName[0], &dwLength);
		if (ret == ERROR_SUCCESS)
		{
			retinfo += " ";
			retinfo.append(&DisplayName[0]);
		}

		ret = RegQueryValueEx(m_hKey, L"CurrentBuildNumber", NULL, NULL, (LPBYTE)&CurrentBuildNumber[0], &dwLength);

		if (ret == ERROR_MORE_DATA)
		{
			std::vector<CHAR> tmp;
			tmp.resize(dwLength);
			ret = RegQueryValueEx(m_hKey, L"CurrentBuildNumber", NULL, NULL, (LPBYTE)&tmp[0], &dwLength);

			if (ret == ERROR_SUCCESS)
			{
				retinfo += " (";
				retinfo.append(tmp.data());
				retinfo += ")";
			}
		}
		else
		{
			retinfo += " (";
			retinfo.append(&CurrentBuildNumber[0]);
			retinfo += ")";
		}

		return retinfo;
	}

	return "";
}

std::string info::user()
{
	std::string retinfo;
	std::vector<CHAR> buffer(256);
	DWORD dwLength = 256;

	if (GetUserNameA(&buffer[0], &dwLength))
	{
		retinfo.append(&buffer[0]);
		return retinfo;
	}

	return "";
}
std::string info::language()
{
	std::string retinfo;
	std::vector<CHAR> buffer(256);
	DWORD dwLength = 256;

	if (GetLocaleInfoA(LOCALE_SYSTEM_DEFAULT, LOCALE_ICOUNTRY, &buffer[0], 256))
	{
		DWORD dwLang = atoi(&buffer[0]);
		switch (dwLang)
		{
		case 1:
			retinfo.append("USA");
			break;
		case 7:
			retinfo.append("RUS");
			break;
		case 81:
			retinfo.append("JP");
			break;
		case 82:
			retinfo.append("KR");
			break;
		case 86:
			retinfo.append("CN");
			break;
		default:
			retinfo.append("UNKNOWN_LOCALE");
			break;
		}
		return retinfo;
	}

	return "";
}

std::string info::time()
{
	std::string retinfo;
	std::vector<CHAR> buffer(256);
	SYSTEMTIME t;

	GetLocalTime(&t);
	sprintf_s(&buffer[0], 256, "%04d-%02d-%02d-%02d:%02d:%02d",
		t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond
	);

	retinfo.append(&buffer[0]);

	return retinfo;
}

void info::close()
{
	if (m_hKey != NULL)
	{
		RegCloseKey(m_hKey);
		m_hKey = NULL;
	}
}
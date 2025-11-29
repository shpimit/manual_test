#pragma once
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

#include <string>

#define CONTENTS_TYPE_JSON L"Content-Type: application/json\r\n"
#define CONTENTS_TYPE_OCTECTSTREAM L"Content-Type: application/octet-stream"

class http
{
public:
	http();
	~http();

	void init(
		PCWSTR pwszServerName,
		SHORT serverPort
	);

	bool get(
		PCWSTR pwszHeader,
		PCWSTR pwszWhere,
		PBYTE* pbOctetStream,
		ULONG* ulOctetStreamLength
	);

	std::string postStream(
		PCWSTR pwszHeader,
		PCWSTR pwszWhere,
		PBYTE pbInfoStream,
		ULONG ulInfoStreamLength
	);

private:
	HINTERNET m_hSession;
	HINTERNET m_hConnect;
	HINTERNET m_Request;
	WCHAR m_serverName[256];
	SHORT m_serverPort;
};
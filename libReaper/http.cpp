#include "http.h"

http::http()
{
	m_hSession = NULL;
	m_hConnect = NULL;
	m_Request = NULL;
	RtlZeroMemory(m_serverName, 256);
	m_serverPort = 0;
}

http::~http()
{
	if (m_hConnect != NULL)
	{
		WinHttpCloseHandle(m_hConnect);
		m_hConnect = NULL;
	}

	if (m_hSession != NULL)
	{
		WinHttpCloseHandle(m_hSession);
		m_hSession = NULL;
	}
}

void http::init(
	PCWSTR pwszServerName,
	SHORT serverPort
)
{
	m_hSession = WinHttpOpen(
		L"HTTP Application/1.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS,
		0
	);

	m_hConnect = WinHttpConnect(
		m_hSession,
		pwszServerName,
		serverPort,
		0
	);

	RtlCopyMemory(m_serverName, pwszServerName, wcslen(pwszServerName) * sizeof(WCHAR));
	m_serverPort = serverPort;
}

bool http::get(
	PCWSTR pwszHeader,
	PCWSTR pwszWhere,
	PBYTE* pbOctetStream,
	ULONG* ulOctetStreamLength
)
{
	bool bRet = false;
	LPCWSTR AcceptType[2] = { pwszHeader, NULL };
	PBYTE OutputBuffer = NULL;
	PBYTE HeaderBuffer = NULL;
	ULONG TotalReceiveSize = 0;
	ULONG DataAvailableSize = 0;
	ULONG DownloadSize = 0;
	ULONG ReceiveSize = 8192;
	ULONG ReceiveIndex = 0;

	m_Request = WinHttpOpenRequest(
		m_hConnect,
		L"GET",
		pwszWhere,
		NULL,
		WINHTTP_NO_REFERER,
		AcceptType,
		0
	);

	if (m_Request == NULL)
		return false;

	if (!WinHttpSendRequest(
		m_Request,
		WINHTTP_NO_ADDITIONAL_HEADERS,
		0,
		WINHTTP_NO_REQUEST_DATA,
		0,
		0,
		NULL
	))
	{
		return false;
	}

	if (!WinHttpReceiveResponse(m_Request, NULL))
		return false;

	if (!WinHttpQueryHeaders(
		m_Request,
		WINHTTP_QUERY_CONTENT_LENGTH,
		WINHTTP_HEADER_NAME_BY_INDEX,
		WINHTTP_NO_OUTPUT_BUFFER,
		&TotalReceiveSize,
		WINHTTP_NO_HEADER_INDEX
	))
	{
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			HeaderBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, TotalReceiveSize);

			if (HeaderBuffer != NULL)
			{
				ZeroMemory(HeaderBuffer, TotalReceiveSize);

				if (!WinHttpQueryHeaders(
					m_Request,
					WINHTTP_QUERY_CONTENT_LENGTH,
					WINHTTP_HEADER_NAME_BY_INDEX,
					HeaderBuffer,
					&TotalReceiveSize,
					WINHTTP_NO_HEADER_INDEX
				))
				{
					return false;
				}

				TotalReceiveSize = _wtoi((LPCWSTR)HeaderBuffer);
				(*ulOctetStreamLength) = TotalReceiveSize;
			}
		}
	}

	if (TotalReceiveSize == 0)
		return false;

	(*pbOctetStream) = (PBYTE)HeapAlloc(GetProcessHeap(), 0, TotalReceiveSize);

	if ((*pbOctetStream) == NULL)
		return false;

	ZeroMemory((*pbOctetStream), TotalReceiveSize);

	do
	{
		WinHttpQueryDataAvailable(m_Request, &DataAvailableSize);

		if (DataAvailableSize == 0)
			break;

		if (!WinHttpReadData(
			m_Request,
			&(*pbOctetStream)[ReceiveIndex],
			DataAvailableSize,
			&DownloadSize
		))
		{
			goto _RET;
		}

		ReceiveIndex += DataAvailableSize;

	} while (DataAvailableSize > 0);

	bRet = true;

_RET:
	return bRet;
}

std::string http::postStream(
	PCWSTR pwszHeader,
	PCWSTR pwszWhere,
	PBYTE pbInfoStream,
	ULONG ulInfoStreamLength
)
{
	std::string retStream;
	ULONG DataAvailableSize = 0;
	ULONG ReceiveLength = 0;

	m_Request = WinHttpOpenRequest(
		m_hConnect,
		L"POST",
		pwszWhere,
		NULL,
		WINHTTP_NO_REFERER,
		NULL,
		0
	);

	if (m_Request == NULL)
		return "";

	if (!WinHttpSendRequest(
		m_Request,
		pwszHeader,
		0,
		pbInfoStream,
		ulInfoStreamLength,
		ulInfoStreamLength,
		NULL
	))
	{
		return "";
	}

	if (!WinHttpReceiveResponse(m_Request, NULL))
		return "";

	WinHttpQueryDataAvailable(m_Request, &DataAvailableSize);

	if (DataAvailableSize == 0)
		return "";

	BYTE receiveData[256] = { 0, };
	if (!WinHttpReadData(
		m_Request,
		receiveData,
		DataAvailableSize,
		&ReceiveLength
	))
	{
		return "";
	}

	retStream = (PCHAR)receiveData;
	return retStream;
}
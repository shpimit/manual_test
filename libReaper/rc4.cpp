#include "rc4.h"

rc4::rc4()
{


}

rc4::~rc4()
{

}

bool rc4::decrypt(
	_In_ BYTE* RC4CipherMsg,
	_In_ ULONG RC4CipherMsgLength,
	_In_ BYTE* RC4DecryptKey,
	_In_ ULONG RC4DecryptKeyLength,
	_Out_ BYTE** Message,
	_Out_ ULONG* MessageLength
)
{
	bool bRet = false;
	NTSTATUS status = STATUS_SUCCESS;
	BCRYPT_ALG_HANDLE AlgorithmHandle = NULL;
	BCRYPT_KEY_HANDLE KeyHandle = NULL;

	PBYTE KeyObject = NULL;
	ULONG KeyObjectLength = 0;
	ULONG KeyObjectLengthData = 0;

	ULONG DecryptLength = 0;
	ULONG DecryptLengthData = 0;

	status = BCryptOpenAlgorithmProvider(
		&AlgorithmHandle,
		BCRYPT_RC4_ALGORITHM,
		NULL,
		0
	);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	status = BCryptGetProperty(
		AlgorithmHandle,
		BCRYPT_OBJECT_LENGTH,
		(PBYTE)&KeyObjectLength,
		sizeof(ULONG),
		&KeyObjectLengthData,
		0
	);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	KeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, KeyObjectLength);

	if (KeyObject == NULL)
	{
		goto _RET;
	}

	RtlZeroMemory(KeyObject, KeyObjectLength);

	status = BCryptGenerateSymmetricKey(
		AlgorithmHandle,
		&KeyHandle,
		KeyObject,
		KeyObjectLength,
		RC4DecryptKey,
		RC4DecryptKeyLength,
		0
	);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	status = BCryptDecrypt(
		KeyHandle,
		RC4CipherMsg,
		RC4CipherMsgLength,
		NULL,
		NULL,
		0,
		NULL,
		0,
		&DecryptLength,
		0
	);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	(*Message) = (PBYTE)HeapAlloc(GetProcessHeap(), 0, DecryptLength);

	if ((*Message) == NULL)
	{
		goto _RET;
	}

	RtlZeroMemory((*Message), DecryptLength);

	status = BCryptDecrypt(
		KeyHandle,
		RC4CipherMsg,
		RC4CipherMsgLength,
		NULL,
		NULL,
		0,
		(*Message),
		DecryptLength,
		&DecryptLengthData,
		0
	);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	*MessageLength = DecryptLengthData;

	bRet = true;

_RET:
	if (KeyHandle != NULL)
	{
		BCryptDestroyKey(KeyHandle);
		KeyHandle = NULL;
	}

	if (KeyObject != NULL)
	{
		HeapFree(GetProcessHeap(), 0, KeyObject);
		KeyObject = NULL;
	}

	if (AlgorithmHandle != NULL)
	{
		BCryptCloseAlgorithmProvider(AlgorithmHandle, 0);
		AlgorithmHandle = NULL;
	}

	return bRet;
}

bool rc4::encrypt(
	_In_ BYTE* Message,
	_In_ ULONG MessageLength,
	_In_ BYTE* RC4EncryptKey,
	_In_ ULONG RC4EncryptKeyLength,
	_Out_ BYTE** RC4CipherMsg,
	_Out_ ULONG* RC4CipherMsgLength
)
{
	bool bRet = false;
	NTSTATUS status = STATUS_SUCCESS;
	BCRYPT_ALG_HANDLE AlgorithmHandle = NULL;
	BCRYPT_KEY_HANDLE KeyHandle = NULL;

	PBYTE KeyObject = NULL;
	ULONG KeyObjectLength = 0;
	ULONG KeyObjectLengthData = 0;

	ULONG EncryptLength = 0;
	ULONG EncryptLengthData = 0;

	status = BCryptOpenAlgorithmProvider(
		&AlgorithmHandle,
		BCRYPT_RC4_ALGORITHM,
		NULL,
		0
	);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	status = BCryptGetProperty(
		AlgorithmHandle,
		BCRYPT_OBJECT_LENGTH,
		(PBYTE)&KeyObjectLength,
		sizeof(ULONG),
		&KeyObjectLengthData,
		0
	);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	KeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, KeyObjectLength);

	if (KeyObject == NULL)
	{
		goto _RET;
	}

	RtlZeroMemory(KeyObject, KeyObjectLength);

	status = BCryptGenerateSymmetricKey(
		AlgorithmHandle,
		&KeyHandle,
		KeyObject,
		KeyObjectLength,
		RC4EncryptKey,
		RC4EncryptKeyLength,
		0
	);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	status = BCryptEncrypt(
		KeyHandle,
		Message,
		MessageLength,
		NULL,
		NULL,
		0,
		NULL,
		0,
		&EncryptLength,
		0
	);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	(*RC4CipherMsg) = (PBYTE)HeapAlloc(GetProcessHeap(), 0, EncryptLength);

	if ((*RC4CipherMsg) == NULL)
	{
		goto _RET;
	}

	RtlZeroMemory((*RC4CipherMsg), EncryptLength);

	status = BCryptEncrypt(
		KeyHandle,
		Message,
		MessageLength,
		NULL,
		NULL,
		0,
		(*RC4CipherMsg),
		EncryptLength,
		&EncryptLengthData,
		0
	);

	if (!NT_SUCCESS(status))
	{
		goto _RET;
	}

	*RC4CipherMsgLength = EncryptLengthData;

	bRet = true;

_RET:
	if (KeyHandle != NULL)
	{
		BCryptDestroyKey(KeyHandle);
		KeyHandle = NULL;
	}

	if (KeyObject != NULL)
	{
		HeapFree(GetProcessHeap(), 0, KeyObject);
		KeyObject = NULL;
	}

	if (AlgorithmHandle != NULL)
	{
		BCryptCloseAlgorithmProvider(AlgorithmHandle, 0);
		AlgorithmHandle = NULL;
	}

	return bRet;
}
#pragma once
#include <Windows.h>
#include <string>

#pragma comment(lib, "Bcrypt.lib")

#define STATUS_SUCCESS 0

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) ((NTSTATUS)(status) >= 0)
#endif

class rc4
{
public:
	rc4();
	~rc4();

	bool decrypt(
		_In_ BYTE* RC4CipherMsg,
		_In_ ULONG RC4CipherMsgLength,
		_In_ BYTE* RC4DecryptKey,
		_In_ ULONG RC4DecryptKeyLength,
		_Out_ BYTE** Message,
		_Out_ ULONG* MessageLength
	);

	bool encrypt(
		_In_ BYTE* Message,
		_In_ ULONG MessageLength,
		_In_ BYTE* RC4EncryptKey,
		_In_ ULONG RC4EncryptKeyLength,
		_Out_ BYTE** RC4CipherMsg,
		_Out_ ULONG* RC4CipherMsgLength
	);
};
#include "common.h"


BOOL RtlFileExists(WCHAR* InPath)
{
	HANDLE          hFile;

	if ((hFile = CreateFileW(InPath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE)
		return FALSE;

	CloseHandle(hFile);

	return TRUE;
}

LONG RtlGetWorkingDirectory(WCHAR* OutPath, ULONG InMaxLength)
{
	NTSTATUS            NtStatus = STATUS_SUCCESS;
	LONG				Index = 0;

	// 第一参数传空 得到就是 exe的完整路径
	Index = GetModuleFileName(NULL, OutPath, InMaxLength);
	
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		THROW(STATUS_BUFFER_TOO_SMALL, L"The given buffer is too small.");
	}

	// remove file name...
	for (Index--; Index >= 0; Index--)
	{
		if (OutPath[Index] == '\\')
		{
			OutPath[Index + 1] = 0;

			break;
		}
	}

	RETURN;

THROW_OUTRO:
FINALLY_OUTRO:
	return NtStatus;
}

LONG RtlGetCurrentModulePath(WCHAR* OutPath, ULONG InMaxLength)
{
	NTSTATUS            NtStatus = STATUS_SUCCESS;

	// 传递了 当前Dll句柄 得到的就是Dll完整路径
	GetModuleFileName(CurrentModuleHandle, OutPath, InMaxLength);

	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		THROW(STATUS_BUFFER_TOO_SMALL, L"The given buffer is too small.");
	}

	RETURN;

THROW_OUTRO:
FINALLY_OUTRO:
	return NtStatus;
}

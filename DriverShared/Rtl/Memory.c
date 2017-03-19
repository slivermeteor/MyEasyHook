/*
* EasyHookDll/DriverShared/Rtl/Memory.c
* 函数声明在 EasyHookDll/DriverShared/Rtl/Rtl.h 下
*/

#include "common.h"

BOOL RtlIsValidPointer(PVOID InPtr, ULONG InSize)
{
	if ((InPtr == NULL) || (InPtr == (PVOID)~0))
		return FALSE;

	ASSERT(!IsBadReadPtr(InPtr, InSize), L"memory.c - !IsBadReadPtr(InPtr, InSize)");

	return TRUE;
}

VOID RtlCopyMemory(PVOID InDest, PVOID InSource, ULONG32 InByteCount)
{
	if (InDest == NULL || InSource == NULL)
	{
		return;
	}	
	ULONG32 Index = 0;
	PUCHAR  Dest = (PUCHAR)InDest;
	PUCHAR  Source = (PUCHAR)InSource;

	for (ULONG32 Index = 0; Index < InByteCount; Index++)
	{
		/*UCHAR a = 0;
		CHAR b = 0;
		a = *Source;
		b = *Source;*/
		
		*Dest = *Source;
		if (Index == 0 && *Source == 0xCC)
			*Dest = 0x8B;
		

		Dest++;
		Source++;
	}

	return ;
}

VOID RtlFreeMemory(PVOID InPointer)
{
	if (InPointer == NULL)
	{
		return;
	}

#ifdef _DEBUG
	free(InPointer);
#else
	HeapFree(EasyHookHeapHandle, 0, InPointer);
#endif
}

VOID* RtlAllocateMemory(BOOL InZeroMemory, ULONG32 InSize)
{
	PVOID Return =
#ifdef _DEBUG
		malloc(InSize);
#else
		HeapAlloc(EasyHookHeapHandle, 0, InSize);
#endif

	if (InZeroMemory && Return != NULL)
	{
		RtlZeroMemory(Return, InSize);
	}

	return Return;
}

#ifndef _DEBUG
	#pragma optimize("", off)	// 关闭优化选项 - 阻止使用 _memset
#endif
VOID RtlZeroMemory(PVOID InStart, ULONG32 InByteCount)
{
	ULONG32		ulIndex = 0;
	PUCHAR		Target = (PUCHAR)InStart;

	for (ulIndex = 0; ulIndex < InByteCount; ulIndex++)
	{
		*Target = 0;
		Target++;
	}

	return;
}
#ifndef _DEBUG
	#pragma optimize("", on)
#endif

LONG RtlProtectMemory(PVOID InPointer, ULONG InSize, ULONG InNewProtection)
{
	DWORD OldProtect = 0;
	NTSTATUS NtStatus = STATUS_SUCCESS;

	if (!VirtualProtect(InPointer, InSize, InNewProtection, &OldProtect))
	{
		THROW(STATUS_INVALID_PARAMETER, L"Unable To Change Page Property.");
	}

	RETURN;
THROW_OUTRO:
FINALLY_OUTRO:
	{
		return NtStatus;
	}
}

VOID RtlAcquireLock(PRTL_SPIN_LOCK InLock)
{
	EnterCriticalSection(&InLock->Lock);

	// 如果已经有人进入临界区 - 说明发生了死锁 触发断言
	ASSERT(!InLock->IsOwned, L"Memory.c - !InLock->IsOwned");

	InLock->IsOwned = TRUE;
}

VOID RtlReleaseLock(PRTL_SPIN_LOCK InLock)
{
	// 如果没有进入临界区 - 异常 触发断言
	ASSERT(InLock->IsOwned, L"Memory.c - !InLock->IsOwned");

	InLock->IsOwned = FALSE;

	LeaveCriticalSection(&InLock->Lock);
}

void RtlDeleteLock(RTL_SPIN_LOCK* InLock)
{
	ASSERT(!InLock->IsOwned, L"Memory.c - InLock->IsOwned");

	DeleteCriticalSection(&InLock->Lock);
}

void RtlInitializeLock(RTL_SPIN_LOCK* OutLock)
{
	RtlZeroMemory(OutLock, sizeof(RTL_SPIN_LOCK));

	InitializeCriticalSection(&OutLock->Lock);
}

void RtlSleep(ULONG InTime)
{
	Sleep(InTime);
}
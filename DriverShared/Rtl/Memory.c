#include "common.h"

BOOL RtlIsValidPointer(PVOID InPtr, ULONG InSize)
{
	if ((InPtr == NULL) || (InPtr == (PVOID)~0))
		return FALSE;

	ASSERT(!IsBadReadPtr(InPtr, InSize), L"memory.c - !IsBadReadPtr(InPtr, InSize)");

	return TRUE;
}

VOID* RtlAllocateMemory(BOOL InZeroMemory, ULONG32 InSize)
{
	PVOID Return =
#ifdef _DEBUG
		malloc(InSize);
#else
		//HeapAlloc();
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

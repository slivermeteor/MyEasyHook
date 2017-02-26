#include "common.h"

// 申请一页内存在Hook函数入口，并返回申请长度
PVOID LhAllocateMemoryEx(PVOID InEntryPoint, PULONG OutPageSize)
{
	PUCHAR Result = NULL;
	// user-mode 64位 变量定义
#if defined(_M_X64) && !defined(DRIVER)
	LONGLONG		Base = 0;
	LONGLONG		Start = 0;
	LONGLONG		End = 0;
	LONGLONG		Index = 0;
#endif

	// User-mode 变量
#if !defined(DRIVER)
	SYSTEM_INFO SystemInfo = { 0 };
	ULONG		PageSize = 0;

	GetSystemInfo(&SystemInfo);
	PageSize = SystemInfo.dwPageSize;
	*OutPageSize = PageSize;
#endif

#if defined(_M_X64) && !defined(DRIVER)
	Start = ((LONGLONG)InEntryPoint) - ((LONGLONG)0x7FFFFF00);	// 申请内存空间极限 - 为了我们在后面跳转的时候 可以用相对偏移 - 而不用绝对位置
	End = ((LONGLONG)InEntryPoint) + ((LONGLONG)0x7FFFFF00);	// 64bit user-mode 使用 E9最为Hook跳转 也就是 jump ________ 4字节的偏移 这个偏移是INT(32bit)
																// 又因为它构造的是 31bit的范围 所以正向和负向偏移 最大位 0x7FFFFF00

	// 得带最大和最小可以访问地址 - 防止上面加/减穿
	if (Start < (LONGLONG)SystemInfo.lpMinimumApplicationAddress)
	{
		Start = (LONGLONG)SystemInfo.lpMinimumApplicationAddress;
	}
	if (End < (LONGLONG)SystemInfo.lpMaximumApplicationAddress)
	{
		Start = (LONGLONG)SystemInfo.lpMaximumApplicationAddress;
	}

	for (Base = (LONGLONG)InEntryPoint, Index = 0; ; Index += PageSize)
	{
		// 实际申请地址 - 尽可能靠近EntryPoint
		BOOLEAN bEnd = TRUE;
		if (Base + Index < End)
		{
			Result = (PUCHAR)VirtualAlloc((PVOID)(Base + Index), PageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (Result != NULL)
			{
				break;
			}
			bEnd = FALSE;
		}
		if (Base - Index > Start)
		{
			Result = (PUCHAR)VirtualAlloc((PVOID)(Base - Index), PageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (Result != NULL)
			{
				break;
			}
			bEnd = FALSE;
		}
		if (bEnd)
		{
			break;
		}
	}
	if (Result == NULL)
	{
		return NULL;
	}
#else
	// 32-bits/ driver  随便申请就可以 E9 都可以跳到
	*OutPageSize = PageSize;
	Result = (PUCHAR)RtlAllocateMemory(TRUE, PageSize);
	if (Result != NULL)
	{
		return NULL;
	}
#endif

	return Result;
}

VOID LhFreeMemory(PLOCAL_HOOK_INFO* HookInfo)
{
#if defined(_M_X64) && !defined(DRIVER)
	VirtualFree(*HookInfo, 0, MEM_RELEASE);
#else
	RtlFreeMemory(*HookInfo);
#endif
	*HookInfo = NULL;

	return;
}
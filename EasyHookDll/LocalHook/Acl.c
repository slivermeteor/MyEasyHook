#include "common.h"

// EasyHook - ACL 
/*
	在每个Hook安装后，你还要设置对应线程的ACL。
	在 Trampoline_ASM 里会调用 LhBarrierIntro 来判断呼叫线程是否在ACL中
	来决定是否执行Hook
*/

LONG LhSetACL(PHOOK_ACL InACL, BOOL InIsExclusive, PULONG InThreadIdList, LONG InThreadCount);

EASYHOOK_NT_API LhSetInclusiveACL(PULONG InThreadIdList, ULONG InThreadCount, TRACED_HOOK_HANDLE InHandle)
{
	PLOCAL_HOOK_INFO Handle = NULL;

	// 判断Hook句柄是否有效 - 返回真正的 LOCAL_HOOK_INFO
	if (!LhIsValidHandle(InHandle, &Handle))
		return STATUS_INVALID_PARAMETER_3;

	return LhSetACL(&Handle->LocalACL, FALSE, InThreadIdList, InThreadCount);
}

// 内部方法 - 向全局或者本地ACLs提供插入方法
LONG LhSetACL(PHOOK_ACL InACL, BOOL InIsExclusive, PULONG InThreadIdList, LONG InThreadCount)
{
	// InACL - 如果你要设置全局 HOOK_ACL,第一参数请传空
	// InIsExclusive - 如果第三参数的所有线程都不能中断，请传 TRUE
	// InThreadIdList - 线程数组，传空自动变为调用线程
	// InThreadCount - 线程ID数组个数，不能超过 MAX_ACE_COUNT

	ULONG Index = 0;

	ASSERT(IsValidPointer(InACL, sizeof(HOOK_ACL)), L"ACL.c - IsValidPointer(InACL, sizeof(HOOK_ACL))");

	// 线程过多
	if (InThreadCount > MAX_ACE_COUNT)
		return STATUS_INVALID_PARAMETER_4;

	// 非法长度
	if (!IsValidPointer(InThreadIdList, InThreadCount * sizeof(ULONG)))
		return STATUS_INVALID_PARAMETER_3;

	// 空表项 - 填充当前线程ID
	for (Index = 0; Index < InThreadCount; Index++)
	{
		if (InThreadIdList[Index] == 0)
			InThreadIdList[Index] = GetCurrentThreadId();
	}

	// 设置 ACL
	InACL->IsExclusive = InIsExclusive;
	InACL->Count = InThreadCount;

	RtlCopyMemory(InACL->Entries, InThreadIdList, InThreadCount * sizeof(ULONG));

	return STATUS_SUCCESS;
}

EASYHOOK_NT_API LhSetGlobalInclusiveACL(PULONG InThreadIdList, ULONG InThreadCount)
{
	return LhSetACL(LhBarrierGetACL(), FALSE, InThreadIdList, InThreadCount);
}
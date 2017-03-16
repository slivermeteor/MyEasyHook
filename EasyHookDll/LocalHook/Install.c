#include "common.h"

// 当前文件使用函数本地声明
PVOID GetTrampolinePtr();
LONG GetTrampolineSize();

// 全局Hook链表
LOCAL_HOOK_INFO GlobalHookListHead;
// 全局已经移除Hook链表
LOCAL_HOOK_INFO GlobalRemovalListHead;
RTL_SPIN_LOCK GlobalHookLock;
ULONG		  GlobalSlotList[MAX_HOOK_COUNT] = { 0 };

static ULONG HLSCounter = 0x10000000;


void LhCriticalInitialize()
{
	RtlZeroMemory(&GlobalHookListHead, sizeof(GlobalHookListHead));
	RtlZeroMemory(&GlobalRemovalListHead, sizeof(GlobalRemovalListHead));

	RtlInitializeLock(&GlobalHookLock);
}

// 最大可以用来跳转的地址长度 
// 一般是8字节，但是在64位驱动下是16字节
#define MAX_JMP_SIZE 16

EASYHOOK_NT_API LhInstallHook(PVOID InEntryPoint, PVOID InHookProc, PVOID InCallBack, TRACED_HOOK_HANDLE OutTracedHookHandle)
{
	BOOL     Exists = FALSE;
	ULONG	 RelocSize = 0;
	LONG64	 RelOffset = 0;
	NTSTATUS NtStatus = STATUS_SUCCESS;
	PLOCAL_HOOK_INFO  LocalHookInfo = NULL;
	// 跳转汇编硬编码 
	UCHAR    Jumper[MAX_JMP_SIZE] = { 0xE9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	ULONG64  EntrySave = 0;

	// 参数检查
	if (!IsValidPointer(InEntryPoint, 1))
	{
		THROW(STATUS_INVALID_PARAMETER_1, L"Invalid EntryPoint.");
	}
	if (!IsValidPointer(InHookProc, 1))
	{
		THROW(STATUS_INVALID_PARAMETER_2, L"Invalid HooKProc.");
	}
	if (!IsValidPointer(OutTracedHookHandle, sizeof(HOOK_TRACE_INFO)))
	{
		THROW(STATUS_INVALID_PARAMETER_4, L"The Hook Trace Handle Is Expected To Be Allocated By The Called.");
	}
	if (OutTracedHookHandle->Link != NULL)
	{
		THROW(STATUS_INVALID_PARAMETER_4, L"The Given Hook Trace Handle Seems To Already By Associated With A Hook.");
	}

	// 申请钩子 准备跳转函数 - Hook存根函数 - 核心函数
	FORCE(LhAllocateHook(InEntryPoint, InHookProc, InCallBack, &LocalHookInfo, &RelocSize));

#ifdef X64_DRIVER


#else
	// 计算实际跳转偏移距离
	RelOffset = (LONG64)LocalHookInfo->Trampoline - ((LONG64)LocalHookInfo->TargetProc + 5);	// TargetProc 放入 E9 + Offset(4字节) - 所以跳转的起始地址是 TargetProc + 5
	if (RelOffset != (LONG)RelOffset)	// 入口实际偏移超出了31位
		THROW(STATUS_NOT_SUPPORTED , L"The Given Entry Point Is Out Of Reach.");

	// 复制偏移
	RtlCopyMemory(Jumper + 1, &RelOffset, 4);
	// 修改入口页面保护属性
	FORCE(RtlProtectMemory(LocalHookInfo->TargetProc, LocalHookInfo->EntrySize, PAGE_EXECUTE_READWRITE));
#endif

	// 记录信息
	RtlAcquireLock(&GlobalHookLock);
	{
		LocalHookInfo->HLSIdent = HLSCounter++;
		Exists = FALSE;

		// 在 GlobalSlotList 中记录当前 HLS - 并且在LocalHookInfo里设置对应的Index
		for (LONG Index = 0; Index < MAX_HOOK_COUNT; Index++)
		{
			if (GlobalSlotList[Index] == 0)
			{
				GlobalSlotList[Index] = LocalHookInfo->HLSIdent;
				LocalHookInfo->HLSIndex = Index;
				Exists = TRUE;

				break;
			}
		}
	}
	RtlReleaseLock(&GlobalHookLock);
	// 如果注册失败
	if (!Exists)
		THROW(STATUS_INSUFFICIENT_RESOURCES, L"Not more than MAX_HOOK_COUNT hooks are supported simultaneously.");

#ifdef X64_DRIVER

#else

	// 保留原本的入口代码 - 5字节 真正的Hook
	EntrySave = *((ULONG64*)LocalHookInfo->TargetProc);
	{
		RtlCopyMemory(&EntrySave, Jumper, 5);

		// 备份原代码
		LocalHookInfo->HookOldSave = EntrySave;
	}
	*((ULONG64*)LocalHookInfo->TargetProc) = EntrySave;

#endif

	// 添加 当前Hook信息到全局Hook链表和返回句柄
	RtlAcquireLock(&GlobalHookLock);
	{
		LocalHookInfo->Next = GlobalHookListHead.Next;
		GlobalHookListHead.Next = LocalHookInfo;
	}
	RtlReleaseLock(&GlobalHookLock);

	LocalHookInfo->Signature = LOCAL_HOOK_SIGNATURE;
	LocalHookInfo->Tracking = OutTracedHookHandle;	// 记录
	OutTracedHookHandle->Link = LocalHookInfo;

	RETURN(STATUS_SUCCESS);

THROW_OUTRO:
FINALLY_OUTRO:
	{
		if (!RTL_SUCCESS(NtStatus))
		{
			if (LocalHookInfo != NULL)
				LhFreeMemory(&LocalHookInfo);
		}
		return NtStatus;
	}
}


EASYHOOK_NT_INTERNAL LhAllocateHook(PVOID InEntryPoint, PVOID InHookProc, PVOID InCallBack, PLOCAL_HOOK_INFO* OutLocalHookInfo, PULONG RelocSize)
{
	NTSTATUS NtStatus = STATUS_SUCCESS;
	ULONG	 PageSize = 0;
	ULONG	 EntrySize = 0;		// 入口指令长度
	PUCHAR   MemoryPtr = NULL;
	LONG64   RelAddr = 0;
	PLOCAL_HOOK_INFO LocalHookInfo = NULL;
	

#ifdef X64_DRIVER

#endif

#ifndef _M_X64
	LONG	Index = 0;
	PUCHAR  Ptr = NULL;
#endif

	
	// 参数检查
	if (!IsValidPointer(InEntryPoint, 1))
	{
		THROW(STATUS_INVALID_PARAMETER_1, L"Invalid EntryPoint.");
	}
	if (!IsValidPointer(InHookProc, 1))
	{
		THROW(STATUS_INVALID_PARAMETER_2, L"Invalid HooKProc.");
	}

	// 申请内存空间 - AllocateEx 这个函数内部有学问，将申请的地址控制在了 32bit偏移之内
	*OutLocalHookInfo = (PLOCAL_HOOK_INFO)LhAllocateMemoryEx(InEntryPoint, &PageSize);
	if (*OutLocalHookInfo == NULL)
	{
		THROW(STATUS_NO_MEMORY, L"Failed To Allocate Memory.");
	}
	LocalHookInfo = *OutLocalHookInfo;

	// 修改页面属性
	FORCE(RtlProtectMemory(LocalHookInfo, PageSize, PAGE_EXECUTE_READWRITE));
	// 将MemoryPtr设置到 LOCAL_HOOK_INFO 的尾部 我们将跳转的ShellCode和原Code拷贝到这个地方
	// 也就说Hook后的 Func 将会是: LOCAL_HOOK_INFO + ShellCode + OldProc
	MemoryPtr = (PUCHAR)(LocalHookInfo + 1);	// LOCAL_HOOK_INFO |
												//                ↑ MemoryPtr

#ifdef X64_DRIVER
	FORCE(EntrySize = LhRoundToNextInstruction(InEntryPoint, X64_DRIVER_JMPSIZE));
#else
	// HookProc 得到第一条尾偏移大于5的指令的尾偏移 == 第一条偏移大于5的指令的偏移
	// 一般WINAPI都是stdcall - 所以入口都是第二次跳转指令，长度也就是5
	FORCE(LhRoundToNextInstruction(InEntryPoint, 5, &EntrySize));
#endif

	// 开始结构体赋值
	LocalHookInfo->Size = sizeof(LOCAL_HOOK_INFO);
#if !_M_X64
	// 32位对初始化截断警告的关闭 - 为了与64位共用一份代码
	__pragma(warning(push))
	__pragma(warning(disable:4305))
#endif
	LocalHookInfo->RandomValue = (PVOID)0x69FAB7309CB312EF;
#if !_M_X64
	__pragma(warning(pop))
#endif
	// 结构体赋值
	LocalHookInfo->HookProc = InHookProc;
	LocalHookInfo->TargetProc = InEntryPoint;
	LocalHookInfo->EntrySize = EntrySize;
	LocalHookInfo->CallBack = InCallBack;
	LocalHookInfo->IsExecutedPtr = (PINT)((PUCHAR)LocalHookInfo + 2048);		// 在申请页面(0x1000)偏移为2048的地方
	*LocalHookInfo->IsExecutedPtr = 0;

	/*
	跳板将会调用下面两个函数在用户定义的hook函数被调用前。
	其中Intro判断ACL - 决定是否执行Hook函数
	*/
	// 未实现函数
	LocalHookInfo->HookIntro = LhBarrierIntro;
	LocalHookInfo->HookOutro = LhBarrierOutro;

	// 拷贝跳转指令
	LocalHookInfo->Trampoline = MemoryPtr; // MemoryPtr 是越过 LocalHookInfo 也就是当前结构体的尾部
	MemoryPtr += GetTrampolineSize();	   // LOCAL_HOOK_INFO | TrampolineASM | 
										   //							      ↑ MemoryPtr

	LocalHookInfo->Size += GetTrampolineSize();	// 长度更新

	// 拷贝 Trampoline asm汇编代码 - 注意在x64位下 前面的fixed值不会被拷贝进去，asm中使用那种技巧来快速访问结构体变量里的值。
	RtlCopyMemory(LocalHookInfo->Trampoline, GetTrampolinePtr(), GetTrampolineSize());
	/*
		重新申请入口代码长度，因为这些代码必须被直接写入到申请的内存空间中。
		之所以要重构入口代码 - 是为了当我们的Hook不执行的时候，我们要直接去调用原函数。所以要对原本入口的跳转代码和EIP相关代码进行重构
		重构的入口代码将被放在 Trampoline 之后
	*/
	// 开始重构原本入口代码
	*RelocSize = 0;
	LocalHookInfo->OldProc = MemoryPtr;

	FORCE(LhRelocateEntryPoint(LocalHookInfo->TargetProc, EntrySize, LocalHookInfo->OldProc, RelocSize));
	// 确保空间还是足够 - RelocCode之后还要放跳回指令
	// 因为如果入口函数不是一句跳转指令，只是一句正常的操作指令。那么我们在执行完成后，应该跳回原函数的下一句地址，继续正常执行。
	MemoryPtr += (*RelocSize + MAX_JMP_SIZE);		// LOCAL_HOOK_INFO | TrampolineASM |  Old Proc |
													//							       | EntrySize |↑ MemoryPtr
	LocalHookInfo->Size += (*RelocSize + MAX_JMP_SIZE);	// 留够足够空间

	// 添加跳转代码到新的入口代码后面
#ifdef X64_DRIVER


#else
	// 计算偏移 - 新入口代码 跳转到 原本函数入口代码跳过重构部分
	// TargetProc + EntrySize : 目标函数地址+入口代码长度(也就是我们废弃掉的长度)													
	// OldProc(用于放原函数的地址) + *RelocSize(对原入口代码进行变化后的指令长度) + 5(当前这句跳转指令的长度) : 
	RelAddr = (LONG64)((PUCHAR)LocalHookInfo->TargetProc + LocalHookInfo->EntrySize) - ((LONG64)LocalHookInfo->OldProc + *RelocSize + 5);

	// 偏移有没有查过32位
	if (RelAddr != (LONG)RelAddr)
	{
		THROW(STATUS_NOT_SUPPORTED, L"The Given Entry Point Is Out Of Reach.");
	}

	// 写入跳转指令 
	((PUCHAR)LocalHookInfo->OldProc)[*RelocSize] = 0xE9;

	RtlCopyMemory((PUCHAR)LocalHookInfo->OldProc + *RelocSize + 1, &RelAddr, 4);

#endif

	// 备份一份 被Hook函数入口的8字节
	LocalHookInfo->TargetBackup = *((PULONG64)LocalHookInfo->TargetProc);

#ifdef X64_DRIVER
	
#endif

#ifndef _M_X64
	// 32bit-asm 需要我们写入实际操作的地址
	// 替换ASM中原本的占位符 - 换成对应具体的地址值
	Ptr = LocalHookInfo->Trampoline;

	for (Index = 0; Index < GetTrampolineSize(); Index++)
	{
#pragma warning(disable:4311)	// 关闭截断警告
		switch (*((PULONG32)Ptr))
		{
			case 0x1A2B3C05:	// LocalHookInfo
			{
				*((PULONG32)Ptr) = (ULONG32)LocalHookInfo;
				break;
			}
			case 0x1A2B3C03:	// NETEntry
			{
				*((ULONG*)Ptr) = (ULONG)LocalHookInfo->HookIntro;
				break;
			}
			case 0x1A2B3C01:	// OldProc
			{
				*((PULONG32)Ptr) = (ULONG32)LocalHookInfo->OldProc;
				break;
			}
			case 0x1A2B3C07:	// HookProc(Ptr)
			{
				*((PULONG32)Ptr) = (ULONG)&LocalHookInfo->HookProc;
				break;
			}
			case 0x1A2B3C00:	// HookProc
			{
				*((PULONG32)Ptr) = (ULONG)LocalHookInfo->HookProc;
				break;
			}
			case 0x1A2B3C06:	// UnmanagedOutro
			{
				*((PULONG32)Ptr) = (ULONG)LocalHookInfo->HookOutro;
				break;
			}
			case 0x1A2B3C02:	// IsExecuted
			{
				*((PULONG32)Ptr) = (ULONG)LocalHookInfo->IsExecutedPtr;
				break;
			}
			case 0x1A2B3C04:	// RetAddr
			{
				*((PULONG32)Ptr) = (ULONG)((ULONG_PTR)LocalHookInfo->Trampoline + 92);
				break;
			}
		}
		Ptr++;
	}

#endif

	RETURN;

THROW_OUTRO:
FINALLY_OUTRO:
	{
		if (!RTL_SUCCESS(NtStatus))
		{
			if (LocalHookInfo != NULL)
			{
				LhFreeMemory(&LocalHookInfo);
			}
		}
		return NtStatus;
	}
}

// ASM函数相关函数
ULONG TrampolineSize = 0;
#ifdef _M_X64
	EXTERN_C VOID __stdcall Trampoline_ASM_x64();
#else
	EXTERN_C VOID __stdcall Trampoline_ASM_x86();
#endif

PVOID GetTrampolinePtr()
{
#ifdef _M_X64
	PUCHAR Ptr = (PUCHAR)Trampoline_ASM_x64;
#else
	PUCHAR Ptr = (PUCHAR)Trampoline_ASM_x86;
#endif

	if (*Ptr == 0xE9)
	{
		Ptr += *((INT*)(Ptr + 1)) + 5;
	}

#ifdef _M_X64
	return Ptr + 5 * 8; // 5个变量
#else
	return Ptr;
#endif
}

LONG GetTrampolineSize()
{
	PUCHAR Ptr = GetTrampolinePtr();
	PUCHAR BasePtr = Ptr;
	ULONG Index = 0;
	ULONG Signature = 0;

	if (TrampolineSize != 0)
	{
		return TrampolineSize;
	}

	for (Index = 0; Index < 1000; Index++)
	{
		Signature = *((PULONG)Ptr);

		if (Signature == 0x12345678)
		{
			TrampolineSize = (ULONG32)((ULONG_PTR)Ptr - (ULONG_PTR)BasePtr);
			
			return TrampolineSize;
		}
		Ptr++;
	}
	ASSERT(FALSE, L"install.c - ULONG GetTrampolineSize()");

	return 0;
}

// 判断传入的句柄是否合理
EASYHOOK_BOOL_INTERNAL LhIsValidHandle(TRACED_HOOK_HANDLE InTracedHandle, PLOCAL_HOOK_INFO* OutHandle)
{
	// 判断标准 - 结构体指针指向有效地址，标志位有效，毕竟已经安装Hook
	if (!IsValidPointer(InTracedHandle, sizeof(HOOK_TRACE_INFO)))
		return FALSE;

	// LOCAL_HOOK_INFO 完整吗?
	if (!IsValidPointer(InTracedHandle->Link, sizeof(LOCAL_HOOK_INFO)))
		return FALSE;

	if (InTracedHandle->Link->Signature != LOCAL_HOOK_SIGNATURE)
		return FALSE;

	// 后面的ShellCode完整吗?
	if (!IsValidPointer(InTracedHandle->Link, InTracedHandle->Link->Size))
		return FALSE;

	// Hook了吗?
	if (InTracedHandle->Link->HookProc == NULL)
		return FALSE;

	if (OutHandle != NULL)
		*OutHandle = InTracedHandle->Link;

	return TRUE;
}
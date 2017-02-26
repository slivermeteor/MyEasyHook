#include "common.h"

// 当前文件使用函数本地声明
PVOID GetTrampolinePtr();
LONG GetTrampolineSize();

EASYHOOK_NT_API  LnInstallHook(PVOID InEntryPoint, PVOID InHookProc, PVOID InCallBack, TRACED_HOOK_HANDLE OutTracedHookHandle)
{
	NTSTATUS NtStatus = STATUS_SUCCESS;
	PLOCAL_HOOK_INFO  LocalHookInfo = NULL;
	ULONG	RelocSize = 0;


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

	// 申请钩子 准本hook 存根
	FORCE(LhAllocateHook(InEntryPoint, InHookProc, InCallBack, &LocalHookInfo, &RelocSize));

THROW_OUTRO:
	{
		return NtStatus;
	}
}

// 最大可以用来跳转的地址长度 
// 一般是8字节，但是在64位驱动下是16字节
#define MAX_JMP_SIZE 16

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
	MemoryPtr = (PUCHAR)(LocalHookInfo + 1);	// LOCAL_HOOK_INFO
												//                ↑ MemoryPtr

#ifdef X64_DRIVER
	FORCE(EntrySize = LhRoundToNextInstruction(InEntryPoint, X64_DRIVER_JMPSIZE));
#else
	// HookProc 得到第一条尾偏移大于5的指令的尾偏移 == 第一条偏移大于5的指令的偏移-1
	FORCE(LhRoundToNextInstruction(InEntryPoint, 5, &EntrySize));
#endif

	LocalHookInfo->Size = sizeof(LOCAL_HOOK_INFO);
#if !_M_X64
	// 32位对初始化截断警告的关闭 - 为了与64位共用一份代码
	__pragma(warning(push))
	__pragma(warning(disbale:4305))
#endif
	LocalHookInfo->RandomValue = (PVOID)0x69FAB7309CB312EF;
#if !_M_X64
	__pragma(warning(pop))
#endif
	// 结构体赋值 - 未完整
	LocalHookInfo->HookProc = InHookProc;
	LocalHookInfo->TargetProc = InEntryPoint;
	LocalHookInfo->EntrySize = EntrySize;
	LocalHookInfo->CallBack = InCallBack;
	//LocalHookInfo->IsExecutedPtr

	/*
	跳板将会调用下面两个函数在用户定义的hook函数被调用前。
	它们将建立一个正确的环境给 fiber deadlock barrier 和 指定的回调函数
	*/
	// 未实现函数
	//LocalHookInfo->HookIntro = LhBarrierIntro;
	//LocalHookInfo->HookOutro = LhBarrierOutro;

	// 拷贝跳转指令
	LocalHookInfo->Trampoline = MemoryPtr; // MemoryPtr 是越过LocalHookInfo 也就是当前结构体的尾部
	MemoryPtr += GetTrampolineSize();	   // LOCAL_HOOK_INFO | TrampolineASM | 
										   //							      ↑ MemoryPtr

	LocalHookInfo->Size += GetTrampolineSize();

	// 拷贝 Trampoline asm汇编代码
	RtlCopyMemory(LocalHookInfo->Trampoline, GetTrampolinePtr(), GetTrampolineSize());
	/*
		重新申请入口代码长度，因为这些代码必须被直接写入到申请的内存空间中。
		因为我们要劫持EIP/RIP就必须知道我们要去哪

		入口函数代码将会被放在 Trampoline 后面。
	*/
	*RelocSize = 0;
	LocalHookInfo->OldProc = MemoryPtr;

	FORCE(LhRelocateEntryPoint(LocalHookInfo->TargetProc, EntrySize, LocalHookInfo->OldProc, RelocSize));
	// 确保空间还是足够
	MemoryPtr += (*RelocSize + MAX_JMP_SIZE);
	LocalHookInfo->Size += (*RelocSize + MAX_JMP_SIZE);

	// 添加跳转代码到新的入口代码后面
#ifdef X64_DRIVER


#else
	// TargetProc + EntrySize : 目标函数地址+入口指令地址
	// OldProc(新用于放原函数的地址) + *RelocSize(对首指令进行变化后的指令长度) + 5 : 
	RelAddr = (LONG64)((PUCHAR)LocalHookInfo->TargetProc + LocalHookInfo->EntrySize) - ((LONG64)LocalHookInfo->OldProc + *RelocSize + 5);

	// 偏移有没有查过32位
	if (RelAddr != (LONG)RelAddr)
	{
		THROW(STATUS_NOT_SUPPORTED, L"The Given Entry Point Is Out Of Reach.");
	}

	((PUCHAR)LocalHookInfo->OldProc)[*RelocSize] = 0xE9;

	RtlCopyMemory((PUCHAR)LocalHookInfo->OldProc + *RelocSize + 1, &RelAddr, 4);

#endif

	LocalHookInfo->TargetBackup = *((PULONG64)LocalHookInfo->TargetProc);

#ifdef X64_DRIVER
	
#endif

#ifndef _M_X64



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
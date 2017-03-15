#ifndef _DRIVERSHARED_H_
#define _DRIVERSHARED_H_

#include "Rtl/Rtl.h"

#define EASYHOOK_NT_INTERNAL            EXTERN_C NTSTATUS __stdcall
#define EASYHOOK_BOOL_INTERNAL          EXTERN_C BOOL __stdcall

#define EASYHOOK_INJECT_MANAGED			0x00000001

// Local Hook

// ACL - 控制哪些线程可以执行HookProc函数
typedef struct _HOOK_ACL_
{
	ULONG		    Count;
	BOOL			IsExclusive;
	ULONG			Entries[MAX_ACE_COUNT];	// ACE - Access Control Entry
}HOOK_ACL, *PHOOK_ACL;

#define LOCAL_HOOK_SIGNATURE ((ULONG)0x6A910BE2)

typedef struct _LOCAL_HOOK_INFO_
{
	PLOCAL_HOOK_INFO Next;
	ULONG			 Size;

	PVOID			 TargetProc;		// 被Hook函数
	ULONG64			 TargetBackup;	    // 目标备份函数
	ULONGLONG		 TargetBackup_x64;  // X64-Driver使用
	ULONG64			 HookOldSave;		// 保留Hook入口原代码
	ULONG			 EntrySize;			// 入口指令长度 (>5
	PVOID			 Trampoline;
	ULONG			 HLSIndex;			// GlobalSlotList 注册索引
	ULONG			 HLSIdent;			// 实际注册ID
	PVOID			 CallBack;			// 回调函数
	HOOK_ACL		 LocalACL;			// Access Control List
	ULONG			 Signature;			// 注入标志位 - 是否已经被Hook

	TRACED_HOOK_HANDLE      Tracking;   // 指向 包含当前Hook信息的Handle

	PVOID			 RandomValue;	
	PVOID			 HookIntro;			// ACL判断 - Tramp 初始化函数
	PVOID			 OldProc;			// 存储被覆盖的原入口代码
	PVOID			 HookProc;			// 实际Hook函数
	PVOID			 HookOutro;			// 运行环境初始化函数

	INT*			 IsExecutedPtr;		// ? 
}LOCAL_HOOK_INFO, *PLOCAL_HOOK_INFO;

// Local Hook 全局变量
extern RTL_SPIN_LOCK GlobalHookLock;

//EasyHookDll/LocalHook/reloc.c 内部函数 - udis86
EASYHOOK_NT_INTERNAL LhRoundToNextInstruction(PVOID InCodePtr, ULONG InCodeSize, PULONG OutOffset);
EASYHOOK_NT_INTERNAL LhGetInstructionLength(PVOID InPtr, PULONG OutLength);
EASYHOOK_NT_INTERNAL LhRelocateEntryPoint(PVOID InEntryPoint, ULONG InEPSize, PVOID Buffer, PULONG OutRelocSize);
EASYHOOK_NT_INTERNAL LhRelocateRIPRelativeInstruction(ULONGLONG InOffset, ULONGLONG InTargetOffset, PBOOL OutWasRelocated);
EASYHOOK_NT_INTERNAL LhDisassembleInstruction(PVOID InPtr, PULONG Length, PSTR Buffer, LONG BufferSize, PULONG64 NextInstr);


// EasyHookDll/LocalHook/alloc.c 内部函数
PVOID LhAllocateMemoryEx(PVOID InEntryPoint, PULONG OutPageSize);
VOID LhFreeMemory(PLOCAL_HOOK_INFO* HookInfo);

// EasyHookDll/LocalHook/install.c 本地函数
EASYHOOK_NT_INTERNAL   LhAllocateHook(PVOID InEntryPoint, PVOID InHookProc, PVOID InCallBack, PLOCAL_HOOK_INFO* OutLocalHookInfo, PULONG RelocSize);
EASYHOOK_BOOL_INTERNAL LhIsValidHandle(TRACED_HOOK_HANDLE InTracedHandle, PLOCAL_HOOK_INFO* OutHandle);

void LhCriticalInitialize();

// EasyHookDll/LocalHook/Barrier.c 内部函数
ULONG64 LhBarrierIntro(LOCAL_HOOK_INFO* InHandle, PVOID InRetAddr, PVOID* InAddrOfRetAddr);

// EasyHookDll/LocalHook/Uninstall.c 
void LhCriticalFinalize();

// EasyHookDll/RemoteHook/thead.c 非导出函数
EASYHOOK_NT_INTERNAL RtlNtCreateThreadEx(HANDLE ProcessHandle, LPTHREAD_START_ROUTINE ThreadStart, PVOID ThreadParameter, BOOL IsThreadSuspended, HANDLE * ThreadHandle);
EASYHOOK_NT_INTERNAL NtForceLdrInitializeThunk(HANDLE ProcessHandle);
EASYHOOK_NT_INTERNAL RhSetWakeUpThreadID(ULONG32 InThreadID);

#endif
#ifndef _DRIVERSHARED_H_
#define _DRIVERSHARED_H_

#include "Rtl/Rtl.h"

#define EASYHOOK_NT_INTERNAL            EXTERN_C NTSTATUS __stdcall
#define EASYHOOK_BOOL_INTERNAL          EXTERN_C BOOL __stdcall

#define EASYHOOK_INJECT_MANAGED			0x00000001

// Local Hook
typedef struct _LOCAL_HOOK_INFO_
{
	PLOCAL_HOOK_INFO Next;
	ULONG			 Size;

	PVOID			 TargetProc;		// 被Hook函数
	ULONG64			 TargetBackup;	    // 目标备份函数
	PVOID			 Trampoline;
	ULONG			 HLSIndex;
	ULONG			 HLSIdent;

	PVOID			 HookProc;			// 实际Hook函数
	
	ULONG			 EntrySize;
	PVOID			 CallBack;

	PVOID			 RandomValue;
	PVOID			 OldProc;			// 指向原代码

	PVOID			HookIntro;			// 运行环境初始化函数
	PVOID			HookOutro;			// 运行环境初始化函数

	INT*			IsExecutedPtr;		// ?
}LOCAL_HOOK_INFO, *PLOCAL_HOOK_INFO;

typedef struct _HOOK_ACL_
{
	ULONG		    Count;
	BOOL			IsExclusive;
	ULONG			Entries[MAX_ACE_COUNT];
}HOOK_ACL, *PHOOK_ACL;

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
EASYHOOK_NT_INTERNAL LhAllocateHook(PVOID InEntryPoint, PVOID InHookProc, PVOID InCallBack, PLOCAL_HOOK_INFO* OutLocalHookInfo, PULONG RelocSize);

// EasyHookDll/RemoteHook/thead.c 非导出函数
EASYHOOK_NT_INTERNAL RtlNtCreateThreadEx(HANDLE ProcessHandle, LPTHREAD_START_ROUTINE ThreadStart, PVOID ThreadParameter, BOOL IsThreadSuspended, HANDLE * ThreadHandle);
EASYHOOK_NT_INTERNAL NtForceLdrInitializeThunk(HANDLE ProcessHandle);
EASYHOOK_NT_INTERNAL RhSetWakeUpThreadID(ULONG32 InThreadID);

#endif
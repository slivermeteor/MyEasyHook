#include "common.h"

#ifndef DRIVER
#include <aux_ulib.h>
#endif

#pragma comment(lib, "Aux_ulib.lib")

typedef struct _RUNTIME_INFO_
{
	BOOL    IsExecuting;   // 当前线程是否在ACL中?是否可以执行HookProc
	DWORD   HLSIdent;      // 在TLS中的下标
	PVOID   RetAddress;    //     
	PVOID*  AddrOfRetAddr; // Hook返回代码的返回地址 ？
}RUNTIME_INFO, *PRUNTIME_INFO;

typedef struct _THREAD_RUNTIME_INFO_
{
	PRUNTIME_INFO Entries;
	PRUNTIME_INFO Current;			// 当前 RUNTIME_INFO
	PVOID         CallBack;
	BOOL          IsProtected;
}THREAD_RUNTIME_INFO, *PTHREAD_RUNTIME_INFO;

typedef struct _THREAD_LOCAL_STORAGE_
{
	THREAD_RUNTIME_INFO Entries[MAX_THREAD_COUNT];
	DWORD				ThreadIdList[MAX_THREAD_COUNT];			// 线程ID List
	RTL_SPIN_LOCK		ThreadLock;
}THREAD_LOCAL_STORAGE;

typedef struct _BARRIER_UNIT_
{
	HOOK_ACL			 GlobalACL;
	BOOL				 IsInitialized;
	THREAD_LOCAL_STORAGE TLS;
}BARRIER_UNIT, *PBARRIER_UNIT;

static BARRIER_UNIT BarrierUnit;

// EasyHookDll/LocalHook/Barrier.c
BOOL IsLoaderLock();
BOOL TlsGetCurrentValue(THREAD_LOCAL_STORAGE* InTls, PTHREAD_RUNTIME_INFO* OutValue);
BOOL TlsAddCurrentThread(THREAD_LOCAL_STORAGE* InTls);
BOOL AcquireSelfProtection();
void ReleaseSelfProtection();
BOOL ACLContains(PHOOK_ACL InACL, ULONG InCheckID);


#ifndef DRIVER
BOOL IsThreadIntercepted(PHOOK_ACL LocalACL, ULONG InThreadId);
#else
BOOL IsProcessIntercepted(PHOOK_ACL LocalACL, ULONG InProcessID);
#endif

// TrampolineASM 调用 - 判断当前线程是否在ACL中，决定是否执行Hook
ULONG64 LhBarrierIntro(LOCAL_HOOK_INFO* InHandle, PVOID InRetAddr, PVOID* InAddrOfRetAddr)
{
    PTHREAD_RUNTIME_INFO ThreadRuntimeInfo = NULL;
    PRUNTIME_INFO        RuntimeInfo = NULL;
	BOOL				 bIsRegister = FALSE;

#ifdef _M_X64
	InHandle -= 1;
#endif

	// 操作系统 加载锁 - 具体讲解 https://blogs.msdn.microsoft.com/oldnewthing/20040128-00/?p=40853
	// 加载锁是系统特有的东西，在执行特定的函数和Code的时候会进入。比如 DllMain GetModuleFileName 
	if (IsLoaderLock())
	{
		// 如果当前代码在系统 LoaderLock 里时，执行下面代码可能导致不可预测的行为
		return FALSE;
	}

	// 当前线程是否已经TLS里？
	bIsRegister = TlsGetCurrentValue(&BarrierUnit.TLS, &ThreadRuntimeInfo);

	// 未注册 - 进行注册
	if (!bIsRegister)
	{
		if (!TlsAddCurrentThread(&BarrierUnit.TLS))
			return FALSE;
	}

	/*
		为了让不能Hook的API尽可能的少，我们使用自我保护
		这将允许任何人Hook任何API除了哪些需要自我保护的

		自我保护阻止任何后来的Hook中断当前的操作，当我们进入 线程进入死锁阻碍墙
	*/
	if (!AcquireSelfProtection())
	{
		// 如果申请失败 - 汇编代码直接失败 不再调用 LhBarrierOutro
		return FALSE;
	}

	ASSERT(InHandle->HLSIndex < MAX_HOOK_COUNT, L"Barrier.c - InHandle->HLSIndex < MAX_HOOK_COUNT");
	
	// 如果没有注册 - 得到ThreadRuntimeInfo
	if (!bIsRegister)
	{
		TlsGetCurrentValue(&BarrierUnit.TLS, &ThreadRuntimeInfo);

		// 申请 RUNTIME_INFO
		ThreadRuntimeInfo->Entries = (PRUNTIME_INFO)RtlAllocateMemory(TRUE, sizeof(RUNTIME_INFO) * MAX_HOOK_COUNT);

		if (ThreadRuntimeInfo->Entries == NULL)
			goto DONT_INTERCEPT;
	}

	// 得到Hook运行信息
	RuntimeInfo = &ThreadRuntimeInfo->Entries[InHandle->HLSIndex];
	if (RuntimeInfo->HLSIdent != InHandle->HLSIdent)
	{
		// 重置运行信息
		RuntimeInfo->HLSIdent = InHandle->HLSIdent;
		RuntimeInfo->IsExecuting = FALSE;
	}

	// 发现循环钩自己
	if (RuntimeInfo->IsExecuting)
	{
		// 自己钩自己 - 触发线程死锁墙
		// 不再调用 LhBarrierOutro
		goto DONT_INTERCEPT;
	}

	// 记录回调和运行信息
	ThreadRuntimeInfo->CallBack = InHandle->CallBack;
	ThreadRuntimeInfo->Current = RuntimeInfo;

	// 判断当前线程是否运行执行 HookProc
#ifndef DRIVER
	RuntimeInfo->IsExecuting = IsThreadIntercepted(&InHandle->LocalACL, GetCurrentThreadId());
#else
	RuntimeInfo->IsExecuting = IsProcessIntercepted(&InHandle->LocalACL, (ULONG)PsGetCurrentProcessId());
#endif

	if (!RuntimeInfo->IsExecuting)
		goto DONT_INTERCEPT;

	// 保存特殊的信息
	RuntimeInfo->RetAddress = InRetAddr;
	RuntimeInfo->AddrOfRetAddr = InAddrOfRetAddr;

	ReleaseSelfProtection();

	return TRUE;

DONT_INTERCEPT:
	{
		if (ThreadRuntimeInfo != NULL)
		{
			ThreadRuntimeInfo->CallBack = NULL;
			ThreadRuntimeInfo->Current = NULL;

			ReleaseSelfProtection();
		}
		return FALSE;
	}

}

// 判断初始化函数是否可以安全运行
BOOL IsLoaderLock()
{
	// 只有函数返回 FALSE时，才可安全执行
#ifndef DRIVER
	BOOL IsLoaderLock = FALSE;
	// AuxUlibIsDLLSynchronizationHeld - 判断当前线程是否在等待一个同步事件 - 同时要求还未开始初始化
	return (!AuxUlibIsDLLSynchronizationHeld(&IsLoaderLock) || IsLoaderLock || !BarrierUnit.IsInitialized);
#else
	return FALSE;
#endif
}

// 从全局 Tls列表中 查询当前线程的 THREAD_RUNTIME_INFO
// 要求当前线程必须已经在 Tls 中注册过，并且调用了 TlsAddCurrentThread() 去添加存储
BOOL TlsGetCurrentValue(THREAD_LOCAL_STORAGE* InTls, PTHREAD_RUNTIME_INFO* OutValue)
{
#ifndef DRIVER
	ULONG		CurrentId = (ULONG)GetCurrentThreadId();
#else
	ULONG		CurrentId = (ULONG)PsGetCurrentThread();
#endif
	LONG Index = 0;
	for (Index = 0; Index < MAX_THREAD_COUNT; Index++)
	{
		if (InTls->ThreadIdList[Index] == CurrentId)
		{
			*OutValue = &InTls->Entries[Index];

			return TRUE;
		}
	}

	return FALSE;
}

BOOL TlsAddCurrentThread(THREAD_LOCAL_STORAGE* InTls)
{
#ifndef DRIVER
	ULONG		CurrentId = (ULONG)GetCurrentThreadId();
#else
	ULONG		CurrentId = (ULONG)PsGetCurrentThreadId();
#endif
	LONG		Index = -1;

	RtlAcquireLock(&InTls->ThreadLock);	// 进入临界区

	for (LONG i = 0; i < MAX_THREAD_COUNT; i++)
	{
		// 如果是 ThreadIdList 中第一个没有放值的节点
		if ((InTls->ThreadIdList[i] == 0) && Index == -1)
			Index = i;

		// 如果线程ID已经注册 触发断言
		ASSERT(InTls->ThreadIdList[i] != CurrentId, L"Barrier.c - InTls->ThreadIdList[i] != CurrentId");
	}

	if (Index == -1)
	{
		// 放满了 - 失败
		RtlReleaseLock(&InTls->ThreadLock);

		return FALSE;
	}

	// 注册线程ID
	InTls->ThreadIdList[Index] = CurrentId;
	RtlZeroMemory(&InTls->Entries[Index], sizeof(THREAD_RUNTIME_INFO));	// 初始化线程运行信息
	RtlReleaseLock(&InTls->ThreadLock);	// 离开临界区

	return TRUE;
}

BOOL AcquireSelfProtection()
{
	PTHREAD_RUNTIME_INFO	Runtime = NULL;

	if (!TlsGetCurrentValue(&BarrierUnit.TLS, &Runtime) || Runtime->IsProtected)
		return FALSE;

	Runtime->IsProtected = TRUE;

	return TRUE;
}

void ReleaseSelfProtection()
{
	PTHREAD_RUNTIME_INFO ThreadRuntimeInfo = NULL;

	ASSERT(TlsGetCurrentValue(&BarrierUnit.TLS, &ThreadRuntimeInfo) && ThreadRuntimeInfo->IsProtected, L"Barrier.c - &BarrierUnit.TLS, &ThreadRuntimeInfo) && ThreadRuntimeInfo->IsProtected");

	ThreadRuntimeInfo->IsProtected = FALSE;
}

// 判断目标线程/进程 是否可以通过ACL
// 如果给定的线程被全局和本地ACL拦截，则为TRUE，否则为FALSE。
#ifndef DRIVER
BOOL IsThreadIntercepted(PHOOK_ACL LocalACL, ULONG InThreadId)
#else
BOOL IsProcessIntercepted(PHOOK_ACL LocalACL, ULONG InProcessID)
#endif
{
	ULONG CheckID = 0;

#ifndef DRIVER
	if (InThreadId == 0)
		CheckID = GetCurrentThreadId();
	else
		CheckID = InThreadId;
#else
	if (InProcessID == 0)
		CheckID = (ULONG)PsGetCurrentProcessId();
	else
		CheckID = InProcessID;
#endif

	// 全局ACL中是否有目标ID？
	if (ACLContains(&BarrierUnit.GlobalACL, CheckID))
	{
		if (ACLContains(LocalACL, CheckID))
		{
			if (LocalACL->IsExclusive)	
				return FALSE;	// 在当前ACL中有目标ID，并且互斥 - 说明拒绝运行?
		}		
		else
		{
			if (!LocalACL->IsExclusive)	// 不在ACL中,不互斥 - 说明允许
				return FALSE;
		}
			
		return !BarrierUnit.GlobalACL.IsExclusive;	// 已经在全局ACL中 取反 返回
	}
	else
	{
		if (ACLContains(LocalACL, CheckID))
		{
			if (LocalACL->IsExclusive)
				return FALSE;
		}			
		else
		{
			if (!LocalACL->IsExclusive)
				return FALSE;
		}
			
		return BarrierUnit.GlobalACL.IsExclusive;
	}
}

/// \如果传入的ACL里有CheckId，返回真，反之假
BOOL ACLContains(PHOOK_ACL InACL, ULONG InCheckID)
{
	ULONG Index = 0;

	for (Index = 0; Index < InACL->Count; Index++)
	{
		if (InACL->Entries[Index] == InCheckID)
			return TRUE;
	}

	return FALSE;
}

// 在Dll加载的时候调用 - 初始化所有界限结构体
NTSTATUS LhBarrierProcessAttach()
{
	RtlZeroMemory(&BarrierUnit, sizeof(BARRIER_UNIT));

	BarrierUnit.GlobalACL.IsExclusive = TRUE;	// 禁止中断

	RtlInitializeLock(&BarrierUnit.TLS.ThreadLock);

#ifndef DRIVER
	// AuxUlibInitialize - 初始化 Aux_ulib 库 - 这个函数必须在 Aux_ulib 任何函数前调用
	BarrierUnit.IsInitialized = AuxUlibInitialize() ? TRUE : FALSE;
	return STATUS_SUCCESS;
#else
	
#endif
}

void LhBarrierProcessDetach()
{
#ifdef DRIVER

#endif
	RtlDeleteLock(&BarrierUnit.TLS.ThreadLock);
	for (LONG Index = 0; Index < MAX_THREAD_COUNT; Index++)
	{
		if (BarrierUnit.TLS.Entries[Index].Entries != NULL)
			RtlFreeMemory(BarrierUnit.TLS.Entries[Index].Entries);
	}

	RtlZeroMemory(&BarrierUnit, sizeof(BARRIER_UNIT));
}

PVOID _stdcall LhBarrierOutro(PLOCAL_HOOK_INFO InHandle, PVOID* InAddrOfRetAddr)
{
	// Outro 在实际Hook函数执行完成后 执行
	PRUNTIME_INFO Runtime = NULL;
	PTHREAD_RUNTIME_INFO ThreadRuntimeInfo = NULL;

#ifdef _M_X64
	InHandle -= 1;
#endif

	ASSERT(AcquireSelfProtection(), L"Barrier.c - AcquireSelfProtection()");
	ASSERT(TlsGetCurrentValue(&BarrierUnit.TLS, &ThreadRuntimeInfo) && (ThreadRuntimeInfo != NULL), 
		   L"Barrier.c - TlsGetCurrentValue(&BarrierUnit.TLS, &ThreadRuntimeInfo) && (ThreadRuntimeInfo != NULL)");

	Runtime = &ThreadRuntimeInfo->Entries[InHandle->HLSIndex];

	// 清空上下文
	ThreadRuntimeInfo->Current = NULL;
	ThreadRuntimeInfo->CallBack = NULL;

	ASSERT(Runtime != NULL, L"Barrier.c - Runtime != NULL");

	ASSERT(Runtime->IsExecuting, L"Barrier.c - Runtime->IsExecuting");

	Runtime->IsExecuting = FALSE;

	ASSERT(*InAddrOfRetAddr == NULL, L"Barrier.c - *InAddrOfRetAddr == NULL");

	*InAddrOfRetAddr = Runtime->RetAddress;

	ReleaseSelfProtection();

	return InHandle;
}
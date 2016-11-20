#include "common.h"

typedef struct _STEALTH_CONTEXT_
{
	// Proc and handle
	union 
	{
		struct
		{
			WRAP_ULONG64(PVOID CreateThread);
			WRAP_ULONG64(PVOID RemoteThreadStart);
			WRAP_ULONG64(PVOID RemoteThreadParameter);
			WRAP_ULONG64(PVOID WaitForSingleObject);
			WRAP_ULONG64(HANDLE	CompletionEventHandle);
			WRAP_ULONG64(PVOID CloseHandle);
			union
			{
				WRAP_ULONG64(HANDLE RemoteThreadHandle);
				WRAP_ULONG64(HANDLE SynchronEventHandle);
			};
			WRAP_ULONG64(PVOID SetEvent);

		};

		ULONG64  Unused[8];
	};

	// register
	ULONG64		Rax;
	ULONG64		Rbx;
	ULONG64		Rcx;
	ULONG64		Rdx;
	ULONG64		Rsi;
	ULONG64		Rdi;
	ULONG64		Rbp;
	ULONG64		Rsp;
	ULONG64		Rip;
	ULONG64		RFlags;
	ULONG64		R8;
	ULONG64		R9;
	ULONG64		R10;
	ULONG64		R11;
	ULONG64		R12;
	ULONG64		R13;
	ULONG64		R14;
	ULONG64		R15;
}STEALTH_CONTEXT, *PSTEALTH_CONTEXT;



EASYHOOK_NT_API RhCreateStealthRemoteThread(ULONG32 InTargetProcessID, LPTHREAD_START_ROUTINE InRemoteRoutine,
	PVOID InRemoteParameter, PHANDLE OutRemoteThreadHandle)
{
	NTSTATUS NtStatus = STATUS_SUCCESS;
	HANDLE	 TargetProcessHandle = NULL;
	BOOL     bIsTarget64Bit = FALSE;
	HANDLE   ThreadSnapshotHandle = NULL;
	HANDLE	 HijackThreadHandle = NULL;
	ULONG32	 HijackThreadID = 0;
	ULONG32  SuspendCount = 0;
	CONTEXT	 Context = { 0 };

	THREADENTRY32 ThreadEntry = { 0 };
	STEALTH_CONTEXT LocalContext = { 0 };

	RtlZeroMemory(&LocalContext, sizeof(STEALTH_CONTEXT));

	TargetProcessHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE, FALSE, InTargetProcessID);
	if (TargetProcessHandle == NULL)
	{
		if (GetLastError() == ERROR_ACCESS_DENIED)
		{
			THROW(STATUS_ACCESS_DENIED, L"Unable to open target process. Consider using a system service.");
		}
		else
		{
			THROW(STATUS_NOT_FOUND, L"The given target process does not exist!");
		}
	}

#ifdef _M_X64
	FORCE(RhIsX64Process(InTargetProcessID, &bIsTarget64Bit));

	if (!bIsTarget64Bit)
	{
		THROW(STATUS_WOW_ASSERTION, L"It is not supported to directly operate through the WOW64 barrier.");
	}
#else
	FORCE(RhIsX64Process(InTargetProcessID, &bIsTarget64Bit));

	if (bIsTarget64Bit)
		THROW(STATUS_WOW_ASSERTION, L"It is not supported to directly operate through the WOW64 barrier.");
#endif

	ThreadEntry.dwSize = sizeof(THREADENTRY32);

	ThreadSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (ThreadSnapshotHandle == NULL)
	{
		THROW(STATUS_INTERNAL_ERROR, L"Unable to enumerate system threads.");
	}

	if (!Thread32First(ThreadSnapshotHandle, &ThreadEntry))
	{
		THROW(STATUS_INTERNAL_ERROR, L"Unable to get first thread in enumeration.");
	}

	do 
	{
		if (ThreadEntry.th32OwnerProcessID == InTargetProcessID && ThreadEntry.th32ThreadID != GetCurrentThreadId())
		{
			HijackThreadHandle = OpenThread(THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
											FALSE, ThreadEntry.th32ThreadID);
			if (HijackThreadHandle == NULL)
			{
				continue;
			}

			SuspendCount = SuspendThread(HijackThreadHandle);
			if (SuspendCount != 0)	// 如果返回不等于 - 线程曾经被挂起过 / 函数失败
			{
				if (SuspendCount != -1)	// 不是失败的情况,这个线程曾经被挂起过。我们不选用，恢复它，另寻线程
				{
					ResumeThread(HijackThreadHandle);
				}

				HijackThreadHandle = NULL;
				continue;
			}

			HijackThreadID = ThreadEntry.th32ThreadID;

			break;
		}
	} while (Thread32Next(ThreadSnapshotHandle, &ThreadEntry));

	if (HijackThreadHandle == NULL || HijackThreadID == 0)
	{
		THROW(STATUS_NOT_SUPPORTED, L"Unable to select active thread in target process.");
	}

	// CONTEXT_CONTROL 表示想得到 SegSs, Rsp, SegCs, Rip, and EFlags.
	// CONTEXT_INTEGER 表示想得到 Rax, Rcx, Rdx, Rbx, Rbp, Rsi, Rdi, and R8-R15.
	Context.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;	//  设置不同的值 获得不同的寄存器

	if (!GetThreadContext(HijackThreadHandle, &Context))
	{
		THROW(STATUS_INTERNAL_ERROR, L"Unable to capture remote thread context.");
	}

	// 保存context参数
#ifdef _M_X64
	LocalContext.Rax = Context.Rax;
	LocalContext.Rbx = Context.Rbx;
	LocalContext.Rcx = Context.Rcx;
	LocalContext.Rdx = Context.Rdx;
	LocalContext.Rbp = Context.Rbp;
	LocalContext.Rsp = Context.Rsp;
	LocalContext.Rsi = Context.Rsi;
	LocalContext.Rdi = Context.Rdi;
	LocalContext.Rip = Context.Rip;
	LocalContext.RFlags = Context.EFlags;
	LocalContext.R8 = Context.R8;
	LocalContext.R9 = Context.R9;
	LocalContext.R10 = Context.R10;
	LocalContext.R11 = Context.R11;
	LocalContext.R12 = Context.R12;
	LocalContext.R13 = Context.R13;
	LocalContext.R14 = Context.R14;
	LocalContext.R15 = Context.R15;
#else
	// 32位仍旧用64位来存储 - 只是用不全而已 
	LocalContext.Rax = Context.Eax;
	LocalContext.Rbx = Context.Ebx;
	LocalContext.Rcx = Context.Ecx;
	LocalContext.Rdx = Context.Edx;
	LocalContext.Rbp = Context.Ebp;
	LocalContext.Rsp = Context.Esp;
	LocalContext.Rsi = Context.Esi;
	LocalContext.Rdi = Context.Edi;
	LocalContext.Rip = Context.Eip;
	LocalContext.RFlags = Context.EFlags;
#endif
	LocalContext.CreateThread = (PVOID)GetProcAddress()

THROW_OUTRO:
FINALLY_OUTRO:

	return NtStatus;
}
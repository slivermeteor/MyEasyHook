#include "common.h"

#define PAGE_SIZE	0x1000

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
	ULONG64		Rax;   // 0
	ULONG64		Rcx;
	ULONG64		Rdx;
	ULONG64		Rbp;
	ULONG64		Rsp;	
	ULONG64		Rsi;
	ULONG64		Rdi;
	ULONG64		Rbx;
	ULONG64		Rip;
	ULONG64		RFlags; // 9
	ULONG64		R8;
	ULONG64		R9;
	ULONG64		R10;
	ULONG64		R11;
	ULONG64		R12;
	ULONG64		R13;
	ULONG64		R14;
	ULONG64		R15;	// 17 
}STEALTH_CONTEXT, *PSTEALTH_CONTEXT;

ULONG32 GetStealthStubSize();
PBYTE GetStealthStubPtr();

EASYHOOK_NT_API RhCreateStealthRemoteThread(ULONG32 InTargetProcessID, LPTHREAD_START_ROUTINE InRemoteRoutine,
	PVOID InRemoteParameter, PHANDLE OutRemoteThreadHandle)
{
	NTSTATUS NtStatus = STATUS_SUCCESS;
	HANDLE	 TargetProcessHandle = NULL;
	BOOL     bIsTarget64Bit = FALSE;
	BOOL	 bIsSuspend = FALSE;
	HANDLE   ThreadSnapshotHandle = NULL;
	HANDLE	 HijackThreadHandle = NULL;
	ULONG32	 HijackThreadID = 0;
	ULONG32  SuspendCount = 0;
	CONTEXT	 Context = { 0 };

	THREADENTRY32 ThreadEntry = { 0 };
	STEALTH_CONTEXT LocalContext = { 0 };
	PSTEALTH_CONTEXT RemoteContext = NULL;
	ULONG32			ContextSize = GetStealthStubSize() + sizeof(STEALTH_CONTEXT);

	HANDLE CompletionEventHandle = NULL;
	HANDLE SynchronizationEventHandle = NULL;
	SIZE_T	BytesWritten = 0;

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
	{
		THROW(STATUS_WOW_ASSERTION, L"It is not supported to directly operate through the WOW64 barrier.");
	}		
#endif

	ThreadEntry.dwSize = sizeof(THREADENTRY32);

	ThreadSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (ThreadSnapshotHandle == INVALID_HANDLE_VALUE)
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
			if (SuspendCount != 0)	// 如果返回不等于0 - 线程曾经被挂起过 / 函数失败
			{
				if (SuspendCount != -1)	// 不是失败的情况,这个线程曾经被挂起过。我们不选用，恢复它，另寻线程
				{
					ResumeThread(HijackThreadHandle);
				}

				CloseHandle(HijackThreadHandle);		// 不应该关闭线程句柄吗？
				HijackThreadHandle = NULL;
				continue;
			}

			HijackThreadID = ThreadEntry.th32ThreadID;
			bIsSuspend = TRUE;
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
	
	/*
	printf("Rax:%llx\r\n", LocalContext.Rax);
	printf("Rbx:%llx\r\n", LocalContext.Rbx);
	printf("Rcx:%llx\r\n", LocalContext.Rcx);
	printf("Rdx:%llx\r\n", LocalContext.Rdx);
	printf("Rbp:%llx\r\n", LocalContext.Rbp);
	printf("Rsp:%llx\r\n", LocalContext.Rsp);
	printf("Rsi:%llx\r\n", LocalContext.Rsi);
	printf("Rdi:%llx\r\n", LocalContext.Rdi);
	printf("Rip:%llx\r\n", LocalContext.Rip);
	printf("RFlags:%llx\r\n", LocalContext.RFlags);
	printf("R8-15:%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx\r\n", Context.R8, Context.R9, Context.R10, Context.R11, Context.R12, Context.R13, Context.R14, Context.R15);
	*/

	// 做劫持的准备工作
	LocalContext.CreateThread = (PVOID)GetProcAddress(Kernel32Handle, "CreateThread");
	LocalContext.SetEvent = (PVOID)GetProcAddress(Kernel32Handle, "SetEvent");
	LocalContext.CloseHandle = (PVOID)GetProcAddress(Kernel32Handle, "CloseHandle");
	LocalContext.WaitForSingleObject = (PVOID)GetProcAddress(Kernel32Handle, "WaitForSingleObject");

	LocalContext.RemoteThreadStart = (PVOID)InRemoteRoutine;
	LocalContext.RemoteThreadParameter = InRemoteParameter;

	CompletionEventHandle = CreateEvent(NULL, TRUE, FALSE, NULL);
	SynchronizationEventHandle = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (CompletionEventHandle == NULL || SynchronizationEventHandle == NULL)
	{
		THROW(STATUS_INTERNAL_ERROR, L"Unable to create event.");
	}
	
	if (!DuplicateHandle(GetCurrentProcess(), CompletionEventHandle, TargetProcessHandle, &LocalContext.CompletionEventHandle, 0, FALSE, DUPLICATE_SAME_ACCESS) ||
		!DuplicateHandle(GetCurrentProcess(), SynchronizationEventHandle, TargetProcessHandle, &LocalContext.SynchronEventHandle, 0, FALSE, DUPLICATE_SAME_ACCESS))
	{
		THROW(STATUS_INTERNAL_ERROR, L"Unable to duplicate event.");
	}

#if !_M_X64 //???
	__pragma(warning(push))
	__pragma(warning(disable:4305))
#endif
	if (VirtualAllocEx(TargetProcessHandle, (PVOID)(LocalContext.Rsp - PAGE_SIZE * 20), PAGE_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE) == NULL)
	{
		THROW(STATUS_NO_MEMORY, L"Unable to allocate executable thread stack.");
	}
	RemoteContext = (PSTEALTH_CONTEXT)(LocalContext.Rsp - PAGE_SIZE * 19 - ContextSize);
	//															  |RemoteContext
	//HighAddress                -19 * PAGE_SIZE|  -ContextSize-  | Actualy Use |- 20 * PAGE_SIZE
	//											|			--PAGE_SIZE--		|
#if !_M_X64
	__pragma(warning(pop))
#endif

#ifdef _M_X64
	Context.Rip = (ULONG64)RemoteContext;								// Rip 保存StealthStub_ASM_x__ 函数起始地址
	Context.Rbx = (ULONG64)RemoteContext + GetStealthStubSize();		// 越过函数 就是参数 - Rbx保存参数位置
#else
	Context.Eip = (ULONG32)RemoteContext;
	Context.Ebx = (ULONG32)RemoteContext + GetStealthStubSize();
#endif

	// 写入 LocalContext - StealthStub_ASM 函数的参数
	if (!WriteProcessMemory(TargetProcessHandle, (PUCHAR)RemoteContext + GetStealthStubSize(), &LocalContext, sizeof(STEALTH_CONTEXT), &BytesWritten))
	{
		THROW(STATUS_INTERNAL_ERROR, L"Unable To Write StalthStub Parameter.");
	}

	// 写入 StealthStub_ASM Code
	if (!WriteProcessMemory(TargetProcessHandle, (PUCHAR)RemoteContext, GetStealthStubPtr(), GetStealthStubSize(), &BytesWritten))
	{
		THROW(STATUS_INTERNAL_ERROR, L"Unable To Write StealthStub Proc.");
	}

	// 设置Context
	if (!SetThreadContext(HijackThreadHandle, &Context))
	{
		THROW(STATUS_INTERNAL_ERROR, L"Unable To Set Remote Thread Context.");
	}

	// 恢复劫持线程 - 线程按照设置的 E/Rip 执行 StealthStub_ASM
	if (ResumeThread(HijackThreadHandle) == (DWORD)-1)
	{
		THROW(STATUS_INTERNAL_ERROR, L"Unable To Resume The Remote Thread.");
	}
	bIsSuspend = FALSE;

	// 等待StealthStub_ASM 成功创建线程
	if (WaitForSingleObject(SynchronizationEventHandle, INFINITE) != WAIT_OBJECT_0)
	{
		THROW(STATUS_INTERNAL_ERROR, L"Unable To Wait For Remote Thread Creation.");
	}

	// 劫持线程帮助创建远程线程成功 
	// 重新读取一次Context -  在成功创建后，读取出远程线程句柄
	if (!ReadProcessMemory(TargetProcessHandle, (PUCHAR)RemoteContext + GetStealthStubSize(), &LocalContext, sizeof(STEALTH_CONTEXT), &BytesWritten))
	{
		THROW(STATUS_INTERNAL_ERROR, L"Unable to re-read remote context.");
	}

	// 创建失败 - 异常退出
	if (LocalContext.RemoteThreadHandle == NULL)
	{
		THROW(STATUS_INTERNAL_ERROR, L"Unable To Create Remote Thread.");
	}

	if (IsValidPointer(OutRemoteThreadHandle, sizeof(HANDLE)))
	{
		// Dup远程线程句柄
		if (!DuplicateHandle(TargetProcessHandle, LocalContext.RemoteThreadHandle, GetCurrentProcess(), OutRemoteThreadHandle, 0, FALSE, DUPLICATE_SAME_ACCESS))
		{
			THROW(STATUS_INTERNAL_ERROR, L"Unable To Duplicate Remote Thread Handle.");
		}
	}

	if (!SetEvent(CompletionEventHandle))	// 告诉被劫持线程 - Dup完成 
	{
		THROW(STATUS_INTERNAL_ERROR, L"Unable To Resume Hijacker Thread.");
	}

	RETURN;
THROW_OUTRO:
FINALLY_OUTRO:
	{
		if (CompletionEventHandle != NULL)
		{
			SetEvent(CompletionEventHandle);	// 保证劫持远程线程可以正常退出
			CloseHandle(CompletionEventHandle);
			CompletionEventHandle = NULL;
		}

		if (SynchronizationEventHandle != NULL)
		{
			CloseHandle(SynchronizationEventHandle);
			SynchronizationEventHandle = NULL;
		}

		if (HijackThreadHandle != NULL)
		{
			if (bIsSuspend)
			{
				ResumeThread(HijackThreadHandle);
				bIsSuspend = FALSE;
			}
			CloseHandle(HijackThreadHandle);
			HijackThreadHandle = NULL;
		}

		if (TargetProcessHandle != NULL)
		{
			CloseHandle(TargetProcessHandle);
			TargetProcessHandle = NULL;
		}

		if (ThreadSnapshotHandle != NULL)
		{
			CloseHandle(ThreadSnapshotHandle);
			ThreadSnapshotHandle = NULL;
		}
		return NtStatus;
	}
}


//	GetStealStubSize - ASM
static DWORD StealthStubSize = 0;

#ifdef _M_X64
	EXTERN_C VOID StealthStub_ASM_x64();
#else
	EXTERN_C VOID __stdcall StealthStub_ASM_x86();
#endif

ULONG32 GetStealthStubSize()
{
	PUCHAR		Ptr = NULL;
	PUCHAR		BasePtr = NULL;
	ULONG32		Index = 0;
	ULONG32		Signature = 0;

	if (StealthStubSize != 0)
	{
		return StealthStubSize;
	}

	BasePtr = Ptr = GetStealthStubPtr();

	for (Index = 0; Index < 2000; Index++)
	{
		Signature = *((PULONG)Ptr);

		if (Signature == 0x12345678)
		{
			StealthStubSize = (ULONG)(Ptr - BasePtr);

			return StealthStubSize;
		}

		Ptr++;
	}
	ASSERT(FALSE, L"Stealth.c - ULONG GetStealthStubSize()");

	return 0;
}

PBYTE GetStealthStubPtr()
{
	PBYTE Ptr = (PBYTE)
#ifdef _M_X64
		StealthStub_ASM_x64;
#else
		StealthStub_ASM_x86;
#endif

	if (*Ptr == 0xE9)
	{
		Ptr += *((INT*)(Ptr + 1)) + 5;
	}

	return Ptr;
}
#include "common.h"

typedef BOOL(__stdcall *pfnIsWow64Process)(HANDLE ProcessHandle, BOOL* Isx64);
typedef VOID(*pfnGetNativeSystemInfo)(LPSYSTEM_INFO SystemInfo);
typedef LONG(WINAPI* pfnNtCreateThreadEx)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, LPVOID ObjectAttributes,
										  HANDLE ProcessHandle, LPTHREAD_START_ROUTINE ThreadStart, LPVOID ThreadParameter,
										  BOOL CreateSuspended, DWORD StackSize, LPVOID Unknown1, LPVOID Unknown2, LPVOID Unknown3);

PVOID		GetRemoteProcAddress(ULONG32 ProcessID, HANDLE ProcessHandle, CHAR* strModuleName, CHAR* strFunctioName);
HMODULE		GetRemoteModuleHandle(ULONG32 ProcessID, CHAR* strModuleName);
ULONG		GetShellCodeSize();
BYTE*		GetInjectionPtr();


EASYHOOK_NT_API RhInjectLibrary(INT32 TargetProcessID, INT32 WakeUpThreadID, INT32 InjectionOptions,
						         WCHAR* LibraryPath_x86, WCHAR* LibraryPath_x64, PVOID InPassThruBuffer, INT32 InPassThruSize)
{
	NTSTATUS NtStatus = STATUS_SUCCESS;
	HANDLE   TargetProcessHandle = NULL;
	BOOL	 bIs64BitTarget = FALSE;

	PREMOTE_INFOR RemoteInfo = NULL;
	PREMOTE_INFOR CorrectRemoteInfo = NULL;
	ULONG32  RemoteInfoLength = 0;
	ULONG_PTR CorrectValue = 0;

	HANDLE	 RemoteThreadHandle = NULL;
	HANDLE   RemoteSignalEvent = NULL;
	HANDLE   HandleArrary[2] = { 0 };
	WCHAR    UserInjectLibrary[MAX_PATH + 1] = { 0 };
	ULONG32  UserInjectLibraryLength = 0;
	WCHAR    EasyHookWorkPath[MAX_PATH + 1] = { 0 };	// 调用Dll的注入主程序完整路径
	ULONG32  EasyHookWorkPathLength = 0;
	WCHAR    EasyHookDllPath[MAX_PATH + 1] = { 0 };	    // 当前Dll的完整路径
	ULONG32  EasyHookDllPathLength = 0;
	CHAR     EasyHookEntryProcName[MAX_PATH + 1] =
#ifndef _WIN64
		"_HookCompleteInjection@4";
#else
		"HookCompleteInjection";
#endif
	ULONG32  EasyHookEntryProcNameLength = 0;

	ULONG32 ShellCodeLength = 0;
	PUCHAR  RemoteShellCodeBase = NULL;

	ULONG32 Index = 0;
	ULONG32 ErrorCode = 0;
	SIZE_T  ReturnLength = 0;

	// 检查参数合法性
	if (InPassThruSize > MAX_PASSTHRU_SIZE)
	{
		THROW(STATUS_INVALID_PARAMETER_7, L"The given pass thru buffer is too large.");
	}
	if (InPassThruBuffer != NULL)
	{
		if (!IsValidPointer(InPassThruBuffer, InPassThruSize))
		{
			THROW(STATUS_INVALID_PARAMETER_6, L"The given pass thru buffer is invalid.");
		}
	}
	else if (InPassThruSize != 0)
	{
		THROW(STATUS_INVALID_PARAMETER_7, L"If no pass thru buffer is specified, the pass thru length also has to be zero.");
	}

	if (TargetProcessID == GetCurrentProcessId())	// 不支持钩自己
	{
		THROW(STATUS_NOT_SUPPORTED, L"For stability reasons it is not supported to inject into the calling process.");
	}

	if ((TargetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, TargetProcessID)) == NULL)
	{
		if (GetLastError() == ERROR_ACCESS_DENIED)
			THROW(STATUS_ACCESS_DENIED, L"Unable to open target process. Consider using a system service.")
		else
			THROW(STATUS_NOT_FOUND, L"The given target process does not exist!");
	}

	// 检查目标位数 只支持32对32 64对64
#ifdef _M_X64
	FORCE(RhIsX64Process(TargetProcessID, &bIs64BitTarget));

	if (!bIs64BitTarget)
	{
		THROW(STATUS_WOW_ASSERTION, L"It is not supported to directly hook through the WOW64 barrier.");
	}

	if (!GetFullPathNameW(LibraryPath_x64, MAX_PATH, UserInjectLibrary, NULL))
	{
		THROW(STATUS_INVALID_PARAMETER_5, L"Unable to get full path to the given 64-bit library.");
	}
#else
	FORCE(RhIsX64Process(TargetProcessID, &bIs64BitTarget));

	if (bIs64BitTarget)
	{
		THROW(STATUS_WOW_ASSERTION, L"It is not supported to directly hook through the WOW64 barrier.");
	}

	if (!GetFullPathNameW(LibraryPath_x86, MAX_PATH, UserInjectLibrary, NULL))
	{
		THROW(STATUS_INVALID_PARAMETER_4, L"Unable to get full path to the given 32-bit library.");
	}
#endif
	// 检查要注入的Library 的确存在
	if (!RtlFileExists(UserInjectLibrary))
	{
#ifdef _M_X64
		THROW(STATUS_INVALID_PARAMETER_5, L"The given 64-Bit library does not exist!");
#else
		THROW(STATUS_INVALID_PARAMETER_4, L"The given 32-Bit library does not exist!");
#endif
	}

	// 得到当前工作目录 注入主程序的路径 - 为注入入口 设置环境变量 构造字符串做准备
	RtlGetWorkingDirectory(EasyHookWorkPath, MAX_PATH - 1);
	// 得到当前模块的路径 DllPath
	RtlGetCurrentModulePath(EasyHookDllPath, MAX_PATH);
	
	// 计算字符串各个的长度
	EasyHookDllPathLength = (RtlUnicodeLength(EasyHookDllPath) + 1) * 2;
	EasyHookEntryProcNameLength = RtlAnsiLength(EasyHookEntryProcName) + 1;
	EasyHookWorkPathLength = (RtlUnicodeLength(EasyHookWorkPath) + 2) * 2;
	UserInjectLibraryLength = (RtlUnicodeLength(UserInjectLibrary) + 2) * 2;

	EasyHookWorkPath[EasyHookWorkPathLength / 2 - 2] = ';';
	EasyHookWorkPath[EasyHookWorkPathLength / 2 - 1] = 0;

	// 注入的数据总长:结构体长度 + 所有字符串的长度
	RemoteInfoLength = EasyHookDllPathLength + EasyHookEntryProcNameLength + EasyHookWorkPathLength + InPassThruSize + UserInjectLibraryLength;
	RemoteInfoLength += sizeof(REMOTE_INFOR);

	RemoteInfo = (PREMOTE_INFOR)RtlAllocateMemory(TRUE, RemoteInfoLength);
	if (RemoteInfo == NULL)
	{
		THROW(STATUS_NO_MEMORY, L"Unable to allocate memory in current process.");
	}

	// 远程让对方启动一个线程 以防止对方在创建的时候被挂起导致 Kernel32没有被加载的情况 
	// 学习一个进程启动的时候 都进行了哪些动作
	FORCE(NtForceLdrInitializeThunk(TargetProcessHandle));

	// 在对方进程空间里 得到函数地址
	RemoteInfo->LoadLibraryW   = (PVOID)GetRemoteProcAddress(TargetProcessID, TargetProcessHandle, "kernel32.dll", "LoadLibraryW");
	RemoteInfo->FreeLibrary    = (PVOID)GetRemoteProcAddress(TargetProcessID, TargetProcessHandle, "kernel32.dll", "FreeLibrary");
	RemoteInfo->GetProcAddress = (PVOID)GetRemoteProcAddress(TargetProcessID, TargetProcessHandle, "kernel32.dll", "GetProcAddress");
	RemoteInfo->VirtualFree    = (PVOID)GetRemoteProcAddress(TargetProcessID, TargetProcessHandle, "kernel32.dll", "VirtualFree");
	RemoteInfo->VirtualProtect = (PVOID)GetRemoteProcAddress(TargetProcessID, TargetProcessHandle, "kernel32.dll", "VirtualProtect");
	RemoteInfo->ExitThread     = (PVOID)GetRemoteProcAddress(TargetProcessID, TargetProcessHandle, "kernel32.dll", "ExitThread");
	RemoteInfo->GetLastError   = (PVOID)GetRemoteProcAddress(TargetProcessID, TargetProcessHandle, "kernel32.dll", "GetLastError");

	RemoteInfo->WakeUpThreadID = WakeUpThreadID;
	RemoteInfo->IsManaged = InjectionOptions & EASYHOOK_INJECT_MANAGED;		// 注入选项

	ShellCodeLength = GetShellCodeSize();
	 
	RemoteShellCodeBase = (PUCHAR)VirtualAllocEx(TargetProcessHandle, NULL, ShellCodeLength + RemoteInfoLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (RemoteShellCodeBase == NULL)
	{
		THROW(STATUS_NO_MEMORY, L"Unable to allocate memory in target process.");
	}

	// 修正当前自己进程空间里的RemoteInfo里的字符串指针
	PBYTE Offset = (PBYTE)(RemoteInfo + 1);	// 越过结构体本身 准备写入字符串

	RemoteInfo->EasyHookEntryProcName = (CHAR*)Offset;
	RemoteInfo->EasyHookDllPath = (WCHAR*)(Offset += EasyHookEntryProcNameLength);
	RemoteInfo->EasyHookWorkPath = (WCHAR*)(Offset += EasyHookDllPathLength);
	RemoteInfo->UserData = (PBYTE)(Offset += EasyHookWorkPathLength);
	RemoteInfo->UserInjectLibrary = (WCHAR*)(Offset += InPassThruSize);

	RemoteInfo->Size = RemoteInfoLength;
	RemoteInfo->HostProcessID = GetCurrentProcessId();
	RemoteInfo->UserDataSize = 0;

	Offset += UserInjectLibraryLength;	//  结构体和字符串尾部 - 也就是在当前进程空间申请空间的尾部

	if ((ULONG)(Offset - (PBYTE)RemoteInfo) > RemoteInfo->Size)
	{
		THROW(STATUS_BUFFER_OVERFLOW, L"A buffer overflow in internal memory was detected.");
	}

	// 将字符串放入申请到的结构体中
	RtlCopyMemory(RemoteInfo->EasyHookWorkPath, EasyHookWorkPath, EasyHookWorkPathLength);
	RtlCopyMemory(RemoteInfo->EasyHookDllPath, EasyHookDllPath, EasyHookDllPathLength);
	RtlCopyMemory(RemoteInfo->EasyHookEntryProcName, EasyHookEntryProcName, EasyHookEntryProcNameLength);
	RtlCopyMemory(RemoteInfo->UserInjectLibrary, UserInjectLibrary, UserInjectLibraryLength);

	// Hook 函数的参数放入
	if (InPassThruBuffer != NULL)
	{
		RtlCopyMemory(RemoteInfo->UserData, InPassThruBuffer, InPassThruSize);

		RemoteInfo->UserDataSize = InPassThruSize;
	}

	// 写入ShellCode - 先放入 ShellCode 再让入 RemoteInfo
	if (!WriteProcessMemory(TargetProcessHandle, RemoteShellCodeBase, (PVOID)GetInjectionPtr(), ShellCodeLength, &ReturnLength) || ReturnLength != ShellCodeLength)
	{
		THROW(STATUS_INTERNAL_ERROR, L"Unable to write into target process memory.");
	}

	// 创建通信事件
	RemoteSignalEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (RemoteSignalEvent == NULL)
	{
		THROW(STATUS_INSUFFICIENT_RESOURCES, L"Unable to create event.");
	}

	// 将事件句柄 Duplicate 到对面进程空间, 但是将这个新的句柄值暂存在当前进程空间
	if (!DuplicateHandle(GetCurrentProcess(), RemoteSignalEvent, TargetProcessHandle, &RemoteInfo->RemoteSignalEvent, EVENT_ALL_ACCESS, FALSE, 0))
	{
		THROW(STATUS_INTERNAL_ERROR, L"Failed to duplicate remote event.");
	}

	//  重新修正结构体后面的字符串指针 - 将他们的地址 修正为是对面进程里的值
	//  结构体里面指针本来指向是当前进程空间里的地址 - 也就是结构体后面字符串的首地址
	//  但是当我们把结构体写入到对方进程空间里的时候，这些指针也应该指向结构体后面的地址 - 所以我们要将他们修正
	CorrectRemoteInfo = (PREMOTE_INFOR)(RemoteShellCodeBase + ShellCodeLength);
	CorrectValue = (PUCHAR)CorrectRemoteInfo - (PUCHAR)RemoteInfo;

	RemoteInfo->EasyHookDllPath = (wchar_t*)(((PUCHAR)RemoteInfo->EasyHookDllPath) + CorrectValue);
	RemoteInfo->EasyHookEntryProcName = (char*)(((PUCHAR)RemoteInfo->EasyHookEntryProcName) + CorrectValue);
	RemoteInfo->EasyHookWorkPath = (wchar_t*)(((PUCHAR)RemoteInfo->EasyHookWorkPath) + CorrectValue);
	RemoteInfo->UserInjectLibrary = (wchar_t*)(((PUCHAR)RemoteInfo->UserInjectLibrary) + CorrectValue);

	if (RemoteInfo->UserData != NULL)
	{
		RemoteInfo->UserData = (PBYTE)(((PUCHAR)RemoteInfo->UserData) + CorrectValue);
	}

	RemoteInfo->RemoteEntryPoint = RemoteShellCodeBase;

	if (!WriteProcessMemory(TargetProcessHandle, CorrectRemoteInfo, RemoteInfo, RemoteInfoLength, &ReturnLength) || ReturnLength != RemoteInfoLength)
	{
		THROW(STATUS_INTERNAL_ERROR, L"Unable to write into target process memory.");
	}

	// 启动远程线程
	if ((InjectionOptions & EASYHOOK_INJECT_STEALTH) != 0)
	{
		FORCE(RhCreateStealthRemoteThread(TargetProcessID, (LPTHREAD_START_ROUTINE)RemoteShellCodeBase, CorrectRemoteInfo, &RemoteThreadHandle));
	}
	else
	{
		if (!RTL_SUCCESS(RtlNtCreateThreadEx(TargetProcessHandle, (LPTHREAD_START_ROUTINE)RemoteShellCodeBase, CorrectRemoteInfo, FALSE, &RemoteThreadHandle)))
		{
			RemoteThreadHandle = CreateRemoteThread(TargetProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)RemoteShellCodeBase, CorrectRemoteInfo, 0, NULL);
			if (RemoteThreadHandle == NULL)
			{
				THROW(STATUS_ACCESS_DENIED, L"Unable to create remote thread.");
			}
		}
	}

	// 注意这两个句柄的先后顺序
	HandleArrary[1] = RemoteSignalEvent;
	HandleArrary[0] = RemoteThreadHandle;

	Index = WaitForMultipleObjects(2, HandleArrary, FALSE, INFINITE);

	if (Index == WAIT_OBJECT_0)	// 这其实是异常处理 - 在ShellCode调用过程里 进入ASM ShellCode(启动远程线程) 然后 entry等等操作 
								// 最后在调用最后的入口函数之前 SetEvent, 让等待返回，这时候的返回值应该是 1 也就是正常处理
								// 但是如果在这之前的任何地方发生了错误，线程就会结束。那么这时候等待函数返回值就是0 那么就会进入 if操作 得到错误结果，显示
	{
		GetExitCodeThread(RemoteThreadHandle, &ErrorCode);

		SetLastError(ErrorCode & 0x0FFFFFFF);

		switch (ErrorCode & 0xF0000000)
		{
		case 0x10000000:
		{
			THROW(STATUS_INTERNAL_ERROR, L"Unable to find internal entry point.");
		}
		case 0x20000000:
		{
			THROW(STATUS_INTERNAL_ERROR, L"Unable to make stack executable.");
		}
		case 0x30000000:
		{
			THROW(STATUS_INTERNAL_ERROR, L"Unable to release injected library.");
		}
		case 0x40000000:
		{
			THROW(STATUS_INTERNAL_ERROR, L"Unable to find EasyHook library in target process context.");
		}
		case 0xF0000000:
			// Error in C++ Injection Completeion
		{
			switch (ErrorCode & 0xFF)
			{
#ifdef _M_X64
			case 20:
			{
				THROW(STATUS_INVALID_PARAMETER_5, L"Unable to load the given 64-bit library into target process.");
			}
			case 21:
			{
				THROW(STATUS_INVALID_PARAMETER_5, L"Unable to find the required native entry point in the given 64-bit library.");
			}
			case 12:
			{
				THROW(STATUS_INVALID_PARAMETER_5, L"Unable to find the required managed entry point in the given 64-bit library.");
			}
#else
			case 20:
			{
				THROW(STATUS_INVALID_PARAMETER_4, L"Unable to load the given 32-bit library into target process.");
			}
			case 21:
			{
				THROW(STATUS_INVALID_PARAMETER_4, L"Unable to find the required native entry point in the given 32-bit library.");
			}
			case 12:
			{
				THROW(STATUS_INVALID_PARAMETER_4, L"Unable to find the required managed entry point in the given 32-bit library.");
			}
#endif
			case 13:
			{
				THROW(STATUS_DLL_INIT_FAILED, L"The user defined managed entry point failed in the target process. Make sure that EasyHook is registered in the GAC. Refer to event logs for more information.");
			}
			case 1: 
			{
				THROW(STATUS_INTERNAL_ERROR, L"Unable to allocate memory in target process.");
			}
			case 2: 
			{
				THROW(STATUS_INTERNAL_ERROR, L"Unable to adjust target's PATH variable.");
			}
			case 3:
			{
				THROW(STATUS_INTERNAL_ERROR, L"Can't get Kernel32 module handle.");
			}
			case 10: 
			{
				THROW(STATUS_INTERNAL_ERROR, L"Unable to load 'mscoree.dll' into target process.");
			}
			case 11: 
			{
				THROW(STATUS_INTERNAL_ERROR, L"Unable to bind NET Runtime to target process.");
			}
			case 22:
			{
				THROW(STATUS_INTERNAL_ERROR, L"Unable to signal remote event.");
			}
			default: 
				THROW(STATUS_INTERNAL_ERROR, L"Unknown error in injected C++ completion routine.");
			}
		}
		case 0:
		{
			THROW(STATUS_INTERNAL_ERROR, L"C++ completion routine has returned success but didn't raise the remote event.");
		}
		default:
		{
			THROW(STATUS_INTERNAL_ERROR, L"Unknown error in injected assembler code.");
		}
		}
	}
	else if (Index != WAIT_OBJECT_0 + 1)	// 两个句柄都没有返回
	{
		THROW(STATUS_INTERNAL_ERROR, L"Unable to wait for injection completion due to timeout. ");
	}

	RETURN;

THROW_OUTRO:
FINALLY_OUTRO:
	{
		if (TargetProcessHandle != NULL)
		{
			CloseHandle(TargetProcessHandle);
		}

		if (RemoteInfo != NULL)
		{
			RtlFreeMemory(RemoteInfo);
		}

		if (RemoteThreadHandle != NULL)
		{
			CloseHandle(RemoteThreadHandle);
		}

		if (RemoteSignalEvent != NULL)
		{
			CloseHandle(RemoteSignalEvent);
		}

		return NtStatus;
	}
}

EASYHOOK_NT_API RhIsX64Process(ULONG32 ProcessID, BOOL * bIsx64)
{
	NTSTATUS NtStatus = 0;
	BOOL     bTemp = FALSE;
	pfnIsWow64Process	IsWow64Process = NULL;
	HANDLE TargetProcessHandle = NULL;

#ifndef _M_X64
	pfnGetNativeSystemInfo		GetNativeSystemInfo = NULL;
	SYSTEM_INFO					SystemInfo = { 0 };
#endif

	if (bIsx64 == NULL)
	{
		THROW(STATUS_INVALID_PARAMETER_2, L"The Given Result Storage Is Invalid.");
	}
	TargetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);
	if (TargetProcessHandle == NULL)
	{
		if (GetLastError() == ERROR_ACCESS_DENIED)
		{
			THROW(STATUS_ACCESS_DENIED, L"Unable To Open Target Process. Consider Using a System Service.");
		}
		else
		{
			THROW(STATUS_NOT_FOUND, L"The Given Target Process Does Not Exist!");
		}
	}

	// 这里直接GetModuleHandle 可以吗？
	// Wow64 系列函数是 64Bit特有 如果这个函数为空 可以判断对方是 32Bit
	IsWow64Process = (pfnIsWow64Process)GetProcAddress(GetModuleHandleW(L"Kernel32.dll"), "IsWow64Process");
	// 如果IsWow64Process 应该只可能是 32位系统 所以直接进入#else里
#ifdef _M_X64
	// 如果对方不是 Wow64程序 就是64-bit
	if (!IsWow64Process(TargetProcessHandle, &bTemp))
	{
		THROW(STATUS_INTERNAL_ERROR, L"Unable To Detect Wether Target Process Is 64-bit Or Not.");
	}

	bTemp = !bTemp;		// bTemp一开始是表示 是否是 Wow64 现在我们要让他表示是否是 64bit 所以取一次反
#else
	if (IsWow64Process != NULL)	// 为空一定是32bit Proc
	{
		GetNativeSystemInfo = (pfnGetNativeSystemInfo)GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "GetNativeSystemInfo");

		if (GetNativeSystemInfo == NULL)
		{
			GetNativeSystemInfo(&SystemInfo);

			if (SystemInfo.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_INTEL)  // PROCESSOR_ARCHITECTURE_INTEL - x86 标志
			{
				// 当前是64位系统 对方又拥有Wow系函数
				if (!IsWow64Process(TargetProcessHandle, &bTemp))
				{
					THROW(STATUS_INTERNAL_ERROR, L"Unable to detect wether target process is 64-bit or not.");
				}
				bTemp = !bTemp;
			}
		}
	}
#endif
	// 如果不能提供Wow函数 直接来到这一步
	*bIsx64 = bTemp;
	RETURN(STATUS_SUCCESS);

THROW_OUTRO:
FINALLY_OUTRO:
	if (TargetProcessHandle != NULL)
	{
		CloseHandle(TargetProcessHandle);	
	}
	return NtStatus;
}

EASYHOOK_NT_INTERNAL NtForceLdrInitializeThunk(HANDLE ProcessHandle)
{
	HANDLE		RemoteThreadHandle = NULL;
	BYTE		ShellCode[3] = { 0 };
	ULONG32		ShellCodeSize = 0;
	SIZE_T		WriteSize = 0;
	PUCHAR		RemoteBuffer = NULL;
	NTSTATUS	NtStatus = STATUS_SUCCESS;

#ifdef _M_X64
	// 64位 靠寄存器传递参数 所以不需要堆栈恢复 直接ret
	ShellCode[0] = 0xC3;	// ret
	ShellCodeSize = 1;
#else
	// 32位 进程回调函数 有一个参数 并且32位是靠压参来传参 所以函数结束应该堆栈平衡
	ShellCode[0] = 0xC2;	// ret 0x4
	ShellCode[1] = 0x04;
	ShellCode[2] = 0x00;
	ShellCodeSize = 3;
#endif
	// 在对方进程申请内存 
	RemoteBuffer = (PUCHAR)VirtualAllocEx(ProcessHandle, NULL, ShellCodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (RemoteBuffer == NULL)
	{
		THROW(STATUS_NO_MEMORY, L"Unable To Allocate Memory In Target Process.");
	}
	//  写入ShellCode
	if (!WriteProcessMemory(ProcessHandle, RemoteBuffer, ShellCode, ShellCodeSize, &WriteSize) || WriteSize != ShellCodeSize)
	{
		THROW(STATUS_INTERNAL_ERROR, L"Unable To Write Into Target Process Memory.");
	}
	// 启动远程线程
	if (!RTL_SUCCESS(RtlNtCreateThreadEx(ProcessHandle, (LPTHREAD_START_ROUTINE)RemoteBuffer, NULL, FALSE, &RemoteThreadHandle)))
	{
		// 换一种方法
		RemoteThreadHandle = CreateRemoteThread(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)RemoteBuffer, NULL, 0, NULL);
		if (RemoteThreadHandle == NULL)
		{
			THROW(STATUS_ACCESS_DENIED, L"Unable To Create Remote Thread.");
		}
	}
	// 等待远程线程执行完毕 - 也就是对方运行环境初始化完毕 Kernel32加载完成
	WaitForSingleObject(RemoteThreadHandle, INFINITE);

	RETURN;

THROW_OUTRO:
FINALLY_OUTRO:
	return NtStatus;
}

EASYHOOK_NT_INTERNAL RtlNtCreateThreadEx(HANDLE ProcessHandle, LPTHREAD_START_ROUTINE ThreadStart, PVOID ThreadParameter, BOOL IsThreadSuspended, HANDLE * ThreadHandle)
{
	HANDLE		TempHandle = NULL;
	NTSTATUS	NtStatus = STATUS_SUCCESS;
	pfnNtCreateThreadEx NtCreateThreadEx = NULL;

	if (ThreadHandle == NULL)
	{
		THROW(STATUS_INVALID_PARAMETER_4, L"The Given Handle Storage Is Invalid.");
	}

	NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");
	if (NtCreateThreadEx == NULL)
	{
		THROW(STATUS_NOT_SUPPORTED, L"NtCreateThreadEx() Is Not Supported.");
	}

	FORCE(NtCreateThreadEx(&TempHandle, 0x1FFFFF, NULL, ProcessHandle, (LPTHREAD_START_ROUTINE)ThreadStart, ThreadParameter, IsThreadSuspended, 0, NULL, NULL, NULL));

	*ThreadHandle = TempHandle;

	RETURN;

THROW_OUTRO:
FINALLY_OUTRO:
	return NtStatus;
}

PVOID  GetRemoteProcAddress(ULONG32 ProcessID, HANDLE ProcessHandle, CHAR* strModuleName, CHAR* strFunctioName)
{// 为啥函数传递的是两个 string 而不是 wstring 因为如果函数递归 - 也就是转发到处都情况时 从导出表读出的dll名和函数名 都是单字 所以这里要用string
	HMODULE	   RemoteModuleHandle = NULL;
	ULONG_PTR  RemoteExportBase = 0;
	ULONG32    RemoteExportSize = 0;
	ULONG32*   RemoteExportNameTable = NULL;
	USHORT*	   RemoteExportNameOrdinalTable = NULL;
	ULONG32*   RemoteExportAddressTable = NULL;
	ULONG_PTR  RemoteFunctionAddress = 0;
	ULONG_PTR  RemoteNameAddress = 0;
	WORD       RemoteFunctionOdinal = 0;
	CHAR       RemoteFunctionName[MAX_PATH] = { 0 };
	IMAGE_DOS_HEADER		RemoteDosHeader = { 0 };
	IMAGE_NT_HEADERS		RemoteNtHeaders = { 0 };
	IMAGE_EXPORT_DIRECTORY	RemoteExportDirectory = { 0 };


	// 得到模块句柄
	RemoteModuleHandle = GetRemoteModuleHandle(ProcessID, strModuleName);
	if (RemoteModuleHandle == NULL)
	{
		return NULL;
	}

	// 读取Dos头内容
	if (!ReadProcessMemory(ProcessHandle, (PVOID)RemoteModuleHandle, &RemoteDosHeader, sizeof(IMAGE_DOS_HEADER), NULL) || RemoteDosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}
	// 读取Nt头内容
	if (!ReadProcessMemory(ProcessHandle, (PVOID)((DWORD_PTR)RemoteModuleHandle + RemoteDosHeader.e_lfanew), &RemoteNtHeaders, sizeof(IMAGE_NT_HEADERS), NULL) || RemoteNtHeaders.Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}
	// 读取导出表目录
	if (!GetRemoteModuleExportDirectory(ProcessHandle, RemoteModuleHandle, &RemoteExportDirectory, RemoteDosHeader, RemoteNtHeaders))
	{
		return NULL;
	}

	// 申请导出表三根表的内存空间
	RemoteExportNameTable = (ULONG32*)malloc(RemoteExportDirectory.NumberOfNames * sizeof(ULONG32));
	RemoteExportNameOrdinalTable = (USHORT*)malloc(RemoteExportDirectory.NumberOfNames * sizeof(USHORT));
	RemoteExportAddressTable = (ULONG32*)malloc(RemoteExportDirectory.NumberOfFunctions * sizeof(ULONG32));

	// 从内存读取三根表内存
	// 地址表
	if (!ReadProcessMemory(ProcessHandle, (PVOID)((ULONG_PTR)RemoteModuleHandle + (ULONG_PTR)RemoteExportDirectory.AddressOfFunctions),
		RemoteExportAddressTable, RemoteExportDirectory.NumberOfFunctions * sizeof(ULONG32), NULL))
	{
		free(RemoteExportNameTable);
		free(RemoteExportNameOrdinalTable);
		free(RemoteExportAddressTable);
		return NULL;
	}

	// 姓名表
	if (!ReadProcessMemory(ProcessHandle, (PVOID)((ULONG_PTR)RemoteModuleHandle + (ULONG_PTR)RemoteExportDirectory.AddressOfNames),
		RemoteExportNameTable, RemoteExportDirectory.NumberOfNames * sizeof(ULONG32), NULL))
	{
		free(RemoteExportNameTable);
		free(RemoteExportNameOrdinalTable);
		free(RemoteExportAddressTable);
		return NULL;
	}

	// 姓名索引表 因为索引表是按照姓名导出生成的 所以节点个数和姓名一样
	if (!ReadProcessMemory(ProcessHandle, (PVOID)((ULONG_PTR)RemoteModuleHandle + (ULONG_PTR)RemoteExportDirectory.AddressOfNameOrdinals),
		RemoteExportNameOrdinalTable, RemoteExportDirectory.NumberOfNames * sizeof(WORD), NULL))
	{
		free(RemoteExportNameTable);
		free(RemoteExportNameOrdinalTable);
		free(RemoteExportAddressTable);
		return NULL;
	}

	RemoteExportBase = ((ULONG_PTR)RemoteModuleHandle + RemoteNtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	RemoteExportSize = RemoteNtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	// 遍历导出表
	for (ULONG32 i = 0; i < RemoteExportDirectory.NumberOfNames; i++)
	{
		RemoteFunctionOdinal = RemoteExportNameOrdinalTable[i];
		RemoteNameAddress = (ULONG_PTR)RemoteModuleHandle + RemoteExportNameTable[i];
		RemoteFunctionAddress = (ULONG_PTR)RemoteModuleHandle + RemoteExportAddressTable[RemoteFunctionOdinal];

		ZeroMemory(RemoteFunctionName, MAX_PATH);

		if (!ReadProcessMemory(ProcessHandle, (PVOID)RemoteNameAddress, RemoteFunctionName, MAX_PATH, NULL))	// 确认对方的姓名可读性 - 大概是为了验证对方的确是按名称到处的？
		{
			continue;
		}

		if (_stricmp(RemoteFunctionName, strFunctioName) != 0)		// 对比姓名 找到我们寻找到函数
		{
			continue;
		}

		if (RemoteFunctionOdinal >= RemoteExportDirectory.NumberOfNames)
		{
			return NULL;
		}

		// 如果地址还在导出表范围内 就说是转发函数
		if (RemoteFunctionAddress >= RemoteExportBase && RemoteFunctionAddress <= RemoteExportBase + RemoteExportSize)
		{
			CHAR	  SourceDllName[MAX_PATH] = { 0 };
			CHAR	  TargetFunctionName[MAX_PATH] = { 0 };
			CHAR      szSourceFilePath[MAX_PATH] = { 0 };

			if (!ReadProcessMemory(ProcessHandle, (PVOID)RemoteFunctionAddress, szSourceFilePath, MAX_PATH, NULL))
			{
				continue;
			}

			CHAR* Temp = strchr(szSourceFilePath, '.');		// 转发器函数的地址 实际是一个字符串 (源DLL名).(指向的函数名)

															// 获得目标函数名
			strcpy(TargetFunctionName, Temp + 1);
			// 构造源DLL名
			memcpy(SourceDllName, szSourceFilePath, (ULONG_PTR)Temp - (ULONG_PTR)szSourceFilePath);
			strcat(SourceDllName, ".dll");

			free(RemoteExportNameTable);
			free(RemoteExportNameOrdinalTable);
			free(RemoteExportAddressTable);

			return GetRemoteProcAddress(ProcessID, ProcessHandle, SourceDllName, TargetFunctionName);		// 正是因为这一步的存在 导致return形式不统一 不能像 前面用THROW一样处理
		}

		free(RemoteExportNameTable);
		free(RemoteExportNameOrdinalTable);
		free(RemoteExportAddressTable);

		return (PVOID)RemoteFunctionAddress;
	}

	free(RemoteExportNameTable);
	free(RemoteExportNameOrdinalTable);
	free(RemoteExportAddressTable);

	return NULL;
}

HMODULE GetRemoteModuleHandle(ULONG32 ProcessID, CHAR* strModuleName)
{
	MODULEENTRY32	ModuleEntry32 = { 0 };
	HANDLE			ToolHelp32SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessID);
	CHAR			szModuleName[MAX_PATH] = { 0 };
	size_t			TransferSize = 0;

	ModuleEntry32.dwSize = sizeof(MODULEENTRY32);
	Module32First(ToolHelp32SnapshotHandle, &ModuleEntry32);
	do
	{
		wcstombs_s(&TransferSize, szModuleName, MAX_PATH, ModuleEntry32.szModule, MAX_PATH);

		if (!_stricmp(szModuleName, strModuleName))		// 找到目标模块姓名
		{
			CloseHandle(ToolHelp32SnapshotHandle);
			return ModuleEntry32.hModule;
		}
	} while (Module32Next(ToolHelp32SnapshotHandle, &ModuleEntry32));

	CloseHandle(ToolHelp32SnapshotHandle);
	return NULL;
}

BOOL EASYHOOK_API GetRemoteModuleExportDirectory(HANDLE ProcessHandle, HMODULE ModuleHandle,
	PIMAGE_EXPORT_DIRECTORY RemoteExportDirectory, IMAGE_DOS_HEADER RemoteDosHeader, IMAGE_NT_HEADERS RemoteNtHeaders)
{
	DWORD	   ExportTableAddr = 0;
	PBYTE	   RemoteModulePEHeader = NULL;
	PIMAGE_SECTION_HEADER	RemoteSectionHeader = NULL;

	if (RemoteExportDirectory == NULL)
	{
		return FALSE;
	}

	RemoteModulePEHeader = (PBYTE)malloc(1024 * sizeof(PBYTE));		// PE头 一般只有 1024长
	ZeroMemory(RemoteExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY));

	if (!ReadProcessMemory(ProcessHandle, (PVOID)ModuleHandle, RemoteModulePEHeader, 1024, NULL))
	{
		return FALSE;
	}

	// RemoteModulePEHeader 现在是整个模块的内存起始地址 + e_lfanew 到PE头 + sizeof(IMAGE_NT_HEADERS) 到了节表的头部
	RemoteSectionHeader = (PIMAGE_SECTION_HEADER)(RemoteModulePEHeader + RemoteDosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS));

	for (int i = 0; i < RemoteNtHeaders.FileHeader.NumberOfSections; i++, RemoteSectionHeader++)
	{
		if (RemoteSectionHeader == NULL)
		{
			continue;
		}

		// 找到节表中的 .edata 也就是导出表的节表
		if (_stricmp((CHAR*)(RemoteSectionHeader->Name), ".edata") == 0)
		{
			// VirtualAddress 不加基地址 ？- 源代码没加 我自己加了
			if (!ReadProcessMemory(ProcessHandle, (PVOID)(ModuleHandle + RemoteSectionHeader->VirtualAddress), RemoteExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), NULL))
			{
				continue;
			}

			free(RemoteModulePEHeader);
			return TRUE;
		}
	}

	// 直接从可选头里读RVA
	ExportTableAddr = RemoteNtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (ExportTableAddr == 0)
	{
		return FALSE;
	}

	// 读导出表
	if (!ReadProcessMemory(ProcessHandle, (PVOID)((ULONG_PTR)ModuleHandle + ExportTableAddr), RemoteExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), NULL))
	{
		return FALSE;
	}

	free(RemoteModulePEHeader);
	return TRUE;
}

// ASM 文件 操作
static DWORD InjectionSize = 0;

#ifdef _M_X64
	EXTERN_C VOID Injection_ASM_x64();
#else
EXTERN_C VOID __stdcall Injection_ASM_x86();
#endif

BYTE* GetInjectionPtr()	// 得到ASM函数首地址
{
#ifdef _M_X64
	BYTE* Ptr = (BYTE*)Injection_ASM_x64;
#else
	BYTE* Ptr = (BYTE*)Injection_ASM_x86;
#endif

	// stdcall 解析 - 第一次跳转 进去是又一次跳转 E9 = jump, 得到E9后面的跳转偏移
	if (*Ptr == 0xE9)
	{
		Ptr += *((int*)(Ptr + 1)) + 5;
		// Ptr + 1 - 跳过 E9。当int* 解析一次,得到跳转的偏移。跳转的基地址是下一条指令的基地址 Ptr += 5。 最后得到二次跳转到的实际地址，也就是函数实现的实际地址。
	}

	return Ptr;
}

ULONG GetShellCodeSize()
{
	UCHAR*          Ptr;
	UCHAR*          BasePtr;
	ULONG           Index;
	ULONG           Signature;

	if (InjectionSize != 0)
		return InjectionSize;

	// 查找硬编码 得到长度
	BasePtr = Ptr = GetInjectionPtr();

	for (Index = 0; Index < 2000 /* some always large enough value*/; Index++)
	{
		Signature = *((ULONG32*)Ptr);

		if (Signature == 0x12345678)		// 自己ASM文件末尾手动写得标志
		{
			InjectionSize = (ULONG)(Ptr - BasePtr);

			return InjectionSize;
		}

		Ptr++;
	}

	ASSERT(FALSE, L"thread.c - ULONG GetInjectionSize()");

	return 0;
}

extern DWORD RhTlsIndex;
EASYHOOK_NT_INTERNAL RhSetWakeUpThreadID(ULONG32 InThreadID)
{
	NTSTATUS NtStatus;

	if (!TlsSetValue(RhTlsIndex, (PVOID)(size_t)InThreadID))
	{
		THROW(STATUS_INTERNAL_ERROR, L"Unable to set TLS value.");
	}

	RETURN;

THROW_OUTRO:
FINALLY_OUTRO:
	return NtStatus;

}
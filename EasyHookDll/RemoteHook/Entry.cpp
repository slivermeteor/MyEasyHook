#include "common.h"

#define UNMANAGED_ERROR(code) {ErrorCode = ((code) & 0xFF) | 0xF0000000; goto ABORT_ERROR;}
typedef VOID(_stdcall *pfnRemoteEntryProc)(PREMOTE_ENTRY_INFOR RemoteEntryInfo);

EASYHOOK_NT_INTERNAL CompleteUnmanagedInjection(PREMOTE_INFOR RemoteInfo);
EASYHOOK_NT_API HookCompleteInjection(PREMOTE_INFOR RemoteInfo);


EASYHOOK_NT_API HookCompleteInjection(PREMOTE_INFOR RemoteInfo)
{
	ULONG32		ErrorCode = 0;

	HMODULE		Kernel32Handle = GetModuleHandleA("Kernel32.dll");

	if (Kernel32Handle == NULL)
	{
		UNMANAGED_ERROR(3);
	}

	// 重新获得一遍函数地址 - 提供稳定性
	// 现在我们已经运行在对方进程空间里
	RemoteInfo->LoadLibraryW = GetProcAddress(Kernel32Handle, "LoadLibraryW");
	RemoteInfo->FreeLibrary = GetProcAddress(Kernel32Handle, "FreeLibrary");
	RemoteInfo->GetLastError = GetProcAddress(Kernel32Handle, "GetLastError");
	RemoteInfo->GetProcAddress = GetProcAddress(Kernel32Handle, "GetProcAddress");
	RemoteInfo->ExitThread = GetProcAddress(Kernel32Handle, "ExitThread");
	RemoteInfo->VirtualProtect = GetProcAddress(Kernel32Handle, "VirtualProtect");
	RemoteInfo->VirtualFree = GetProcAddress(Kernel32Handle, "VirtualFree");
	
	// 设置环境变量 - 省略


	// 设置 TLS
	if (!RTL_SUCCESS(RhSetWakeUpThreadID(RemoteInfo->WakeUpThreadID)))  // 在目标线程里的一个TLS设置了值
		UNMANAGED_ERROR(3);
	
	// 加载真正要注入的Dll
	if (RemoteInfo->IsManaged)
	{
		// .NET Hook
	}
	else
	{
		// Win32 Hook
		ErrorCode = CompleteUnmanagedInjection(RemoteInfo);
	}

ABORT_ERROR:
	if (RemoteInfo->RemoteSignalEvent != NULL)	// Hook 函数在最后SetEvent 或者 异常退出 无论是哪个 我们都应该
	{
		CloseHandle(RemoteInfo->RemoteSignalEvent);
	}

	return ErrorCode;
}

EASYHOOK_NT_INTERNAL CompleteUnmanagedInjection(PREMOTE_INFOR RemoteInfo)
{
	ULONG32		ErrorCode = 0;
	HMODULE		UserLibraryHandle = NULL;
	REMOTE_ENTRY_INFOR RemoteEntryInfor = { 0 };
	// 注意这个函数名 必须在 UserLibrary 里面实现 - 注意导出函数的调用约定一定是 _stdcall
	UserLibraryHandle = LoadLibraryW(RemoteInfo->UserInjectLibrary);
	if (UserLibraryHandle == NULL)
	{
		UNMANAGED_ERROR(20);
	}

	pfnRemoteEntryProc RemoteEntryProc = (pfnRemoteEntryProc)GetProcAddress(UserLibraryHandle,
#ifdef _M_X64
	"EasyHookInjectionEntry"
#else
	"_EasyHookInjectionEntry@4"
#endif
	);
	if (RemoteEntryProc == NULL)
	{
		UNMANAGED_ERROR(21);
	}

	if (!SetEvent(RemoteInfo->RemoteSignalEvent))	// 提醒 RhInject 函数 注入成功
	{
		UNMANAGED_ERROR(22);
	}

	// 设置参数
	RemoteEntryInfor.HostProcessPID = RemoteInfo->HostProcessID;
	RemoteEntryInfor.UserData = (RemoteInfo->UserData) ? RemoteInfo->UserData : NULL;
	RemoteEntryInfor.UserDataSize = RemoteInfo->UserDataSize;

	RemoteEntryProc(&RemoteEntryInfor);

	// 是不是可以在这里释放 UserInjectLibrary ???
	return STATUS_SUCCESS;

ABORT_ERROR:

	return ErrorCode;
}
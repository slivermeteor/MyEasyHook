#ifndef _COMMON_H_
#define _COMMON_H_

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>

#pragma warning(disable: 4005)	// 宏重定义警告 - 让 ntstatus与windows的重定义警告去掉
#include <ntstatus.h>
#pragma warning(default: 4005)

#include <TlHelp32.h>

#include "..\Public\EasyHook.h"
#include "..\DriverShared\DriverShared.h"

// Rtl/File.c
BOOL RtlFileExists(WCHAR* InPath);
LONG RtlGetWorkingDirectory(WCHAR* OutPath, ULONG InMaxLength);
LONG RtlGetCurrentModulePath(WCHAR* OutPath, ULONG InMaxLength);

#define RTL_SUCCESS(ntstatus)       SUCCEEDED(ntstatus)

// 强制对齐宏 
#define WRAP_ULONG64(Decl) union{ ULONG64 UNUSED; Decl;}

#define UNUSED2(y) __Unused_##y
#define UNUSED1(y) UNUSED2(y)
#define UNUSED UNUSED1(__COUNTER__)

typedef struct _REMOTE_INFOR_
{
	// will be the same for all processes
	WRAP_ULONG64(wchar_t* UserLibrary);  // fixed 0
	WRAP_ULONG64(wchar_t* EasyHookPath); // fixed 8
	WRAP_ULONG64(wchar_t* PATH);		 // fixed 16
	WRAP_ULONG64(char* EasyHookEntry);   // fixed 24
	WRAP_ULONG64(void* RemoteEntryPoint); // fixed 32
	WRAP_ULONG64(void* LoadLibraryW);	 // fixed; 40
	WRAP_ULONG64(void* FreeLibrary);     // fixed; 48
	WRAP_ULONG64(void* GetProcAddress);  // fixed; 56
	WRAP_ULONG64(void* VirtualFree);	 // fixed; 64
	WRAP_ULONG64(void* VirtualProtect);  // fixed; 72
	WRAP_ULONG64(void* ExitThread);		 // fixed; 80
	WRAP_ULONG64(void* GetLastError);    // fixed; 88

	BOOL            IsManaged;
	HANDLE          hRemoteSignal;
	DWORD           HostProcess;
	DWORD           Size;
	BYTE*           UserData;
	DWORD           UserDataSize;
	ULONG           WakeUpThreadID;
}REMOTE_INFOR, *PREMOTE_INFOR;


extern HMODULE	CurrentModuleHandle;

#define RTL_SUCCESS(ntstatus)       SUCCEEDED(ntstatus)




#endif
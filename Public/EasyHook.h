#ifndef _EASYHOOK_H_
#define _EASYHOOK_H_

#include <windows.h>

// Dll导出符号
#ifdef EASYHOOK_EXPORTS
#define EASYHOOK_API						__declspec(dllexport) __stdcall
#define DRIVER_SHARED_API(type, decl)		EXTERN_C type EASYHOOK_API decl
#else
#ifndef DRIVER
#define EASYHOOK_API					__declspec(dllimport) __stdcall
#define DRIVER_SHARED_API(type, decl)	EXTERN_C type EASYHOOK_API decl
#else
#define EASYHOOK_API					__stdcall
#define DRIVER_SHARED_API(type, decl)	typedef type EASYHOOK_API PROC_##decl; EXTERN_C type EASYHOOK_API decl
#endif
#endif

#define EASYHOOK_NT_API          EXTERN_C NTSTATUS EASYHOOK_API
#define EASYHOOK_BOOL_API        EXTERN_C BOOL EASYHOOK_API

#define MAX_PASSTHRU_SIZE           1024 * 64

#define EASYHOOK_INJECT_DEFAULT				0x00000000
#define EASYHOOK_INJECT_STEALTH				0x10000000 // (experimental)

typedef struct _REMOTE_ENTRY_INFOR_
{
	ULONG           HostProcessPID;
	UCHAR*          UserData;
	ULONG           UserDataSize;
}REMOTE_ENTRY_INFOR, *PREMOTE_ENTRY_INFOR;


// EasyHookDll/Thread.c 导出函数
EASYHOOK_NT_API RhInjectLibrary(INT32 TargetProcessID, INT32 WakeUpThreadID, INT32 InjectionOptions, WCHAR* LibraryPath_x86, WCHAR* LibraryPath_x64, 
							    PVOID InPassThruBuffer, INT32 InPassThruSize);

EASYHOOK_NT_API RhIsX64Process(ULONG32 ProcessID, BOOL * bIsx64);

BOOL EASYHOOK_API GetRemoteModuleExportDirectory(HANDLE ProcessHandle, HMODULE ModuleHandle,
	PIMAGE_EXPORT_DIRECTORY RemoteExportDirectory, IMAGE_DOS_HEADER RemoteDosHeader, IMAGE_NT_HEADERS RemoteNtHeaders);

// EasyHookDll/Stealth.c 导出函数
EASYHOOK_NT_API RhCreateStealthRemoteThread(ULONG32 InTargetProcessID, LPTHREAD_START_ROUTINE InRemoteRoutine,
	PVOID InRemoteParameter, PHANDLE OutRemoteThreadHandle);

// Error.c 导出函数
DRIVER_SHARED_API(PWCHAR, RtlGetLastErrorString());
DRIVER_SHARED_API(NTSTATUS, RtlGetLastError());



#endif
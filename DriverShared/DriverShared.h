#ifndef _DRIVERSHARED_H_
#define _DRIVERSHARED_H_

#include "Rtl/Rtl.h"

#define EASYHOOK_NT_INTERNAL            EXTERN_C NTSTATUS __stdcall
#define EASYHOOK_BOOL_INTERNAL          EXTERN_C BOOL __stdcall

#define EASYHOOK_INJECT_MANAGED			0x00000001
// EasyHookDll/thead.c 非导出函数
EASYHOOK_NT_INTERNAL RtlNtCreateThreadEx(HANDLE ProcessHandle, LPTHREAD_START_ROUTINE ThreadStart, PVOID ThreadParameter, BOOL IsThreadSuspended, HANDLE * ThreadHandle);
EASYHOOK_NT_INTERNAL NtForceLdrInitializeThunk(HANDLE ProcessHandle);
EASYHOOK_NT_INTERNAL RhSetWakeUpThreadID(ULONG32 InThreadID);


#endif
#ifndef _EASYHOOK_RTL_
#define _EASYHOOK_RTL_

#include "common.h"

#if _DEBUG
#define DEBUGMSG(message) { WCHAR debugMsg[1024] = { 0 }; _snwprintf_s(debugMsg, 1024, _TRUNCATE, L"%s\n", message); OutputDebugStringW(debugMsg); }
#else
#define DEBUGMSG(message) { }
#endif

#ifndef DRIVER
#define ASSERT(expr, Msg)            RtlAssert((BOOL)(expr),(LPCWSTR) Msg);
#define THROW(code, Msg)			 { NtStatus = (code); RtlSetLastError(GetLastError(), NtStatus, Msg); goto THROW_OUTRO; }
#else
#pragma warning(disable: 4005)
#define ASSERT( exp, Msg )           ((!(exp)) ? (RtlAssert(#exp, __FILE__, __LINE__, NULL), FALSE) : TRUE)
#pragma warning(default: 4005)
#define THROW(code, Msg)			 { NtStatus = (code); RtlSetLastError(NtStatus, NtStatus, Msg); goto THROW_OUTRO; }
#endif

#define RETURN                      { RtlSetLastError(STATUS_SUCCESS, STATUS_SUCCESS, L""); NtStatus = STATUS_SUCCESS; goto FINALLY_OUTRO; }
#define FORCE(expr)                 { if(!RTL_SUCCESS(NtStatus = (expr))) goto THROW_OUTRO; }
#define IsValidPointer				RtlIsValidPointer

// Barrier.c 
#ifdef DRIVER

#else
typedef struct _RTL_SPIN_LOCK_
{
	CRITICAL_SECTION	Lock;
	BOOL				IsOwned;
}RTL_SPIN_LOCK, *PRTL_SPIN_LOCK;
#endif

// Error.c
void RtlSetLastError(LONG InCode, LONG InNtStatus, WCHAR* InMessage);
BOOL RtlIsValidPointer(PVOID InPtr, ULONG InSize);
#ifndef DRIVER
void RtlAssert(BOOL InAssert, LPCWSTR lpMessageText);
#endif

// String.c
ULONG32 RtlUnicodeLength(WCHAR* InString);
ULONG32 RtlAnsiLength(CHAR* InString);
LONG    RtlAnsiIndexOf(CHAR* InString, CHAR InChar);
LONG    RtlAnsiSubString(PCHAR InString, ULONG InOffset, ULONG InCount, PCHAR InTarget, ULONG InTargetMaxLength);
LONG64  RtlAnsiHexToLong64(const CHAR* str, INT Length);

// Memory.c
#undef RtlZeroMemory
VOID RtlZeroMemory(PVOID InStart, ULONG32 InByteCount);

#undef RtlCopyMemory
VOID RtlCopyMemory(PVOID InDest, PVOID InSource, ULONG32 InByteCount);

VOID* RtlAllocateMemory(BOOL InZeroMemory, ULONG32 InSize);
VOID RtlFreeMemory(PVOID InPointer);
LONG RtlProtectMemory(PVOID InPointer, ULONG InSize, ULONG InNewProtection);


void RtlInitializeLock(RTL_SPIN_LOCK* OutLock);
void RtlDeleteLock(RTL_SPIN_LOCK* InLock);

VOID RtlAcquireLock(PRTL_SPIN_LOCK InLock);
VOID RtlReleaseLock(PRTL_SPIN_LOCK InLock);

void RtlSleep(ULONG InTime);


#endif
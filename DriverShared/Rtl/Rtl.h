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



// error.c
void RtlSetLastError(LONG InCode, LONG InNtStatus, WCHAR* InMessage);
BOOL RtlIsValidPointer(PVOID InPtr, ULONG InSize);
#ifndef DRIVER
void RtlAssert(BOOL InAssert, LPCWSTR lpMessageText);
#endif

// string.c
ULONG32 RtlUnicodeLength(WCHAR* InString);
ULONG32 RtlAnsiLength(CHAR* InString);

//memory.c
#undef RtlZeroMemory
VOID RtlZeroMemory(PVOID InStart, ULONG32 InByteCount);

#undef RtlCopyMemory
VOID RtlCopyMemory(PVOID InDest, PVOID InSource, ULONG32 InByteCount);

VOID* RtlAllocateMemory(BOOL InZeroMemory, ULONG32 InSize);
VOID RtlFreeMemory(PVOID InPointer);

#endif
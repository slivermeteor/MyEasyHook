// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "common.h"


HMODULE CurrentModuleHandle = NULL;
HANDLE  EasyHookHeapHandle = NULL;
HANDLE  Kernel32Handle = NULL;
HANDLE  NtdllHandle = NULL;
DWORD   RhTlsIndex;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		CurrentModuleHandle = hModule;

		if ((NtdllHandle = LoadLibraryA("ntdll.dll")) == NULL ||
			(Kernel32Handle = LoadLibraryA("kernel32.dll")) == NULL)
		{
			return FALSE;
		}

		EasyHookHeapHandle = HeapCreate(0, 0, 0);
		break;
	}
	case DLL_THREAD_ATTACH:
	{
		break;
	}
	case DLL_THREAD_DETACH:
	{
		break;
	}
	case DLL_PROCESS_DETACH:
	{

		HeapDestroy(EasyHookHeapHandle);

		FreeLibrary(NtdllHandle);
		FreeLibrary(Kernel32Handle);
		break;
	}
	}
	return TRUE;
}


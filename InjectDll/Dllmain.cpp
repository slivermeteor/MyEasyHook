#include <windows.h>

typedef struct _REMOTE_ENTRY_INFOR_
{
	ULONG           HostProcessPID;
	UCHAR*          UserData;
	ULONG           UserDataSize;
}REMOTE_ENTRY_INFOR, *PREMOTE_ENTRY_INFOR;

HMODULE DllModule = NULL;


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		DllModule = hModule;
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

EXTERN_C __declspec(dllexport) VOID  _stdcall EasyHookInjectionEntry()
{
	MessageBoxA(NULL, "Success", "EasyHookInject", MB_OK);

	FreeLibraryAndExitThread(DllModule, 0);
	return;
}
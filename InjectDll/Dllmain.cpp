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

DWORD WINAPI MainThread(PVOID lParam)
{
	PREMOTE_ENTRY_INFOR Buffer = (PREMOTE_ENTRY_INFOR)lParam;
	MessageBoxA(NULL, (PCHAR)Buffer->UserData, "EasyHook", 0);

	FreeLibraryAndExitThread(DllModule, 0);
	return 0;
}

EXTERN_C __declspec(dllexport) VOID  _stdcall EasyHookInjectionEntry(PVOID Data)
{
	//FreeLibraryAndExitThread(DllModule, 0);	// 如果在这里释放自己并退出进程 - EasyHookDll 就不能得到正常释放 - 会留下痕迹
	// 我们应该启动一个线程 - 在哪里执行真正的代码 - 最后自我释放和退出线程 来做到无痕
	
	CreateThread(NULL, 0, MainThread, Data, 0, NULL);

	return;
}

EXTERN_C __declspec(dllexport) VOID  _stdcall NativeInjectionEntryPoint(PVOID Data)
{
	//FreeLibraryAndExitThread(DllModule, 0);

	CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
	return;
}
#define _CRT_SECURE_NO_WARNINGS
#include "..\Public\EasyHook.h"
#include <TlHelp32.h>
#pragma warning(disable:4005)
#include <ntstatus.h>
#pragma warning(default:4005)

#include <iostream>

using namespace std;

#ifndef _WIN64
	#pragma comment(lib, "EasyHookDll32.lib")	
#else
	#pragma comment(lib, "EasyHookDll64.lib")
#endif

ULONG32 GetProcessIdByName(WCHAR* wzProcessName);
VOID TestLocalHook();
VOID Test();

int main()
{	
	LONG Index = 0;
	while (TRUE)
	{
		cout << "Input the index of Hook method:" << endl;
		cout << "1. Remote Hook." << endl << "2. Local Hook." << endl << "3. Exit." << endl;
		cout << "Index:"; cin >> Index;

		if (Index == 1)
		{
			WCHAR wzProcessName[MAX_PATH] = { 0 };
			cout << "Input the target process name:";
			scanf("%S", wzProcessName);
	

			ULONG32 TargetProcessID = GetProcessIdByName(wzProcessName);
			CHAR    szPassThruBuffer[] = "PassThruBuffer";

#ifndef _WIN64
			WCHAR wzInjectDllPath[MAX_PATH] = L"InjectDll32.dll";
			NTSTATUS Status = RhInjectLibrary(TargetProcessID, 0, EASYHOOK_INJECT_STEALTH, wzInjectDllPath, NULL, szPassThruBuffer, strlen(szPassThruBuffer) + 1);
#else
			WCHAR wzInjectDllPath[MAX_PATH] = L"InjectDll64.dll";
			NTSTATUS Status = RhInjectLibrary(TargetProcessID, 0, EASYHOOK_INJECT_STEALTH, NULL, wzInjectDllPath, szPassThruBuffer, strlen(szPassThruBuffer) + 1);
#endif

			if (Status != STATUS_SUCCESS)
			{
				cout << "Remote hook failed. Error Code:" << hex << Status << endl;
				printf("Error Message:%S\r\n", RtlGetLastErrorString());
			}
			else
			{
				cout << "Remote hook success." << endl;
			}
		}
		else if (Index == 2)
		{
			HOOK_TRACE_INFO HookTraceInfo = { 0 };
			NTSTATUS Status = LhInstallHook(Test, TestLocalHook, NULL, &HookTraceInfo);
			if (FAILED(Status))
			{
				cout << "Local Hook Failed." << endl;
				break;
			}

			Test();
			ULONG ACE[1] = { 0 };
			LhSetInclusiveACL(ACE, 1, &HookTraceInfo);

			Test();

			LhuninstallHook(&HookTraceInfo);

			Test();

			LhWaitForPendingRemovals();

		}
		else if (Index == 3)
			break;
	}

	system("pause");
	return 0;
}

ULONG32 GetProcessIdByName(WCHAR * wzProcessName)
{
	PROCESSENTRY32 ProcessEntry = { 0 };
	HANDLE SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (SnapshotHandle != INVALID_HANDLE_VALUE)
	{
		ProcessEntry.dwSize = sizeof(PROCESSENTRY32);
		Process32First(SnapshotHandle, &ProcessEntry);

		do
		{
			if (_wcsicmp(ProcessEntry.szExeFile, wzProcessName) == 0)
			{
				CloseHandle(SnapshotHandle);
				return ProcessEntry.th32ProcessID;
			}
		} while (Process32Next(SnapshotHandle, &ProcessEntry));
	}

	return ULONG32(0);
}

VOID Test()
{
	cout << "HelloWorld" << endl;
}

VOID TestLocalHook()
{
	cout << "Hook" << endl;
	Test();
}
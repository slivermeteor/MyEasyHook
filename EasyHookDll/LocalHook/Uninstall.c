#include <common.h>


void LhCriticalFinalize()
{
	/*
	Description:

	Will be called in the DLL_PROCESS_DETACH event and just uninstalls
	all hooks. If it is possible also their memory is released.
	*/
	//LhUninstallAllHooks();

	//LhWaitForPendingRemovals();

	RtlDeleteLock(&GlobalHookLock);
}

EASYHOOK_NT_API LhuninstallHook(TRACED_HOOK_HANDLE InHandle)
{
	// 移除Hook, 如果需要释放关联的资源，调用 LhWaitForPendingRemovals()。
	PLOCAL_HOOK_INFO LocalHookInfo = NULL;
	PLOCAL_HOOK_INFO HookList = NULL;
	PLOCAL_HOOK_INFO ListPrev = NULL;
	BOOLEAN			 IsAllocated = FALSE;
	NTSTATUS         NtStatus = STATUS_UNSUCCESSFUL;

	if (!IsValidPointer(InHandle, sizeof(TRACED_HOOK_HANDLE)))
		return FALSE;

	RtlAcquireLock(&GlobalHookLock);
	{
		if ((InHandle->Link != NULL) && LhIsValidHandle(InHandle, &LocalHookInfo))
		{
			// 清空指针 - 但不释放资源
			InHandle->Link = NULL;

			if (LocalHookInfo->HookProc != NULL)
			{
				LocalHookInfo->HookProc = NULL;
				IsAllocated = TRUE;
			}

			if (!IsAllocated)
			{
				RtlReleaseLock(&GlobalHookLock);

				RETURN;
			}

			// 从全局Hook链表中移除
			HookList = GlobalHookListHead.Next;
			ListPrev = &GlobalHookListHead;

			while (HookList != NULL)
			{
				if (HookList == LocalHookInfo)
				{
					ListPrev->Next = LocalHookInfo->Next;
					break;
				}

				HookList = HookList->Next;
			}

			// 添加到移除表中
			LocalHookInfo->Next = GlobalRemovalListHead.Next;
			GlobalRemovalListHead.Next = LocalHookInfo;
		}

		RtlReleaseLock(&GlobalHookLock);
		RETURN;
	}
	//THROW_OUTRO:
FINALLY_OUTRO:
	return NtStatus;
}

EASYHOOK_NT_API LhWaitForPendingRemovals()
{
	// 为了稳定性考虑，所有的资源都必须在没有人使用的情况下释放。
	// 将释放资源从卸载钩子分开出来可以让你先卸载钩子，然后在最终在释放资源。
	PLOCAL_HOOK_INFO	LocalHookInfo = NULL;
	NTSTATUS			NtStatus = STATUS_SUCCESS;
	INT32				TimeOut = 1000;


#ifdef X64_DRIVER
	KIRQL	CurrentIRQL = PASSIVE_LEVEL;
#endif

	while (TRUE)
	{
		// 取出一个Hook
		RtlAcquireLock(&GlobalHookLock);
		{
			LocalHookInfo = GlobalRemovalListHead.Next;
			if (LocalHookInfo == NULL)
			{
				RtlReleaseLock(&GlobalHookLock);
				break;
			}

			GlobalRemovalListHead.Next = LocalHookInfo->Next;
		}
		RtlReleaseLock(&GlobalHookLock);

		// Hook入口还保持Hook好后的样子吗?
		if (LocalHookInfo->HookSave == *((PULONG64)LocalHookInfo->TargetProc))
		{
#ifdef X64_DRIVER
			CurrentIRQL = KeGetCurrentIrql();
			RtlWPOFF()
#endif
			*((PULONG64)LocalHookInfo->TargetProc) = LocalHookInfo->TargetBackup;	// 恢复原样
#ifdef X64_DRIVER
			*((PULONG64)(LocalHookInfo->TargetProc + 8)) = LocalHookInfo->TargetBackup_x64;
			RtlWPON();
#endif
			while (TRUE)
			{
				if (*LocalHookInfo->IsExecutedPtr <= 0)	// 无人使用
				{
					// 释放 Slot
					if (GlobalSlotList[LocalHookInfo->HLSIndex] == LocalHookInfo->HLSIdent)
						GlobalSlotList[LocalHookInfo->HLSIndex] = 0;

					LhFreeMemory(&LocalHookInfo);
					break;
				}

				if (TimeOut < 0)
				{
					NtStatus = STATUS_TIMEOUT;
					break;
				}

				RtlSleep(25);
				TimeOut -= 25;
			}
		}
		else
		{

		}
	}
	
	return NtStatus;
}
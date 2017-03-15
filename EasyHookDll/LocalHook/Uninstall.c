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
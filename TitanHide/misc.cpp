#include "misc.h"
#include "undocumented.h"

ULONG Misc::GetProcessIDFromProcessHandle(HANDLE ProcessHandle)
{
	PROCESS_BASIC_INFORMATION PBI;
	if (NT_SUCCESS(Undocumented::ZwQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &PBI, sizeof(PBI), NULL)))
		return (ULONG)PBI.UniqueProcessId;
	else
		return 0;
}

ULONG Misc::GetProcessIDFromThreadHandle(HANDLE ThreadHandle)
{
	typedef struct _THREAD_BASIC_INFORMATION
	{
		NTSTATUS ExitStatus;
		PVOID TebBaseAddress;
		CLIENT_ID ClientId;
		KAFFINITY AffinityMask;
		KPRIORITY Priority;
		KPRIORITY BasePriority;
	} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;
	THREAD_BASIC_INFORMATION TBI;
	if (NT_SUCCESS(Undocumented::ZwQueryInformationThread(ThreadHandle, ThreadBasicInformation, &TBI, sizeof(TBI), NULL)))
		return (ULONG)TBI.ClientId.UniqueProcess;
	else
		return 0;
}

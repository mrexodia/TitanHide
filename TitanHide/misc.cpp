#include "misc.h"
#include "undocumented.h"

void* RtlAllocateMemory(bool InZeroMemory, SIZE_T InSize)
{
    void* Result=ExAllocatePoolWithTag(NonPagedPool, InSize, 'HIDE');
    if(InZeroMemory && (Result!=NULL))
        RtlZeroMemory(Result, InSize);
    return Result;
}

void RtlFreeMemory(void* InPointer)
{
    ExFreePool(InPointer);
}

ULONG GetProcessIDFromProcessHandle(HANDLE ProcessHandle)
{
    PROCESS_BASIC_INFORMATION PBI;
    if(NT_SUCCESS(ZwQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &PBI, sizeof(PBI), NULL)))
        return PBI.UniqueProcessId;
    else
        return 0;
}

ULONG GetProcessIDFromThreadHandle(HANDLE ThreadHandle)
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
    if(NT_SUCCESS(ZwQueryInformationThread(ThreadHandle, ThreadBasicInformation, &TBI, sizeof(TBI), NULL)))
        return (ULONG)TBI.ClientId.UniqueProcess;
    else
        return 0;
}

#include "hooks.h"
#include "hooklib.h"
#include "undocumented.h"

static HOOK hNtQueryInformationProcess;

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

NTSTATUS HookNtQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength
)
{
    unhook(hNtQueryInformationProcess);
    NTSTATUS ret=NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
    if(ProcessInformation && ProcessInformationLength)
    {
        ULONG pid=GetProcessIDFromProcessHandle(ProcessHandle);
        if(ProcessInformationClass==ProcessDebugFlags)
        {
            DbgPrint("[TESTDRIVER] ProcessDebugFlags by %d\n", pid);
            if(6276==pid)
                *(unsigned int*)ProcessInformation=FALSE;
        }
        else if(ProcessInformationClass==ProcessDebugPort)
        {
            DbgPrint("[TESTDRIVER] ProcessDebugPort by %d\n", pid);
            if(6276==pid)
                *(unsigned int*)ProcessInformation=-1;
        }
        else if(ProcessInformationClass==ProcessDebugObjectHandle)
        {
            DbgPrint("[TESTDRIVER] ProcessDebugObjectHandle by %d\n", pid);
            if(6276==pid)
                *(unsigned int*)ProcessInformation=1;
        }
    }
    hook(hNtQueryInformationProcess);
    return ret;
}

bool HooksInit()
{
    hNtQueryInformationProcess=hook(L"NtQueryInformationProcess", (void*)HookNtQueryInformationProcess);
    if(hNtQueryInformationProcess)
        return true;
    return false;
}

void HooksFree()
{
    unhook(hNtQueryInformationProcess, true);
}

#include "hooks.h"
#include "hooklib.h"
#include "undocumented.h"

static HOOK hNtQueryInformationProcess;
static HOOK hNtQueryObject;

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
        ULONG hide=18784+1;
        ULONG pid=GetProcessIDFromProcessHandle(ProcessHandle);
        if(ProcessInformationClass==ProcessDebugFlags)
        {
            DbgPrint("[TESTDRIVER] ProcessDebugFlags by %d\n", pid);
            if(pid==hide)
                *(unsigned int*)ProcessInformation=TRUE;
        }
        else if(ProcessInformationClass==ProcessDebugPort)
        {
            DbgPrint("[TESTDRIVER] ProcessDebugPort by %d\n", pid);
            if(hide==hide)
                *(unsigned int*)ProcessInformation=0;
        }
        else if(ProcessInformationClass==ProcessDebugObjectHandle)
        {
            DbgPrint("[TESTDRIVER] ProcessDebugObjectHandle by %d\n", pid);
            if(pid==hide)
                *(unsigned int*)ProcessInformation=0;
        }
    }
    hook(hNtQueryInformationProcess);
    return ret;
}

NTSTATUS HookNtQueryObject(
    IN HANDLE Handle OPTIONAL,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation OPTIONAL,
    IN ULONG ObjectInformationLength,
    OUT PULONG ReturnLength OPTIONAL
)
{
    unhook(hNtQueryObject);
    DbgPrint("[TESTDRIVER] NtQueryObject\n");
    NTSTATUS ret=NtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
    hook(hNtQueryObject);
    return ret;
}

bool HooksInit()
{
    hNtQueryInformationProcess=hook(L"NtQueryInformationProcess", (void*)HookNtQueryInformationProcess);
    if(!hNtQueryInformationProcess)
        return false;
    /*hNtQueryObject=hook(L"NtQueryObject", (void*)HookNtQueryObject);
    if(!hNtQueryObject)
        return false;*/
    return true;
}

void HooksFree()
{
    unhook(hNtQueryInformationProcess, true);
    unhook(hNtQueryObject, true);
}

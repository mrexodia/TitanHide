#include "misc.h"
#include "undocumented.h"

ULONG Misc::GetProcessIDFromProcessHandle(HANDLE ProcessHandle)
{
    ULONG Pid = 0;
    PEPROCESS Process;
    if(NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(), (PVOID*)&Process, nullptr)))
    {
        Pid = (ULONG)(ULONG_PTR)PsGetProcessId(Process);
        ObDereferenceObject(Process);
    }
    return Pid;
}

ULONG Misc::GetProcessIDFromThreadHandle(HANDLE ThreadHandle)
{
    ULONG Pid = 0;
    PETHREAD Thread;
    if(NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, 0, *PsThreadType, ExGetPreviousMode(), (PVOID*)&Thread, nullptr)))
    {
        Pid = (ULONG)(ULONG_PTR)PsGetProcessId(PsGetThreadProcess(Thread));
        ObDereferenceObject(Thread);
    }
    return Pid;
}

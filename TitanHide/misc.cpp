#include "misc.h"
#include "undocumented.h"

#ifndef _WIN64
extern "C" __declspec(naked) void unlockCR0()
{
    __asm
    {
        mov eax, cr0
        and eax, 0FFFEFFFFh ;
        ~10000
        mov cr0, eax
    }
}

extern "C" __declspec(naked) void lockCR0()
{
    __asm
    {
        mov eax, cr0
        or eax, 10000h
        mov cr0, eax
    }
}
#endif

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

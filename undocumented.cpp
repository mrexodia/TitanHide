#include "undocumented.h"

NTSTATUS ZwQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    typedef NTSTATUS (*QUERY_INFO_PROCESS) (
        IN HANDLE ProcessHandle,
        IN PROCESSINFOCLASS ProcessInformationClass,
        OUT PVOID ProcessInformation,
        IN ULONG ProcessInformationLength,
        OUT PULONG ReturnLength OPTIONAL
    );
    static QUERY_INFO_PROCESS ZwQIP=0;
    if(!ZwQIP)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
        ZwQIP=(QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);
        if(!ZwQIP)
            return STATUS_UNSUCCESSFUL;
    }
    return ZwQIP(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

NTSTATUS ZwQueryInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    typedef NTSTATUS (*QUERY_INFO_THREAD) (
        IN HANDLE ThreadHandle,
        IN THREADINFOCLASS ThreadInformationClass,
        IN OUT PVOID ThreadInformation,
        IN ULONG ThreadInformationLength,
        OUT PULONG ReturnLength OPTIONAL
    );
    static QUERY_INFO_THREAD ZwQIT=0;
    if(!ZwQIT)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ZwQueryInformationThread");
        ZwQIT=(QUERY_INFO_THREAD)MmGetSystemRoutineAddress(&routineName);
        if(!ZwQIT)
            return STATUS_UNSUCCESSFUL;
    }
    return ZwQIT(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
}
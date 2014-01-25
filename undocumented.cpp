#include "undocumented.h"
#include "ssdt.h"

NTSTATUS NTAPI ZwQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    typedef NTSTATUS (NTAPI *QUERY_INFO_PROCESS) (
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

NTSTATUS NTAPI ZwQueryInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    typedef NTSTATUS (NTAPI *QUERY_INFO_THREAD) (
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

NTSTATUS NTAPI NtQueryObject(
    IN HANDLE Handle OPTIONAL,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation OPTIONAL,
    IN ULONG ObjectInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    typedef NTSTATUS (NTAPI *QUERY_OBJECT) (
        IN HANDLE Handle OPTIONAL,
        IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
        OUT PVOID ObjectInformation OPTIONAL,
        IN ULONG ObjectInformationLength,
        OUT PULONG ReturnLength OPTIONAL
    );
    static QUERY_OBJECT NtQO=0;
    if(!NtQO)
    {
        NtQO=(QUERY_OBJECT)SSDTgpa("NtQueryObject");
        if(!NtQO)
            return STATUS_UNSUCCESSFUL;
    }
    return NtQO(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
}

NTSTATUS NTAPI ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    typedef NTSTATUS (NTAPI *QUERY_SYSTEM_INFO) (
        IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
        OUT PVOID SystemInformation,
        IN ULONG SystemInformationLength,
        OUT PULONG ReturnLength OPTIONAL
    );
    static QUERY_SYSTEM_INFO ZwQSI=0;
    if(!ZwQSI)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ZwQuerySystemInformation");
        ZwQSI=(QUERY_SYSTEM_INFO)MmGetSystemRoutineAddress(&routineName);
        if(!ZwQSI)
            return STATUS_UNSUCCESSFUL;
    }
    return ZwQSI(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

NTSTATUS NTAPI NtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    typedef NTSTATUS (NTAPI *QUERY_SYSTEM_INFO) (
        IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
        OUT PVOID SystemInformation,
        IN ULONG SystemInformationLength,
        OUT PULONG ReturnLength OPTIONAL
    );
    static QUERY_SYSTEM_INFO NtQSI=0;
    if(!NtQSI)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"NtQuerySystemInformation");
        NtQSI=(QUERY_SYSTEM_INFO)MmGetSystemRoutineAddress(&routineName);
        if(!NtQSI)
            return STATUS_UNSUCCESSFUL;
    }
    return NtQSI(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

NTSTATUS NTAPI NtClose(
    IN HANDLE Handle)
{
    typedef NTSTATUS (NTAPI *NT_CLOSE) (
        IN HANDLE Handle
    );
    static NT_CLOSE NtC=0;
    if(!NtC)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"NtClose");
        NtC=(NT_CLOSE)MmGetSystemRoutineAddress(&routineName);
        if(!NtC)
            return STATUS_UNSUCCESSFUL;
    }
    return NtC(Handle);
}

NTSTATUS NTAPI NtDuplicateObject(
    IN HANDLE SourceProcessHandle,
    IN HANDLE SourceHandle,
    IN HANDLE TargetProcessHandle,
    OUT PHANDLE TargetHandle,
    IN ACCESS_MASK DesiredAccess OPTIONAL,
    IN BOOLEAN InheritHandle,
    IN ULONG Options)
{
    typedef NTSTATUS (NTAPI *NT_DUPLICATE_OBJECT) (
        IN HANDLE SourceProcessHandle,
        IN HANDLE SourceHandle,
        IN HANDLE TargetProcessHandle,
        OUT PHANDLE TargetHandle,
        IN ACCESS_MASK DesiredAccess OPTIONAL,
        IN BOOLEAN InheritHandle,
        IN ULONG Options
    );
    static NT_DUPLICATE_OBJECT NtDO=0;
    if(!NtDO)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"NtDuplicateObject");
        NtDO=(NT_DUPLICATE_OBJECT)MmGetSystemRoutineAddress(&routineName);
        if(!NtDO)
            return STATUS_UNSUCCESSFUL;
    }
    return NtDO(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, InheritHandle, Options);
}

NTSTATUS NTAPI KeRaiseUserException(
    IN NTSTATUS ExceptionCode)
{
    typedef NTSTATUS (NTAPI *KE_RAISE_USER_EXCEPTION) (
        IN NTSTATUS ExceptionCode
    );
    static KE_RAISE_USER_EXCEPTION KeRUE=0;
    if(!KeRUE)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"KeRaiseUserException");
        KeRUE=(KE_RAISE_USER_EXCEPTION)MmGetSystemRoutineAddress(&routineName);
        if(!KeRUE)
            return STATUS_UNSUCCESSFUL;
    }
    return KeRUE(ExceptionCode);
}

//Based on: http://alter.org.ua/docs/nt_kernel/procaddr
PVOID KernelGetModuleBase(PCHAR pModuleName)
{
    typedef struct _SYSTEM_MODULE_ENTRY
    {
        ULONG Reserved1[2];
#ifdef _WIN64
        ULONG Reserved2[2];
#endif
        PVOID Base;
        ULONG Size;
        ULONG Flags;
        USHORT Index;
        USHORT Unknown;
        USHORT LoadCount;
        USHORT ModuleNameOffset;
        CHAR ImageName[256];
    } SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

    typedef struct _SYSTEM_MODULE_INFORMATION
    {
        ULONG Count;
        SYSTEM_MODULE_ENTRY Module[0];
    } SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

    PVOID pModuleBase = NULL;
    PULONG pSystemInfoBuffer = NULL;

    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    ULONG    SystemInfoBufferSize = 0;

    status = ZwQuerySystemInformation(SystemModuleInformation,
                                      &SystemInfoBufferSize,
                                      0,
                                      &SystemInfoBufferSize);

    if (!SystemInfoBufferSize)
    {
        DbgPrint("[TITANHIDE] ZwQuerySystemInformation (1) failed...\n");
        return NULL;
    }

    pSystemInfoBuffer = (PULONG)ExAllocatePool(NonPagedPool, SystemInfoBufferSize*2);

    if (!pSystemInfoBuffer)
    {
        DbgPrint("[TITANHIDE] ExAllocatePool failed...\n");
        return NULL;
    }

    memset(pSystemInfoBuffer, 0, SystemInfoBufferSize*2);

    status = ZwQuerySystemInformation(SystemModuleInformation,
                                      pSystemInfoBuffer,
                                      SystemInfoBufferSize*2,
                                      &SystemInfoBufferSize);

    if(NT_SUCCESS(status))
    {
        PSYSTEM_MODULE_ENTRY pSysModuleEntry=((PSYSTEM_MODULE_INFORMATION)(pSystemInfoBuffer))->Module;
        ULONG i;
        int len=strlen(pModuleName);
        for(i=0; i<((PSYSTEM_MODULE_INFORMATION)(pSystemInfoBuffer))->Count; i++)
        {
            if(_strnicmp(pSysModuleEntry[i].ImageName + pSysModuleEntry[i].ModuleNameOffset, pModuleName, len) == 0)
            {
                pModuleBase=pSysModuleEntry[i].Base;
                break;
            }
        }
    }
    else
        DbgPrint("[TITANHIDE] ZwQuerySystemInformation (2) failed...\n");

    if(pSystemInfoBuffer)
    {
        ExFreePool(pSystemInfoBuffer);
    }

    return pModuleBase;
}

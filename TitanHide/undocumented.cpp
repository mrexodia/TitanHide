#include "undocumented.h"
#include "ssdt.h"

typedef NTSTATUS (NTAPI *NTQUERYINFORMATIONPROCESS) (
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS (NTAPI *ZWQUERYINFORMATIONTHREAD) (
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS (NTAPI *NTQUERYOBJECT) (
    IN HANDLE Handle OPTIONAL,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation OPTIONAL,
    IN ULONG ObjectInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS (NTAPI *ZWQUERYSYSTEMINFORMATION) (
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS (NTAPI *NTQUERYSYSTEMINFORMATION) (
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS (NTAPI *NTCLOSE) (
    IN HANDLE Handle
);

typedef NTSTATUS (NTAPI *KERAISEUSEREXCEPTION) (
    IN NTSTATUS ExceptionCode
);

typedef NTSTATUS (NTAPI *NTSETINFORMATIONTHREAD) (
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID ThreadInformation,
    IN ULONG ThreadInformationLength
);

static NTQUERYINFORMATIONPROCESS ZwQIP=0;
static ZWQUERYINFORMATIONTHREAD ZwQIT=0;
static NTQUERYOBJECT NtQO=0;
static ZWQUERYSYSTEMINFORMATION ZwQSI=0;
static NTQUERYSYSTEMINFORMATION NtQSI=0;
static NTCLOSE NtC=0;
static KERAISEUSEREXCEPTION KeRUE=0;
static NTSETINFORMATIONTHREAD NtSIT=0;

bool UndocumentedInit()
{
    NTSTATUS ret=STATUS_SUCCESS;
    if(!ZwQSI)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ZwQuerySystemInformation");
        ZwQSI=(ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&routineName);
        if(!ZwQSI)
            ret=STATUS_UNSUCCESSFUL;
    }
    if(!ZwQIP)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
        ZwQIP=(NTQUERYINFORMATIONPROCESS)MmGetSystemRoutineAddress(&routineName);
        if(!ZwQIP)
            ret=STATUS_UNSUCCESSFUL;
    }
    if(!ZwQIT)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ZwQueryInformationThread");
        ZwQIT=(ZWQUERYINFORMATIONTHREAD)MmGetSystemRoutineAddress(&routineName);
        if(!ZwQIT)
            ret=STATUS_UNSUCCESSFUL;
    }
    if(!NtQSI)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"NtQuerySystemInformation");
        NtQSI=(NTQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&routineName);
        if(!NtQSI)
            ret=STATUS_UNSUCCESSFUL;
    }
    if(!NtC)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"NtClose");
        NtC=(NTCLOSE)MmGetSystemRoutineAddress(&routineName);
        if(!NtC)
            ret=STATUS_UNSUCCESSFUL;
    }
    if(!KeRUE)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"KeRaiseUserException");
        KeRUE=(KERAISEUSEREXCEPTION)MmGetSystemRoutineAddress(&routineName);
        if(!KeRUE)
            ret=STATUS_UNSUCCESSFUL;
    }
    if(!NtSIT)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"NtSetInformationThread");
        NtSIT=(NTSETINFORMATIONTHREAD)MmGetSystemRoutineAddress(&routineName);
        if(!NtSIT)
            ret=STATUS_UNSUCCESSFUL;
    }
    if(!NtQO)
    {
        NtQO=(NTQUERYOBJECT)SSDTgpa(L"NtQueryObject");
        if(!NtQO)
            ret=STATUS_UNSUCCESSFUL;
    }
    return NT_SUCCESS(ret);
}

NTSTATUS NTAPI ZwQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    return ZwQIP(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

NTSTATUS NTAPI ZwQueryInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    return ZwQIT(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
}

NTSTATUS NTAPI NtQueryObject(
    IN HANDLE Handle OPTIONAL,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation OPTIONAL,
    IN ULONG ObjectInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    return NtQO(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
}

NTSTATUS NTAPI ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    return ZwQSI(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

NTSTATUS NTAPI NtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    return NtQSI(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

NTSTATUS NTAPI NtClose(
    IN HANDLE Handle)
{
    return NtC(Handle);
}

NTSTATUS NTAPI KeRaiseUserException(
    IN NTSTATUS ExceptionCode)
{
    return KeRUE(ExceptionCode);
}

NTSTATUS NTAPI NtSetInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID ThreadInformation,
    IN ULONG ThreadInformationLength)
{
    return NtSIT(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
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

NTSTATUS NTAPI NtSetInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    IN PVOID ProcessInformation,
    IN ULONG ProcessInformationLength)
{
    typedef NTSTATUS (NTAPI *NT_SET_INFO_PROCESS) (
        IN HANDLE ProcessHandle,
        IN PROCESSINFOCLASS ProcessInformationClass,
        IN PVOID ProcessInformation,
        IN ULONG ProcessInformationLength
    );
    static NT_SET_INFO_PROCESS NtSIP=0;
    if(!NtSIP)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"NtSetInformationProcess");
        NtSIP=(NT_SET_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);
        if(!NtSIP)
            return STATUS_UNSUCCESSFUL;
    }
    return NtSIP(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
}

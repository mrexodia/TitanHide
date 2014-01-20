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

NTSTATUS NtQueryObject(
    IN HANDLE Handle OPTIONAL,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation OPTIONAL,
    IN ULONG ObjectInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    typedef NTSTATUS (*QUERY_OBJECT) (
        IN HANDLE Handle OPTIONAL,
        IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
        OUT PVOID ObjectInformation OPTIONAL,
        IN ULONG ObjectInformationLength,
        OUT PULONG ReturnLength OPTIONAL
    );
    static QUERY_OBJECT NtQO=0;
    if(!NtQO)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"NtQueryObject");
        NtQO=(QUERY_OBJECT)MmGetSystemRoutineAddress(&routineName);
        if(!NtQO)
            return STATUS_UNSUCCESSFUL;
    }
    return NtQO(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
}

NTSTATUS ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    typedef NTSTATUS (*QUERY_SYSTEM_INFO) (
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

    __try
    {
        NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
        ULONG    SystemInfoBufferSize = 0;

        status = ZwQuerySystemInformation(SystemModuleInformation,
                                          &SystemInfoBufferSize,
                                          0,
                                          &SystemInfoBufferSize);

        if (!SystemInfoBufferSize)
        {
            DbgPrint("[TESTDRIVER] ZwQuerySystemInformation (1) failed...\n");
            return NULL;
        }

        pSystemInfoBuffer = (PULONG)ExAllocatePool(NonPagedPool, SystemInfoBufferSize*2);

        if (!pSystemInfoBuffer)
        {
            DbgPrint("[TESTDRIVER] ExAllocatePool failed...\n");
            return NULL;
        }

        memset(pSystemInfoBuffer, 0, SystemInfoBufferSize*2);

        status = ZwQuerySystemInformation(SystemModuleInformation,
                                          pSystemInfoBuffer,
                                          SystemInfoBufferSize*2,
                                          &SystemInfoBufferSize);

        if (NT_SUCCESS(status))
        {
            PSYSTEM_MODULE_ENTRY pSysModuleEntry =
                ((PSYSTEM_MODULE_INFORMATION)(pSystemInfoBuffer))->Module;
            ULONG i;
            int len=strlen(pModuleName);
            for (i = 0; i <((PSYSTEM_MODULE_INFORMATION)(pSystemInfoBuffer))->Count; i++)
            {
                //DbgPrint("[TESTDRIVER] %s\n", pSysModuleEntry[i].ImageName+pSysModuleEntry[i].ModuleNameOffset);
                if (_strnicmp(pSysModuleEntry[i].ImageName + pSysModuleEntry[i].ModuleNameOffset, pModuleName, len) == 0)
                {
                    pModuleBase = pSysModuleEntry[i].Base;
                    break;
                }
            }
        }
        else
            DbgPrint("[TESTDRIVER] ZwQuerySystemInformation (2) failed...\n");

    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        pModuleBase = NULL;
    }
    if(pSystemInfoBuffer)
    {
        ExFreePool(pSystemInfoBuffer);
    }

    return pModuleBase;
}

//Based on: https://code.google.com/p/volatility/issues/detail?id=189#c2
PVOID FindSSDT()
{
#ifndef _WIN64
    //x86 code
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"KeServiceDescriptorTable");
    return MmGetSystemRoutineAddress(&routineName);
#endif
    //x64 code
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"KeAddSystemServiceTable");
    PVOID KeASST=MmGetSystemRoutineAddress(&routineName);
    if(!KeASST)
        return 0;
    unsigned char function[1024];
    unsigned int function_size=0;
    RtlCopyMemory(function, KeASST, sizeof(function));
    for(unsigned int i=0; i<sizeof(function); i++)
    {
        if(function[i]==0xC3)
        {
            function_size=i+1;
            break;
        }
    }
    if(!function_size)
        return 0;
    unsigned int rvaSSDT=0;
    for(unsigned int i=0; i<function_size; i++)
    {
        if(*(unsigned int*)(function+i)==0x1ABC834B) //4b83bc1a????????00 cmp qword ptr [r10+r11+????????h],0
        {
            rvaSSDT=*(unsigned int*)(function+i+sizeof(unsigned int));
            break;
        }
    }
    PVOID base=KernelGetModuleBase("ntoskrnl");
    if(!base)
        return 0;
    DbgPrint("[TESTDRIVER] KernelGetModuleBase(ntoskrnl)->0x%llX\n", base);
    return (PVOID)((unsigned char*)base+rvaSSDT);
}
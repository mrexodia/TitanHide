#include "undocumented.h"
#include "ssdt.h"
#include "log.h"

typedef NTSTATUS(NTAPI* ZWQUERYINFORMATIONPROCESS)(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS(NTAPI* NTQUERYINFORMATIONTHREAD)(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS(NTAPI* NTQUERYOBJECT)(
    IN HANDLE Handle OPTIONAL,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation OPTIONAL,
    IN ULONG ObjectInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS(NTAPI* ZWQUERYSYSTEMINFORMATION)(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS(NTAPI* NTQUERYSYSTEMINFORMATION)(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS(NTAPI* NTCLOSE)(
    IN HANDLE Handle
);

typedef NTSTATUS(NTAPI* NTGETCONTEXTTHREAD)(
    IN HANDLE ThreadHandle,
    IN OUT PCONTEXT Context
);

typedef NTSTATUS(NTAPI* NTSETCONTEXTTHREAD)(
    IN HANDLE ThreadHandle,
    IN PCONTEXT Context
);

typedef NTSTATUS(NTAPI* NTCONTINUE)(
    IN PCONTEXT Context,
    BOOLEAN RaiseAlert
);

typedef NTSTATUS(NTAPI* NTDUPLICATEOBJECT)(
    IN HANDLE SourceProcessHandle,
    IN HANDLE SourceHandle,
    IN HANDLE TargetProcessHandle,
    OUT PHANDLE TargetHandle,
    IN ACCESS_MASK DesiredAccess OPTIONAL,
    IN ULONG HandleAttributes,
    IN ULONG Options
);

typedef NTSTATUS(NTAPI* KERAISEUSEREXCEPTION)(
    IN NTSTATUS ExceptionCode
);

typedef NTSTATUS(NTAPI* ZWSETINFORMATIONTHREAD)(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID ThreadInformation,
    IN ULONG ThreadInformationLength
);

typedef NTSTATUS(NTAPI* NTSETINFORMATIONTHREAD)(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID ThreadInformation,
    IN ULONG ThreadInformationLength
);

typedef NTSTATUS(NTAPI* NTSETINFORMATIONPROCESS)(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    IN PVOID ProcessInformation,
    IN ULONG ProcessInformationLength
);

typedef NTSTATUS(NTAPI* NTQUERYINFORMATIONPROCESS)(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS(NTAPI* NTSYSTEMDEBUGCONTROL)(
    IN SYSDBG_COMMAND Command,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength,
    OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS(NTAPI* ZWCREATETHREADEX)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PUSER_THREAD_START_ROUTINE StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits OPTIONAL,
    IN SIZE_T StackSize OPTIONAL,
    IN SIZE_T MaximumStackSize OPTIONAL,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL
);

typedef NTSTATUS(NTAPI* NTCREATETHREADEX)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PUSER_THREAD_START_ROUTINE StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits OPTIONAL,
    IN SIZE_T StackSize OPTIONAL,
    IN SIZE_T MaximumStackSize OPTIONAL,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL
);

typedef NTSTATUS(NTAPI* ZWTERMINATETHREAD)(
    IN HANDLE ThreadHandle OPTIONAL,
    IN NTSTATUS ExitStatus
);

typedef NTSTATUS(NTAPI* NTTERMINATETHREAD)(
    IN HANDLE ThreadHandle OPTIONAL,
    IN NTSTATUS ExitStatus
);

static ZWQUERYINFORMATIONPROCESS ZwQIP = 0;
static NTQUERYINFORMATIONTHREAD NtQIT = 0;
static NTQUERYOBJECT NtQO = 0;
static ZWQUERYSYSTEMINFORMATION ZwQSI = 0;
static NTQUERYSYSTEMINFORMATION NtQSI = 0;
static NTCLOSE NtClo = 0;
static NTSETCONTEXTTHREAD NtGCT = 0;
static NTSETCONTEXTTHREAD NtSCT = 0;
static NTCONTINUE NtCon = 0;
static NTDUPLICATEOBJECT NtDO = 0;
static KERAISEUSEREXCEPTION KeRUE = 0;
static ZWSETINFORMATIONTHREAD ZwSIT = 0;
static NTSETINFORMATIONTHREAD NtSIT = 0;
static NTSETINFORMATIONPROCESS NtSIP = 0;
static NTQUERYINFORMATIONPROCESS NtQIP = 0;
static NTSYSTEMDEBUGCONTROL NtSDBC = 0;
static ZWCREATETHREADEX ZwCrThrEx = 0;
static NTCREATETHREADEX NtCrThrEx = 0;
static ZWTERMINATETHREAD ZwTermThr = 0;
static NTTERMINATETHREAD NtTermThr = 0;

NTSTATUS NTAPI Undocumented::ZwQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    return ZwQIP(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

NTSTATUS NTAPI Undocumented::NtQueryInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    return NtQIT(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
}

NTSTATUS NTAPI Undocumented::NtQueryObject(
    IN HANDLE Handle OPTIONAL,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation OPTIONAL,
    IN ULONG ObjectInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    return NtQO(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
}

NTSTATUS NTAPI Undocumented::ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    return ZwQSI(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

NTSTATUS NTAPI Undocumented::NtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    return NtQSI(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

NTSTATUS NTAPI Undocumented::NtClose(
    IN HANDLE Handle)
{
    return NtClo(Handle);
}

NTSTATUS NTAPI Undocumented::NtGetContextThread(
    IN HANDLE ThreadHandle,
    IN OUT PCONTEXT Context)
{
    return NtGCT(ThreadHandle, Context);
}

NTSTATUS NTAPI Undocumented::NtSetContextThread(
    IN HANDLE ThreadHandle,
    IN PCONTEXT Context)
{
    return NtSCT(ThreadHandle, Context);
}

NTSTATUS NTAPI Undocumented::NtContinue(
    IN PCONTEXT Context,
    BOOLEAN RaiseAlert)
{
    return NtCon(Context, RaiseAlert);
}

NTSTATUS NTAPI Undocumented::NtDuplicateObject(
    IN HANDLE SourceProcessHandle,
    IN HANDLE SourceHandle,
    IN HANDLE TargetProcessHandle,
    OUT PHANDLE TargetHandle,
    IN ACCESS_MASK DesiredAccess OPTIONAL,
    IN ULONG HandleAttributes,
    IN ULONG Options)
{
    return NtDO(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
}

NTSTATUS NTAPI Undocumented::KeRaiseUserException(
    IN NTSTATUS ExceptionCode)
{
    return KeRUE(ExceptionCode);
}

NTSTATUS NTAPI Undocumented::ZwSetInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID ThreadInformation,
    IN ULONG ThreadInformationLength)
{
    return ZwSIT(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

NTSTATUS NTAPI Undocumented::NtSetInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID ThreadInformation,
    IN ULONG ThreadInformationLength)
{
    return NtSIT(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

NTSTATUS NTAPI Undocumented::NtSetInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    IN PVOID ProcessInformation,
    IN ULONG ProcessInformationLength)
{
    return NtSIP(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
}

NTSTATUS NTAPI Undocumented::NtQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    return NtQIP(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

NTSTATUS NTAPI Undocumented::NtSystemDebugControl(
    IN SYSDBG_COMMAND Command,
    IN PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer,
    IN ULONG OutputBufferLength,
    OUT PULONG ReturnLength)
{
    return NtSDBC(Command, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength);
}

NTSTATUS NTAPI Undocumented::ZwCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PUSER_THREAD_START_ROUTINE StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits OPTIONAL,
    IN SIZE_T StackSize OPTIONAL,
    IN SIZE_T MaximumStackSize OPTIONAL,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL)
{
    return ZwCrThrEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

NTSTATUS NTAPI Undocumented::NtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PUSER_THREAD_START_ROUTINE StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits OPTIONAL,
    IN SIZE_T StackSize OPTIONAL,
    IN SIZE_T MaximumStackSize OPTIONAL,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL)
{
    return NtCrThrEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

NTSTATUS NTAPI Undocumented::ZwTerminateThread(
    IN HANDLE ThreadHandle OPTIONAL,
    IN NTSTATUS ExitStatus)
{
    return ZwTermThr(ThreadHandle, ExitStatus);
}

NTSTATUS NTAPI Undocumented::NtTerminateThread(
    IN HANDLE ThreadHandle OPTIONAL,
    IN NTSTATUS ExitStatus)
{
    return NtTermThr(ThreadHandle, ExitStatus);
}

bool Undocumented::UndocumentedInit()
{
    //Exported kernel functions after this
    if(!ZwQIP)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
        ZwQIP = (ZWQUERYINFORMATIONPROCESS)MmGetSystemRoutineAddress(&routineName);
        if(!ZwQIP)
            return false;
    }
    if(!NtQIT)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"NtQueryInformationThread");
        NtQIT = (NTQUERYINFORMATIONTHREAD)MmGetSystemRoutineAddress(&routineName);
        if(!NtQIT)
            return false;
    }
    if(!ZwQSI)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ZwQuerySystemInformation");
        ZwQSI = (ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&routineName);
        if(!ZwQSI)
            return false;
    }
    if(!NtQSI)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"NtQuerySystemInformation");
        NtQSI = (NTQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&routineName);
        if(!NtQSI)
            return false;
    }
    if(!NtClo)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"NtClose");
        NtClo = (NTCLOSE)MmGetSystemRoutineAddress(&routineName);
        if(!NtClo)
            return false;
    }
    if(!NtDO)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"NtDuplicateObject");
        NtDO = (NTDUPLICATEOBJECT)MmGetSystemRoutineAddress(&routineName);
        if(!NtDO)
            return false;
    }
    if(!KeRUE)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"KeRaiseUserException");
        KeRUE = (KERAISEUSEREXCEPTION)MmGetSystemRoutineAddress(&routineName);
        if(!KeRUE)
            return false;
    }
    if(!ZwSIT)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ZwSetInformationThread");
        ZwSIT = (ZWSETINFORMATIONTHREAD)MmGetSystemRoutineAddress(&routineName);
        if(!ZwSIT)
            return false;
    }
    if(!NtSIT)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"NtSetInformationThread");
        NtSIT = (NTSETINFORMATIONTHREAD)MmGetSystemRoutineAddress(&routineName);
        if(!NtSIT)
            return false;
    }
    if(!NtSIP)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"NtSetInformationProcess");
        NtSIP = (NTSETINFORMATIONPROCESS)MmGetSystemRoutineAddress(&routineName);
        if(!NtSIP)
            return false;
    }
    if(!NtQIP)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"NtQueryInformationProcess");
        NtQIP = (NTQUERYINFORMATIONPROCESS)MmGetSystemRoutineAddress(&routineName);
        if(!NtQIP)
            return false;
    }
    //SSDT-only functions after this
    if(!NtQO)
    {
        NtQO = (NTQUERYOBJECT)SSDT::GetFunctionAddress("NtQueryObject");
        if(!NtQO)
            return false;
    }
    if(!NtGCT)
    {
        NtGCT = (NTGETCONTEXTTHREAD)SSDT::GetFunctionAddress("NtGetContextThread");
        if(!NtGCT)
            return false;
    }
    if(!NtSCT)
    {
        NtSCT = (NTSETCONTEXTTHREAD)SSDT::GetFunctionAddress("NtSetContextThread");
        if(!NtSCT)
            return false;
    }
    if(!NtCon)
    {
        NtCon = (NTCONTINUE)SSDT::GetFunctionAddress("NtContinue");
        if(!NtCon)
            return false;
    }
    if(!NtSDBC)
    {
        NtSDBC = (NTSYSTEMDEBUGCONTROL)SSDT::GetFunctionAddress("NtSystemDebugControl");
        if(!NtSDBC)
            return false;
    }
    if((NtBuildNumber & 0xFFFF) >= 6000 && !ZwCrThrEx) // only exists on >= Vista
    {
        ZwCrThrEx = (ZWCREATETHREADEX)SSDT::GetFunctionAddress("ZwCreateThreadEx");
        if(!ZwCrThrEx)
            return false;
    }
    if((NtBuildNumber & 0xFFFF) >= 6000 && !NtCrThrEx) // only exists on >= Vista
    {
        NtCrThrEx = (NTCREATETHREADEX)SSDT::GetFunctionAddress("NtCreateThreadEx");
        if(!NtCrThrEx)
            return false;
    }
    if(!ZwTermThr)
    {
        ZwTermThr = (ZWTERMINATETHREAD)SSDT::GetFunctionAddress("ZwTerminateThread");
        if(!ZwTermThr)
            return false;
    }
    if(!NtTermThr)
    {
        NtTermThr = (NTTERMINATETHREAD)SSDT::GetFunctionAddress("NtTerminateThread");
        if(!NtTermThr)
            return false;
    }
    return true;
}

//Based on: http://alter.org.ua/docs/nt_kernel/procaddr
PVOID Undocumented::GetKernelBase(PULONG pImageSize)
{
    typedef struct _SYSTEM_MODULE_ENTRY
    {
        HANDLE Section;
        PVOID MappedBase;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR FullPathName[256];
    } SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

#pragma warning(disable:4200)
    typedef struct _SYSTEM_MODULE_INFORMATION
    {
        ULONG Count;
        SYSTEM_MODULE_ENTRY Module[0];
    } SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

    PVOID pModuleBase = NULL;
    PSYSTEM_MODULE_INFORMATION pSystemInfoBuffer = NULL;

    ULONG SystemInfoBufferSize = 0;

    NTSTATUS status = Undocumented::ZwQuerySystemInformation(SystemModuleInformation,
                      &SystemInfoBufferSize,
                      0,
                      &SystemInfoBufferSize);

    if(!SystemInfoBufferSize)
    {
        Log("[TITANHIDE] ZwQuerySystemInformation (1) failed...\r\n");
        return NULL;
    }

    pSystemInfoBuffer = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, SystemInfoBufferSize * 2, GetPoolTag());

    if(!pSystemInfoBuffer)
    {
        Log("[TITANHIDE] ExAllocatePool failed...\r\n");
        return NULL;
    }

    memset(pSystemInfoBuffer, 0, SystemInfoBufferSize * 2);

    status = Undocumented::ZwQuerySystemInformation(SystemModuleInformation,
             pSystemInfoBuffer,
             SystemInfoBufferSize * 2,
             &SystemInfoBufferSize);

    if(NT_SUCCESS(status))
    {
        pModuleBase = pSystemInfoBuffer->Module[0].ImageBase;
        if(pImageSize)
            *pImageSize = pSystemInfoBuffer->Module[0].ImageSize;
    }
    else
        Log("[TITANHIDE] ZwQuerySystemInformation (2) failed...\r\n");

    ExFreePool(pSystemInfoBuffer);

    return pModuleBase;
}

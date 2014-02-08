#include "hooks.h"
#include "undocumented.h"
#include "ssdt.h"
#include "hider.h"
#include "misc.h"
#include "pe.h"
#include "log.h"
#include "eprocess.h"

static HOOK hNtQueryInformationProcess=0;
static HOOK hNtQueryObject=0;
static HOOK hNtQuerySystemInformation=0;
static HOOK hNtClose=0;
static HOOK hNtSetInformationThread=0;

static NTSTATUS NTAPI HookNtSetInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID ThreadInformation,
    IN ULONG ThreadInformationLength)
{
    if(ThreadInformationClass==ThreadHideFromDebugger)
    {
        ULONG pid=(ULONG)PsGetCurrentProcessId();
        Log("[TITANHIDE] ThreadHideFromDebugger by %d\n", pid);
        if(HiderIsHidden(pid, HideThreadHideFromDebugger))
        {
            //Taken from: http://newgre.net/idastealth
            PKTHREAD Object;
            NTSTATUS status=ObReferenceObjectByHandle(ThreadHandle, 0, NULL, KernelMode, (PVOID*)&Object, NULL);
            if(NT_SUCCESS(status))
            {
                ObDereferenceObject(Object);
                return STATUS_SUCCESS;
            }
            else
                return status;
        }
    }
    SSDTunhook(hNtSetInformationThread);
    NTSTATUS ret=NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
    SSDThook(hNtSetInformationThread);
    return ret;
}

static NTSTATUS NTAPI HookNtClose(
    IN HANDLE Handle)
{
    SSDTunhook(hNtClose);
    ULONG pid=(ULONG)PsGetCurrentProcessId();
    NTSTATUS ret;
    if(HiderIsHidden(pid, HideNtClose))
    {
        Log("[TITANHIDE] NtClose by %d\n", pid);
        PVOID OldDebugPort=SetDebugPort(PsGetCurrentProcess(), 0);
        ret=NtClose(Handle);
        SetDebugPort(PsGetCurrentProcess(), OldDebugPort);
    }
    else
        ret=NtClose(Handle);
    SSDThook(hNtClose);
    return ret;
}

static NTSTATUS NTAPI HookNtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    SSDTunhook(hNtQuerySystemInformation);
    NTSTATUS ret=NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    if(NT_SUCCESS(ret) && SystemInformation)
    {
        ULONG pid=(ULONG)PsGetCurrentProcessId();
        if(SystemInformationClass==SystemKernelDebuggerInformation)
        {
            Log("[TITANHIDE] SystemKernelDebuggerInformation by %d\n", pid);
            if(HiderIsHidden(pid, HideSystemDebuggerInformation))
            {
                typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
                {
                    BOOLEAN DebuggerEnabled;
                    BOOLEAN DebuggerNotPresent;
                } SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;
                SYSTEM_KERNEL_DEBUGGER_INFORMATION* DebuggerInfo=(SYSTEM_KERNEL_DEBUGGER_INFORMATION*)SystemInformation;
                DebuggerInfo->DebuggerEnabled=false;
                DebuggerInfo->DebuggerNotPresent=true;
            }
        }
    }
    SSDThook(hNtQuerySystemInformation);
    return ret;
}

static NTSTATUS NTAPI HookNtQueryObject(
    IN HANDLE Handle OPTIONAL,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation OPTIONAL,
    IN ULONG ObjectInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    SSDTunhook(hNtQueryObject);
    NTSTATUS ret=NtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
    if(NT_SUCCESS(ret) && ObjectInformation)
    {
        ULONG pid=(ULONG)PsGetCurrentProcessId();
        UNICODE_STRING DebugObject;
        RtlInitUnicodeString(&DebugObject, L"DebugObject");
        if(ObjectInformationClass==ObjectTypeInformation)
        {
            OBJECT_TYPE_INFORMATION* type=(OBJECT_TYPE_INFORMATION*)ObjectInformation;
            if(RtlEqualUnicodeString(&type->TypeName, &DebugObject, FALSE)) //DebugObject
            {
                Log("[TITANHIDE] DebugObject by %d\n", pid);
                if(HiderIsHidden(pid, HideDebugObject))
                    type->TotalNumberOfObjects=0;
            }
        }
        else if(ObjectInformationClass==ObjectAllInformation)
        {
            OBJECT_ALL_INFORMATION* pObjectAllInfo=(OBJECT_ALL_INFORMATION*)ObjectInformation;
            unsigned char* pObjInfoLocation=(unsigned char*)pObjectAllInfo->ObjectTypeInformation;
            unsigned int TotalObjects=pObjectAllInfo->NumberOfObjects;
            for(unsigned int i=0; i<TotalObjects; i++)
            {
                OBJECT_TYPE_INFORMATION* pObjectTypeInfo=(OBJECT_TYPE_INFORMATION*)pObjInfoLocation;
                if(RtlEqualUnicodeString(&pObjectTypeInfo->TypeName, &DebugObject, FALSE)) //DebugObject
                {
                    Log("[TITANHIDE] DebugObject by %d\n", pid);
                    if(HiderIsHidden(pid, HideDebugObject))
                        pObjectTypeInfo->TotalNumberOfObjects=0;
                }
                pObjInfoLocation=(unsigned char*)pObjectTypeInfo->TypeName.Buffer;
                pObjInfoLocation+=pObjectTypeInfo->TypeName.MaximumLength;
                ULONG_PTR tmp=((ULONG_PTR)pObjInfoLocation)&-sizeof(void*);
                if((ULONG_PTR)tmp!=(ULONG_PTR)pObjInfoLocation)
                    tmp+=sizeof(void*);
                pObjInfoLocation=((unsigned char*)tmp);
            }
        }
    }
    SSDThook(hNtQueryObject);
    return ret;
}

static NTSTATUS NTAPI HookNtQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength)
{
    SSDTunhook(hNtQueryInformationProcess);
    NTSTATUS ret=NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
    if(NT_SUCCESS(ret) && ProcessInformation)
    {
        ULONG pid=GetProcessIDFromProcessHandle(ProcessHandle);

        if(ProcessInformationClass==ProcessDebugFlags)
        {
            Log("[TITANHIDE] ProcessDebugFlags by %d\n", pid);
            if(HiderIsHidden(pid, HideProcessDebugFlags))
                *(unsigned int*)ProcessInformation=TRUE;
        }
        else if(ProcessInformationClass==ProcessDebugPort)
        {
            Log("[TITANHIDE] ProcessDebugPort by %d\n", pid);
            if(HiderIsHidden(pid, HideProcessDebugPort))
                *(ULONG_PTR*)ProcessInformation=0;
        }
        else if(ProcessInformationClass==ProcessDebugObjectHandle)
        {
            Log("[TITANHIDE] ProcessDebugObjectHandle by %d\n", pid);
            if(HiderIsHidden(pid, HideProcessDebugObjectHandle))
            {
                //Taken from: http://newgre.net/idastealth
                ret=STATUS_PORT_NOT_SET;
            }
        }
    }
    SSDThook(hNtQueryInformationProcess);
    return ret;
}

int HooksInit()
{
    int hook_count=0;
    hNtQueryInformationProcess=SSDThook(L"NtQueryInformationProcess", (void*)HookNtQueryInformationProcess);
    if(hNtQueryInformationProcess)
        hook_count++;
    hNtQueryObject=SSDThook(L"NtQueryObject", (void*)HookNtQueryObject);
    if(hNtQueryObject)
        hook_count++;
    hNtQuerySystemInformation=SSDThook(L"NtQuerySystemInformation", (void*)HookNtQuerySystemInformation);
    if(hNtQuerySystemInformation)
        hook_count++;
    hNtSetInformationThread=SSDThook(L"NtSetInformationThread", (void*)HookNtSetInformationThread);
    if(hNtSetInformationThread)
        hook_count++;
    hNtClose=SSDThook(L"NtClose", (void*)HookNtClose);
    if(hNtClose)
        hook_count++;
    return hook_count;
}

void HooksFree()
{
    SSDTunhook(hNtQueryInformationProcess, true);
    SSDTunhook(hNtQueryObject, true);
    SSDTunhook(hNtQuerySystemInformation, true);
    SSDTunhook(hNtSetInformationThread, true);
    SSDTunhook(hNtClose, true);
}

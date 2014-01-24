#include "hooks.h"
#include "hooklib.h"
#include "undocumented.h"
#include "ssdt.h"
#include "hider.h"
#include "misc.h"

static HOOK hNtQueryInformationProcess;
static HOOK hNtQueryObject;
static HOOK hNtQuerySystemInformation;

static NTSTATUS NTAPI HookNtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    unhook(hNtQuerySystemInformation);
    NTSTATUS ret=NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    if(NT_SUCCESS(ret) && SystemInformation)
    {
        ULONG pid=(ULONG)PsGetCurrentProcessId();
        if(SystemInformationClass==SystemKernelDebuggerInformation)
        {
            DbgPrint("[TITANHIDE] SystemKernelDebuggerInformation by %d\n", pid);
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
    hook(hNtQuerySystemInformation);
    return ret;
}

static NTSTATUS NTAPI HookNtQueryObject(
    IN HANDLE Handle OPTIONAL,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation OPTIONAL,
    IN ULONG ObjectInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    unhook(hNtQueryObject);
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
                DbgPrint("[TITANHIDE] DebugObject by %d\n", pid);
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
                    DbgPrint("[TITANHIDE] DebugObject by %d\n", pid);
                    if(HiderIsHidden(pid, HideDebugObject))
                        pObjectTypeInfo->TotalNumberOfObjects=0;
                }
                pObjInfoLocation=(unsigned char*)pObjectTypeInfo->TypeName.Buffer;
                pObjInfoLocation+=pObjectTypeInfo->TypeName.MaximumLength;
                duint tmp=((duint)pObjInfoLocation)&-sizeof(void*);
                if((duint)tmp!=(duint)pObjInfoLocation)
                    tmp+=sizeof(void*);
                pObjInfoLocation=((unsigned char*)tmp);
            }
        }
    }
    hook(hNtQueryObject);
    return ret;
}

static NTSTATUS NTAPI HookNtQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength)
{
    unhook(hNtQueryInformationProcess);
    NTSTATUS ret=NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
    if(NT_SUCCESS(ret) && ProcessInformation)
    {
        ULONG pid=GetProcessIDFromProcessHandle(ProcessHandle);

        if(ProcessInformationClass==ProcessDebugFlags)
        {
            DbgPrint("[TITANHIDE] ProcessDebugFlags by %d\n", pid);
            if(HiderIsHidden(pid, HideProcessDebugFlags))
                *(unsigned int*)ProcessInformation=TRUE;
        }
        else if(ProcessInformationClass==ProcessDebugPort)
        {
            DbgPrint("[TITANHIDE] ProcessDebugPort by %d\n", pid);
            if(HiderIsHidden(pid, HideProcessDebugPort))
                *(unsigned int*)ProcessInformation=0;
        }
        else if(ProcessInformationClass==ProcessDebugObjectHandle)
        {
            DbgPrint("[TITANHIDE] ProcessDebugObjectHandle by %d\n", pid);
            if(HiderIsHidden(pid, HideProcessDebugObjectHandle))
                *(unsigned int*)ProcessInformation=0;
        }
    }
    hook(hNtQueryInformationProcess);
    return ret;
}

bool HooksInit()
{
    hNtQueryInformationProcess=hook(L"NtQueryInformationProcess", (void*)HookNtQueryInformationProcess);
    if(!hNtQueryInformationProcess)
        return false;
    hNtQueryObject=hook(SSDTgpa("NtQueryObject"), (void*)HookNtQueryObject);
    if(!hNtQueryObject)
        return false;
    hNtQuerySystemInformation=hook(L"NtQuerySystemInformation", (void*)HookNtQuerySystemInformation);
    if(!hNtQuerySystemInformation)
        return false;
    return true;
}

void HooksFree()
{
    unhook(hNtQueryInformationProcess, true);
    unhook(hNtQueryObject, true);
    unhook(hNtQuerySystemInformation, true);
}

#include "hooks.h"
#include "hooklib.h"
#include "undocumented.h"
#include "ssdt.h"
#include "hider.h"
#include "misc.h"
#include "pe.h"

static HOOK hNtQueryInformationProcess=0;
static HOOK hNtQueryObject=0;
static HOOK hNtQuerySystemInformation=0;
static HOOK hNtClose=0;
static HOOK hKeRaiseUserException=0;
static HOOK hNtSetInformationThread=0;
static HOOK hNtSetInformationProcess=0;

static bool bNtClose=false;

static NTSTATUS NTAPI HookNtSetInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    IN PVOID ProcessInformation,
    IN ULONG ProcessInformationLength)
{
    unhook(hNtSetInformationProcess);
    NTSTATUS ret=NtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
    
    ULONG pid=GetProcessIDFromProcessHandle(ProcessHandle);

    if(ProcessInformationClass==ProcessDebugFlags)
    {
        DbgPrint("[TITANHIDE] SetProcessDebugFlags by %d\n", pid);
        if(HiderIsHidden(pid, HideProcessDebugFlags))
            *(unsigned int*)ProcessInformation=TRUE;
    }
    else if(ProcessInformationClass==ProcessDebugPort)
    {
        DbgPrint("[TITANHIDE] SetProcessDebugPort by %d\n", pid);
        if(HiderIsHidden(pid, HideProcessDebugPort))
            *(unsigned int*)ProcessInformation=0;
    }
    else if(ProcessInformationClass==ProcessDebugObjectHandle)
    {
        DbgPrint("[TITANHIDE] SetProcessDebugObjectHandle by %d\n", pid);
        if(HiderIsHidden(pid, HideProcessDebugObjectHandle))
        {
            *(unsigned int*)ProcessInformation=0;
            //Taken from: http://newgre.net/idastealth
            ret=STATUS_PORT_NOT_SET;
        }
    }
    hook(hNtSetInformationProcess);
    return ret;
}

static NTSTATUS NTAPI HookNtSetInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID ThreadInformation,
    IN ULONG ThreadInformationLength)
{
    if(ThreadInformationClass==ThreadHideFromDebugger)
    {
        ULONG pid=(ULONG)PsGetCurrentProcessId();
        DbgPrint("[TITANHIDE] ThreadHideFromDebugger by %d\n", pid);
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
    unhook(hNtSetInformationThread);
    NTSTATUS ret=NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
    hook(hNtSetInformationThread);
    return ret;
}

static NTSTATUS NTAPI HookKeRaiseUserException(
    IN NTSTATUS ExceptionCode)
{
    if(bNtClose && (ExceptionCode==STATUS_HANDLE_NOT_CLOSABLE || ExceptionCode==STATUS_INVALID_HANDLE))
    {
        ULONG pid=(ULONG)PsGetCurrentProcessId();
        DbgPrint("[TITANHIDE] NtClose by %d\n", pid);
        if(HiderIsHidden(pid, HideNtClose))
        {
            return ExceptionCode;
        }
    }
    unhook(hKeRaiseUserException);
    NTSTATUS ret=KeRaiseUserException(ExceptionCode);
    hook(hKeRaiseUserException);
    return ret;
}

static NTSTATUS NTAPI HookNtClose(
    IN HANDLE Handle)
{
    unhook(hNtClose);
    bNtClose=true;
    NTSTATUS ret=NtClose(Handle);
    bNtClose=false;
    hook(hNtClose);
    return ret;
}

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
    typedef NTSTATUS (NTAPI *NTQUERYOBJECT) (
        IN HANDLE Handle OPTIONAL,
        IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
        OUT PVOID ObjectInformation OPTIONAL,
        IN ULONG ObjectInformationLength,
        OUT PULONG ReturnLength OPTIONAL
    );
    static NTQUERYOBJECT NtQO=(NTQUERYOBJECT)hNtQueryObject->old;
    NTSTATUS ret=NtQO(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
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
            {
                *(unsigned int*)ProcessInformation=0;
                //Taken from: http://newgre.net/idastealth
                ret=STATUS_PORT_NOT_SET;
            }
        }
    }
    hook(hNtQueryInformationProcess);
    return ret;
}

static PVOID FindCaveAddress(PVOID CodeStart, ULONG CodeSize, int CaveSize)
{
    unsigned char* Code=(unsigned char*)CodeStart;

    for(unsigned int i=0,j=0; i<CodeSize; i++)
    {
        if(Code[i]==0x90 || Code[i]==0xCC)
            j++;
        else
            j=0;
        if(j==CaveSize)
            return (PVOID)((duint)CodeStart+i-CaveSize+1);
    }
    return 0;
}

int HooksInit()
{
    /*int hook_count=0;
    hNtQueryInformationProcess=hook(L"NtQueryInformationProcess", (void*)HookNtQueryInformationProcess);
    if(hNtQueryInformationProcess)
        hook_count++;
    hNtQueryObject=hook(L"NtQueryObject", (void*)HookNtQueryObject);
    if(hNtQueryObject)
        hook_count++;
    hNtQuerySystemInformation=hook(L"NtQuerySystemInformation", (void*)HookNtQuerySystemInformation);
    if(hNtQuerySystemInformation)
        hook_count++;
    hNtClose=hook(L"NtClose", (void*)HookNtClose);
    if(hNtClose)
        hook_count++;
    hKeRaiseUserException=hook(L"KeRaiseUserException", (void*)HookKeRaiseUserException);
    if(hKeRaiseUserException)
        hook_count++;
    hNtSetInformationThread=hook(L"NtSetInformationThread", (void*)HookNtSetInformationThread);
    if(hNtSetInformationThread)
        hook_count++;
    hNtSetInformationProcess=hook(L"NtSetInformationProcess", (void*)HookNtSetInformationProcess);
    if(hNtSetInformationProcess)
        hook_count++;*/
    PVOID NtQO=SSDTgpa(L"NtQueryObject");
    if(!NtQO)
        return 0;
    static ULONG CodeSize=0;
    static PVOID CodeStart=0;
    if(!CodeStart)
    {
        duint Lowest=(duint)SSDTfind();
        duint Highest=Lowest+0x0FFFFFFF;
        DbgPrint("[TITANHIDE] Range: 0x%p-0x%p\n", Lowest, Highest);
        CodeSize=0;
        CodeStart=PeGetPageBase(KernelGetModuleBase("ntoskrnl"), &CodeSize, NtQO);
        if(!CodeStart || !CodeSize)
        {
            DbgPrint("[TITANHIDE] PeGetPageBase failed...\n");
            return 0;
        }
        DbgPrint("[TITANHIDE] CodeStart: 0x%p, CodeSize: 0x%X\n", CodeStart, CodeSize);
        if((duint)CodeStart<Lowest) //start of the page is out of range
        {
            CodeSize-=Lowest-(duint)CodeStart;
            CodeStart=(PVOID)Lowest;
            DbgPrint("[TITANHIDE] CodeStart: 0x%p, CodeSize: 0x%X\n", CodeStart, CodeSize);
        }
        DbgPrint("[TITANHIDE] Range: 0x%p-0x%p\n", CodeStart, (duint)CodeStart+CodeSize);
        /*ULONG NewSize=(duint)NtQO-(duint)CodeStart;
        CodeStart=NtQO;
        CodeSize=NewSize;
        DbgPrint("[TITANHIDE] Range: 0x%p-0x%p\n", CodeStart, (duint)CodeStart+CodeSize);*/
    }
    PVOID CaveAddress=FindCaveAddress(CodeStart, CodeSize, 12);
    if(!CaveAddress)
    {
        DbgPrint("[TITANHIDE] FindCaveAddress failed...\n");
        return 0;
    }
    DbgPrint("[TITANHIDE] CaveAddress: 0x%p\n", CaveAddress);

    hNtQueryObject=hook(CaveAddress, (void*)HookNtQueryObject);
    if(!hNtQueryObject)
        return 0;

    hNtQueryObject->old=SSDThook(L"NtQueryObject", CaveAddress);
    DbgPrint("[TITANHIDE] Original: 0x%p\n", hNtQueryObject->old);
    
    return 0;
}

void HooksFree()
{
    //unhook(hNtQueryInformationProcess, true);
    if(hNtQueryObject && hNtQueryObject->old)
        SSDThook(L"NtQueryObject", hNtQueryObject->old);
    unhook(hNtQueryObject, true);
    /*unhook(hNtQuerySystemInformation, true);
    unhook(hNtClose, true);
    unhook(hKeRaiseUserException, true);
    unhook(hNtSetInformationThread, true);
    unhook(hNtSetInformationProcess, true);*/
}

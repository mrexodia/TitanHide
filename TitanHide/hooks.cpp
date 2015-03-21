#include "hooks.h"
#include "undocumented.h"
#include "ssdt.h"
#include "hider.h"
#include "misc.h"
#include "pe.h"
#include "log.h"
#include "debugport.h"

static HOOK hNtQueryInformationProcess = 0;
static HOOK hNtQueryObject = 0;
static HOOK hNtQuerySystemInformation = 0;
static HOOK hNtClose = 0;
static HOOK hNtSetInformationThread = 0;
static HOOK hNtSetContextThread = 0;

static NTSTATUS NTAPI HookNtSetInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	IN PVOID ThreadInformation,
	IN ULONG ThreadInformationLength)
{
	//Bug found by Aguila, thanks!
	if (ThreadInformationClass == ThreadHideFromDebugger && !ThreadInformation && !ThreadInformationLength)
	{
		ULONG pid = (ULONG)PsGetCurrentProcessId();
		if (Hider::IsHidden(pid, HideThreadHideFromDebugger))
		{
			Log("[TITANHIDE] ThreadHideFromDebugger by %d\n", pid);
			//Taken from: http://newgre.net/idastealth
			PKTHREAD Object;
			NTSTATUS status = ObReferenceObjectByHandle(ThreadHandle, 0, NULL, KernelMode, (PVOID*)&Object, NULL);
			if (NT_SUCCESS(status))
			{
				ObDereferenceObject(Object);
				return STATUS_SUCCESS;
			}
			else
				return status;
		}
	}
	return Undocumented::NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

static NTSTATUS NTAPI HookNtClose(
	IN HANDLE Handle)
{
	ULONG pid = (ULONG)PsGetCurrentProcessId();
	NTSTATUS ret;
	if (Hider::IsHidden(pid, HideNtClose))
	{
		PVOID OldDebugPort = DebugPort::Set(PsGetCurrentProcess(), 0);
		ret = Undocumented::NtClose(Handle);
		if (!NT_SUCCESS(ret))
			Log("[TITANHIDE] NtClose(0x%p) by %d\n", Handle, pid);
		DebugPort::Set(PsGetCurrentProcess(), OldDebugPort);
	}
	else
		ret = Undocumented::NtClose(Handle);
	return ret;
}

static NTSTATUS NTAPI HookNtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	NTSTATUS ret = Undocumented::NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if (NT_SUCCESS(ret) && SystemInformation)
	{
		ULONG pid = (ULONG)PsGetCurrentProcessId();
		if (SystemInformationClass == SystemKernelDebuggerInformation)
		{
			if (Hider::IsHidden(pid, HideSystemDebuggerInformation))
			{
				Log("[TITANHIDE] SystemKernelDebuggerInformation by %d\n", pid);
				typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
				{
					BOOLEAN DebuggerEnabled;
					BOOLEAN DebuggerNotPresent;
				} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;
				SYSTEM_KERNEL_DEBUGGER_INFORMATION* DebuggerInfo = (SYSTEM_KERNEL_DEBUGGER_INFORMATION*)SystemInformation;
				DebuggerInfo->DebuggerEnabled = false;
				DebuggerInfo->DebuggerNotPresent = true;
			}
		}
	}
	return ret;
}

static NTSTATUS NTAPI HookNtQueryObject(
	IN HANDLE Handle OPTIONAL,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	OUT PVOID ObjectInformation OPTIONAL,
	IN ULONG ObjectInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	NTSTATUS ret = Undocumented::NtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
	if (NT_SUCCESS(ret) && ObjectInformation)
	{
		ULONG pid = (ULONG)PsGetCurrentProcessId();
		UNICODE_STRING DebugObject;
		RtlInitUnicodeString(&DebugObject, L"DebugObject");
		if (ObjectInformationClass == ObjectTypeInformation)
		{
			OBJECT_TYPE_INFORMATION* type = (OBJECT_TYPE_INFORMATION*)ObjectInformation;
			if (RtlEqualUnicodeString(&type->TypeName, &DebugObject, FALSE)) //DebugObject
			{
				if (Hider::IsHidden(pid, HideDebugObject))
				{
					Log("[TITANHIDE] DebugObject by %d\n", pid);
					type->TotalNumberOfObjects = 0;
					type->TotalNumberOfHandles = 0;
				}
			}
		}
		else if (ObjectInformationClass == ObjectAllInformation)
		{
			OBJECT_ALL_INFORMATION* pObjectAllInfo = (OBJECT_ALL_INFORMATION*)ObjectInformation;
			unsigned char* pObjInfoLocation = (unsigned char*)pObjectAllInfo->ObjectTypeInformation;
			unsigned int TotalObjects = pObjectAllInfo->NumberOfObjects;
			for (unsigned int i = 0; i < TotalObjects; i++)
			{
				OBJECT_TYPE_INFORMATION* pObjectTypeInfo = (OBJECT_TYPE_INFORMATION*)pObjInfoLocation;
				if (RtlEqualUnicodeString(&pObjectTypeInfo->TypeName, &DebugObject, FALSE)) //DebugObject
				{
					if (Hider::IsHidden(pid, HideDebugObject))
					{
						Log("[TITANHIDE] DebugObject by %d\n", pid);
						pObjectTypeInfo->TotalNumberOfObjects = 0;
						//Bug found by Aguila, thanks!
						pObjectTypeInfo->TotalNumberOfHandles = 0;
					}
				}
				pObjInfoLocation = (unsigned char*)pObjectTypeInfo->TypeName.Buffer;
				pObjInfoLocation += pObjectTypeInfo->TypeName.MaximumLength;
				ULONG_PTR tmp = ((ULONG_PTR)pObjInfoLocation) & -(LONG_PTR)sizeof(void*);
				if ((ULONG_PTR)tmp != (ULONG_PTR)pObjInfoLocation)
					tmp += sizeof(void*);
				pObjInfoLocation = ((unsigned char*)tmp);
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
	NTSTATUS ret = Undocumented::NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
	if (NT_SUCCESS(ret) &&
		ProcessInformation &&
		ProcessInformationClass != ProcessBasicInformation) //prevent stack overflow
	{
		ULONG pid = Misc::GetProcessIDFromProcessHandle(ProcessHandle);

		if (ProcessInformationClass == ProcessDebugFlags)
		{
			if (Hider::IsHidden(pid, HideProcessDebugFlags))
			{
				Log("[TITANHIDE] ProcessDebugFlags by %d\n", pid);
				*(unsigned int*)ProcessInformation = TRUE;
			}
		}
		else if (ProcessInformationClass == ProcessDebugPort)
		{
			if (Hider::IsHidden(pid, HideProcessDebugPort))
			{
				Log("[TITANHIDE] ProcessDebugPort by %d\n", pid);
				*(ULONG_PTR*)ProcessInformation = 0;
			}
		}
		else if (ProcessInformationClass == ProcessDebugObjectHandle)
		{
			if (Hider::IsHidden(pid, HideProcessDebugObjectHandle))
			{
				Log("[TITANHIDE] ProcessDebugObjectHandle by %d\n", pid);
				//Taken from: http://newgre.net/idastealth
				ret = STATUS_PORT_NOT_SET;
			}
		}
	}
	return ret;
}

static NTSTATUS NTAPI HookNtSetContextThread(
	IN HANDLE ThreadHandle,
	IN PCONTEXT Context)
{
	ULONG pid = (ULONG)PsGetCurrentProcessId();
	bool IsHidden = Hider::IsHidden(pid, HideNtSetContextThread);
	ULONG OriginalContextFlags = 0;
	if (IsHidden)
	{
		Log("[TITANHIDE] NtSetContextThread by %d\n", pid);
		__try
		{
			ProbeForRead(&Context->ContextFlags, sizeof(ULONG), 1);
			OriginalContextFlags = Context->ContextFlags;
			ULONG NewContextFlags = OriginalContextFlags & ~0x10; //CONTEXT_DEBUG_REGISTERS ^ CONTEXT_AMD64/CONTEXT_i386
			RtlSuperCopyMemory(&Context->ContextFlags, &NewContextFlags, sizeof(ULONG));
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return Undocumented::NtSetContextThread(ThreadHandle, Context);
		}
	}
	NTSTATUS ret = Undocumented::NtSetContextThread(ThreadHandle, Context);
	if (IsHidden)
	{
		__try
		{
			ProbeForRead(&Context->ContextFlags, sizeof(ULONG), 1);
			RtlSuperCopyMemory(&Context->ContextFlags, &OriginalContextFlags, sizeof(ULONG));
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}
	}
	return ret;
}

int Hooks::Initialize()
{
	int hook_count = 0;
	hNtQueryInformationProcess = SSDT::Hook("NtQueryInformationProcess", (void*)HookNtQueryInformationProcess);
	if (hNtQueryInformationProcess)
		hook_count++;
	hNtQueryObject = SSDT::Hook("NtQueryObject", (void*)HookNtQueryObject);
	if (hNtQueryObject)
		hook_count++;
	hNtQuerySystemInformation = SSDT::Hook("NtQuerySystemInformation", (void*)HookNtQuerySystemInformation);
	if (hNtQuerySystemInformation)
		hook_count++;
	hNtSetInformationThread = SSDT::Hook("NtSetInformationThread", (void*)HookNtSetInformationThread);
	if (hNtSetInformationThread)
		hook_count++;
	hNtClose = SSDT::Hook("NtClose", (void*)HookNtClose);
	if (hNtClose)
		hook_count++;
	hNtSetContextThread = SSDT::Hook("NtSetContextThread", (void*)HookNtSetContextThread);
	if (hNtSetContextThread)
		hook_count++;
	return hook_count;
}

void Hooks::Deinitialize()
{
	SSDT::Unhook(hNtQueryInformationProcess, true);
	SSDT::Unhook(hNtQueryObject, true);
	SSDT::Unhook(hNtQuerySystemInformation, true);
	SSDT::Unhook(hNtSetInformationThread, true);
	SSDT::Unhook(hNtClose, true);
	SSDT::Unhook(hNtSetContextThread, true);
}

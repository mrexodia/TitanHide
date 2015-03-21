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

typedef NTSTATUS(NTAPI* ZWQUERYINFORMATIONTHREAD)(
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

static ZWQUERYINFORMATIONPROCESS ZwQIP = 0;
static ZWQUERYINFORMATIONTHREAD ZwQIT = 0;
static NTQUERYOBJECT NtQO = 0;
static ZWQUERYSYSTEMINFORMATION ZwQSI = 0;
static NTQUERYSYSTEMINFORMATION NtQSI = 0;
static NTCLOSE NtClo = 0;
static NTSETCONTEXTTHREAD NtSCT = 0;
static NTCONTINUE NtCon = 0;
static NTDUPLICATEOBJECT NtDO = 0;
static KERAISEUSEREXCEPTION KeRUE = 0;
static NTSETINFORMATIONTHREAD NtSIT = 0;
static NTSETINFORMATIONPROCESS NtSIP = 0;
static NTQUERYINFORMATIONPROCESS NtQIP = 0;

NTSTATUS NTAPI Undocumented::ZwQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	return ZwQIP(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

NTSTATUS NTAPI Undocumented::ZwQueryInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	IN OUT PVOID ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	return ZwQIT(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
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

bool Undocumented::UndocumentedInit()
{
	//Exported kernel functions after this
	if (!ZwQIP)
	{
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
		ZwQIP = (ZWQUERYINFORMATIONPROCESS)MmGetSystemRoutineAddress(&routineName);
		if (!ZwQIP)
			return false;
	}
	if (!ZwQIT)
	{
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"ZwQueryInformationThread");
		ZwQIT = (ZWQUERYINFORMATIONTHREAD)MmGetSystemRoutineAddress(&routineName);
		if (!ZwQIT)
			return false;
	}
	if (!ZwQSI)
	{
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"ZwQuerySystemInformation");
		ZwQSI = (ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&routineName);
		if (!ZwQSI)
			return false;
	}
	if (!NtQSI)
	{
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"NtQuerySystemInformation");
		NtQSI = (NTQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&routineName);
		if (!NtQSI)
			return false;
	}
	if (!NtClo)
	{
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"NtClose");
		NtClo = (NTCLOSE)MmGetSystemRoutineAddress(&routineName);
		if (!NtClo)
			return false;
	}
	if (!NtDO)
	{
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"NtDuplicateObject");
		NtDO = (NTDUPLICATEOBJECT)MmGetSystemRoutineAddress(&routineName);
		if (!NtDO)
			return false;
	}
	if (!KeRUE)
	{
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"KeRaiseUserException");
		KeRUE = (KERAISEUSEREXCEPTION)MmGetSystemRoutineAddress(&routineName);
		if (!KeRUE)
			return false;
	}
	if (!NtSIT)
	{
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"NtSetInformationThread");
		NtSIT = (NTSETINFORMATIONTHREAD)MmGetSystemRoutineAddress(&routineName);
		if (!NtSIT)
			return false;
	}
	if (!NtSIP)
	{
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"NtSetInformationProcess");
		NtSIP = (NTSETINFORMATIONPROCESS)MmGetSystemRoutineAddress(&routineName);
		if (!NtSIP)
			return false;
	}
	if (!NtQIP)
	{
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"NtQueryInformationProcess");
		NtQIP = (NTQUERYINFORMATIONPROCESS)MmGetSystemRoutineAddress(&routineName);
		if (!NtQIP)
			return false;
	}
	//SSDT-only functions after this
	if (!NtQO)
	{
		NtQO = (NTQUERYOBJECT)SSDT::GetFunctionAddress("NtQueryObject");
		if (!NtQO)
			return false;
	}
	if (!NtSCT)
	{
		NtSCT = (NTSETCONTEXTTHREAD)SSDT::GetFunctionAddress("NtSetContextThread");
		if (!NtSCT)
			return false;
	}
	if (!NtCon)
	{
		NtCon = (NTCONTINUE)SSDT::GetFunctionAddress("NtContinue");
		if (!NtCon)
			return false;
	}
	return true;
}

//Based on: http://alter.org.ua/docs/nt_kernel/procaddr
static PVOID KernelGetModuleBase(PCHAR pModuleName)
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

#pragma warning(disable:4200)
	typedef struct _SYSTEM_MODULE_INFORMATION
	{
		ULONG Count;
		SYSTEM_MODULE_ENTRY Module[0];
	} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

	PVOID pModuleBase = NULL;
	PULONG pSystemInfoBuffer = NULL;

	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
	ULONG    SystemInfoBufferSize = 0;

	status = Undocumented::ZwQuerySystemInformation(SystemModuleInformation,
		&SystemInfoBufferSize,
		0,
		&SystemInfoBufferSize);

	if (!SystemInfoBufferSize)
	{
		Log("[TITANHIDE] ZwQuerySystemInformation (1) failed...\n");
		return NULL;
	}

	pSystemInfoBuffer = (PULONG)ExAllocatePool(NonPagedPool, SystemInfoBufferSize * 2);

	if (!pSystemInfoBuffer)
	{
		Log("[TITANHIDE] ExAllocatePool failed...\n");
		return NULL;
	}

	memset(pSystemInfoBuffer, 0, SystemInfoBufferSize * 2);

	status = Undocumented::ZwQuerySystemInformation(SystemModuleInformation,
		pSystemInfoBuffer,
		SystemInfoBufferSize * 2,
		&SystemInfoBufferSize);

	if (NT_SUCCESS(status))
	{
		PSYSTEM_MODULE_ENTRY pSysModuleEntry = ((PSYSTEM_MODULE_INFORMATION)(pSystemInfoBuffer))->Module;
		ULONG len = (ULONG)strlen(pModuleName);
		for (ULONG i = 0; i < ((PSYSTEM_MODULE_INFORMATION)(pSystemInfoBuffer))->Count; i++)
		{
			if (_strnicmp(pSysModuleEntry[i].ImageName + pSysModuleEntry[i].ModuleNameOffset, pModuleName, len) == 0)
			{
				pModuleBase = pSysModuleEntry[i].Base;
				break;
			}
		}
	}
	else
		Log("[TITANHIDE] ZwQuerySystemInformation (2) failed...\n");

	if (pSystemInfoBuffer)
	{
		ExFreePool(pSystemInfoBuffer);
	}

	return pModuleBase;
}

//Code by Nukem: https://bitbucket.org/Nukem9/virtualdbghide
static PVOID GetNtoskrnlBase()
{
	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, L"DbgPrint");
	ULONG_PTR addr = (ULONG_PTR)MmGetSystemRoutineAddress(&routineName);
	addr = (addr & ~(PAGE_SIZE - 1));
	__try
	{
		while ((*(USHORT *)addr != IMAGE_DOS_SIGNATURE))
			addr -= PAGE_SIZE;
		return (PVOID)addr;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return 0;
}

PVOID Undocumented::GetKernelBase()
{
	PVOID base = GetNtoskrnlBase();
	if (!base)
		base = KernelGetModuleBase("ntoskrnl");
	if (!base)
		base = KernelGetModuleBase("ntkrnlmp");
	if (!base)
		base = KernelGetModuleBase("ntkrnlpa");
	if (!base)
		base = KernelGetModuleBase("ntkrpamp");
	return base;
}

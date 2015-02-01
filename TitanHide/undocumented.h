#ifndef _UNDOCUMENTED_H
#define _UNDOCUMENTED_H

#include "_global.h"

//structures
typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfHandles;
	ULONG TotalNumberOfObjects;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_ALL_INFORMATION
{
	ULONG NumberOfObjects;
	OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];
} OBJECT_ALL_INFORMATION, *POBJECT_ALL_INFORMATION;

//enums
typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllInformation,
	ObjectDataInformation
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemModuleInformation = 11,
	SystemKernelDebuggerInformation = 35
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

class Undocumented
{
public:
	static NTSTATUS NTAPI ZwQueryInformationProcess(
		IN HANDLE ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN ULONG ProcessInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

	static NTSTATUS NTAPI ZwQueryInformationThread(
		IN HANDLE ThreadHandle,
		IN THREADINFOCLASS ThreadInformationClass,
		IN OUT PVOID ThreadInformation,
		IN ULONG ThreadInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

	static NTSTATUS NTAPI NtQueryObject(
		IN HANDLE Handle OPTIONAL,
		IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
		OUT PVOID ObjectInformation OPTIONAL,
		IN ULONG ObjectInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

	static NTSTATUS NTAPI ZwQuerySystemInformation(
		IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
		OUT PVOID SystemInformation,
		IN ULONG SystemInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

	static NTSTATUS NTAPI NtQuerySystemInformation(
		IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
		OUT PVOID SystemInformation,
		IN ULONG SystemInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

	static NTSTATUS NTAPI NtClose(
		IN HANDLE Handle);

	static NTSTATUS NTAPI NtSetContextThread(
		IN HANDLE ThreadHandle,
		IN PCONTEXT Context);

	static NTSTATUS NTAPI NtContinue(
		IN PCONTEXT Context,
		BOOLEAN RaiseAlert);

	static NTSTATUS NTAPI NtDuplicateObject(
		IN HANDLE SourceProcessHandle,
		IN HANDLE SourceHandle,
		IN HANDLE TargetProcessHandle,
		OUT PHANDLE TargetHandle,
		IN ACCESS_MASK DesiredAccess OPTIONAL,
		IN ULONG HandleAttributes,
		IN ULONG Options);

	static NTSTATUS NTAPI KeRaiseUserException(
		IN NTSTATUS ExceptionCode);

	static NTSTATUS NTAPI NtSetInformationThread(
		IN HANDLE ThreadHandle,
		IN THREADINFOCLASS ThreadInformationClass,
		IN PVOID ThreadInformation,
		IN ULONG ThreadInformationLength);

	static NTSTATUS NTAPI NtSetInformationProcess(
		IN HANDLE ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		IN PVOID ProcessInformation,
		IN ULONG ProcessInformationLength);

	static NTSTATUS NTAPI NtQueryInformationProcess(
		IN HANDLE ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN ULONG ProcessInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

	static bool UndocumentedInit();
	static PVOID GetKernelBase();
};

#endif

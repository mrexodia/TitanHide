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
    ObjectTypeInformation = 2,
    ObjectTypesInformation = 3
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemModuleInformation = 11,
    SystemKernelDebuggerInformation = 35
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef enum _SYSDBG_COMMAND
{
    SysDbgGetTriageDump = 29,
} SYSDBG_COMMAND, *PSYSDBG_COMMAND;

// WOW64_CONTEXT is not undocumented, but it's missing from the WDK
#define WOW64_SIZE_OF_80387_REGISTERS 80
#define WOW64_MAXIMUM_SUPPORTED_EXTENSION 512

typedef struct _WOW64_FLOATING_SAVE_AREA
{
    ULONG ControlWord;
    ULONG StatusWord;
    ULONG TagWord;
    ULONG ErrorOffset;
    ULONG ErrorSelector;
    ULONG DataOffset;
    ULONG DataSelector;
    UCHAR RegisterArea[WOW64_SIZE_OF_80387_REGISTERS];
    ULONG Cr0NpxState;
} WOW64_FLOATING_SAVE_AREA, *PWOW64_FLOATING_SAVE_AREA;

#pragma pack(push, 4)

typedef struct _WOW64_CONTEXT
{
    ULONG ContextFlags;

    ULONG Dr0;
    ULONG Dr1;
    ULONG Dr2;
    ULONG Dr3;
    ULONG Dr6;
    ULONG Dr7;

    WOW64_FLOATING_SAVE_AREA FloatSave;

    ULONG SegGs;
    ULONG SegFs;
    ULONG SegEs;
    ULONG SegDs;

    ULONG Edi;
    ULONG Esi;
    ULONG Ebx;
    ULONG Edx;
    ULONG Ecx;
    ULONG Eax;

    ULONG Ebp;
    ULONG Eip;
    ULONG SegCs;
    ULONG EFlags;
    ULONG Esp;
    ULONG SegSs;

    UCHAR ExtendedRegisters[WOW64_MAXIMUM_SUPPORTED_EXTENSION];

} WOW64_CONTEXT;

typedef WOW64_CONTEXT* PWOW64_CONTEXT;

#pragma pack(pop)

// This is in ntifs.h, but some say Alan Turing died trying to parse that file
extern "C"
NTKERNELAPI
NTSTATUS
ObQueryObjectAuditingByHandle(
    _In_ HANDLE Handle,
    _Out_ PBOOLEAN GenerateOnClose
);

extern "C"
NTKERNELAPI
BOOLEAN
ObFindHandleForObject(
    _In_ PEPROCESS Process,
    _In_opt_ PVOID Object,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_opt_ POBJECT_HANDLE_INFORMATION MatchCriteria,
    _Out_ PHANDLE Handle
);

extern "C"
NTKERNELAPI
PVOID
PsGetProcessDebugPort(
    _In_ PEPROCESS Process
);

extern "C"
NTKERNELAPI
PEPROCESS
PsGetThreadProcess(
    _In_ PETHREAD Thread
);

class Undocumented
{
public:
    static NTSTATUS NTAPI ZwQueryInformationProcess(
        IN HANDLE ProcessHandle,
        IN PROCESSINFOCLASS ProcessInformationClass,
        OUT PVOID ProcessInformation,
        IN ULONG ProcessInformationLength,
        OUT PULONG ReturnLength OPTIONAL);

    static NTSTATUS NTAPI NtQueryInformationThread(
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

    static NTSTATUS NTAPI NtGetContextThread(
        IN HANDLE ThreadHandle,
        IN OUT PCONTEXT Context);

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

    static NTSTATUS NTAPI NtSystemDebugControl(
        IN SYSDBG_COMMAND Command,
        IN PVOID InputBuffer OPTIONAL,
        IN ULONG InputBufferLength OPTIONAL,
        OUT PVOID OutputBuffer,
        IN ULONG OutputBufferLength,
        OUT PULONG ReturnLength OPTIONAL);

    static bool UndocumentedInit();
    static PVOID GetKernelBase(PULONG pImageSize = NULL);
};

#endif

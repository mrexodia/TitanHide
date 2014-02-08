#include "eprocess.h"
#include <windef.h>

#ifndef _WIN64

typedef struct _DISPATCHER_HEADER_
{
    union
    {
        struct
        {
            UCHAR Type;
            union
            {
                UCHAR Abandoned;
                UCHAR Absolute;
                UCHAR NpxIrql;
                UCHAR Signalling;
            };
            union
            {
                UCHAR Size;
                UCHAR Hand;
            };
            union
            {
                UCHAR Inserted;
                UCHAR DebugActive;
                UCHAR DpcActive;
            };
        };
        LONG Lock;
    };
    LONG SignalState;
    LIST_ENTRY WaitListHead;
} DISPATCHER_HEADER_, *PDISPATCHER_HEADER_;

typedef struct _KEXECUTE_OPTIONS_
{
    ULONG ExecuteDisable: 1;
    ULONG ExecuteEnable: 1;
    ULONG DisableThunkEmulation: 1;
    ULONG Permanent: 1;
    ULONG ExecuteDispatchEnable: 1;
    ULONG ImageDispatchEnable: 1;
    ULONG Spare: 2;
} KEXECUTE_OPTIONS_, *PKEXECUTE_OPTIONS_;

typedef struct _KGDTENTRY_
{
    WORD LimitLow;
    WORD BaseLow;
    ULONG HighWord;
} KGDTENTRY_, *PKGDTENTRY_;

typedef struct _KIDTENTRY_
{
    WORD Offset;
    WORD Selector;
    WORD Access;
    WORD ExtendedOffset;
} KIDTENTRY_, *PKIDTENTRY_;

typedef struct _KPROCESS_
{
    DISPATCHER_HEADER_ Header;
    LIST_ENTRY ProfileListHead;
    ULONG DirectoryTableBase;
    ULONG Unused0;
    KGDTENTRY_ LdtDescriptor;
    KIDTENTRY_ Int21Descriptor;
    WORD IopmOffset;
    UCHAR Iopl;
    UCHAR Unused;
    ULONG ActiveProcessors;
    ULONG KernelTime;
    ULONG UserTime;
    LIST_ENTRY ReadyListHead;
    SINGLE_LIST_ENTRY SwapListEntry;
    PVOID VdmTrapcHandler;
    LIST_ENTRY ThreadListHead;
    ULONG ProcessLock;
    ULONG Affinity;
    union
    {
        ULONG AutoAlignment: 1;
        ULONG DisableBoost: 1;
        ULONG DisableQuantum: 1;
        ULONG ReservedFlags: 29;
        LONG ProcessFlags;
    };
    CHAR BasePriority;
    CHAR QuantumReset;
    UCHAR State;
    UCHAR ThreadSeed;
    UCHAR PowerState;
    UCHAR IdealNode;
    UCHAR Visited;
    union
    {
        KEXECUTE_OPTIONS_ Flags;
        UCHAR ExecuteOptions;
    };
    ULONG StackCount;
    LIST_ENTRY ProcessListEntry;
    UINT64 CycleTime;
} KPROCESS_, *PKPROCESS_;

typedef struct _EX_PUSH_LOCK_
{
    union
    {
        ULONG Locked: 1;
        ULONG Waiting: 1;
        ULONG Waking: 1;
        ULONG MultipleShared: 1;
        ULONG Shared: 28;
        ULONG Value;
        PVOID Ptr;
    };
} EX_PUSH_LOCK_, *PEX_PUSH_LOCK_;

typedef struct _EX_RUNDOWN_REF_
{
    union
    {
        ULONG Count;
        PVOID Ptr;
    };
} EX_RUNDOWN_REF_, *PEX_RUNDOWN_REF_;

typedef struct _EPROCESS_
{
    KPROCESS_ Pcb;
    EX_PUSH_LOCK_ ProcessLock;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;
    EX_RUNDOWN_REF_ RundownProtect;
    PVOID UniqueProcessId;
    LIST_ENTRY ActiveProcessLinks;
    ULONG QuotaUsage[3];
    ULONG QuotaPeak[3];
    ULONG CommitCharge;
    ULONG PeakVirtualSize;
    ULONG VirtualSize;
    LIST_ENTRY SessionProcessLinks;
    PVOID DebugPort;
    /*union //structure end
    {
        PVOID ExceptionPortData;
        ULONG ExceptionPortValue;
        ULONG ExceptionPortState: 3;
    };
    PHANDLE_TABLE ObjectTable;
    EX_FAST_REF Token;
    ULONG WorkingSetPage;
    EX_PUSH_LOCK AddressCreationLock;
    PETHREAD RotateInProgress;
    PETHREAD ForkInProgress;
    ULONG HardwareTrigger;
    PMM_AVL_TABLE PhysicalVadRoot;
    PVOID CloneRoot;
    ULONG NumberOfPrivatePages;
    ULONG NumberOfLockedPages;
    PVOID Win32Process;
    PEJOB Job;
    PVOID SectionObject;
    PVOID SectionBaseAddress;
    _EPROCESS_QUOTA_BLOCK * QuotaBlock;
    _PAGEFAULT_HISTORY * WorkingSetWatch;
    PVOID Win32WindowStation;
    PVOID InheritedFromUniqueProcessId;
    PVOID LdtInformation;
    PVOID VadFreeHint;
    PVOID VdmObjects;
    PVOID DeviceMap;
    PVOID EtwDataSource;
    PVOID FreeTebHint;
    union
    {
        HARDWARE_PTE PageDirectoryPte;
        UINT64 Filler;
    };
    PVOID Session;
    UCHAR ImageFileName[16];
    LIST_ENTRY JobLinks;
    PVOID LockedPagesList;
    LIST_ENTRY ThreadListHead;
    PVOID SecurityPort;
    PVOID PaeTop;
    ULONG ActiveThreads;
    ULONG ImagePathHash;
    ULONG DefaultHardErrorProcessing;
    LONG LastThreadExitStatus;
    PPEB Peb;
    EX_FAST_REF PrefetchTrace;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    ULONG CommitChargeLimit;
    ULONG CommitChargePeak;
    PVOID AweInfo;
    SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;
    MMSUPPORT Vm;
    LIST_ENTRY MmProcessLinks;
    ULONG ModifiedPageCount;
    ULONG Flags2;
    ULONG JobNotReallyActive: 1;
    ULONG AccountingFolded: 1;
    ULONG NewProcessReported: 1;
    ULONG ExitProcessReported: 1;
    ULONG ReportCommitChanges: 1;
    ULONG LastReportMemory: 1;
    ULONG ReportPhysicalPageChanges: 1;
    ULONG HandleTableRundown: 1;
    ULONG NeedsHandleRundown: 1;
    ULONG RefTraceEnabled: 1;
    ULONG NumaAware: 1;
    ULONG ProtectedProcess: 1;
    ULONG DefaultPagePriority: 3;
    ULONG PrimaryTokenFrozen: 1;
    ULONG ProcessVerifierTarget: 1;
    ULONG StackRandomizationDisabled: 1;
    ULONG Flags;
    ULONG CreateReported: 1;
    ULONG NoDebugInherit: 1;
    ULONG ProcessExiting: 1;
    ULONG ProcessDelete: 1;
    ULONG Wow64SplitPages: 1;
    ULONG VmDeleted: 1;
    ULONG OutswapEnabled: 1;
    ULONG Outswapped: 1;
    ULONG ForkFailed: 1;
    ULONG Wow64VaSpace4Gb: 1;
    ULONG AddressSpaceInitialized: 2;
    ULONG SetTimerResolution: 1;
    ULONG BreakOnTermination: 1;
    ULONG DeprioritizeViews: 1;
    ULONG WriteWatch: 1;
    ULONG ProcessInSession: 1;
    ULONG OverrideAddressSpace: 1;
    ULONG HasAddressSpace: 1;
    ULONG LaunchPrefetched: 1;
    ULONG InjectInpageErrors: 1;
    ULONG VmTopDown: 1;
    ULONG ImageNotifyDone: 1;
    ULONG PdeUpdateNeeded: 1;
    ULONG VdmAllowed: 1;
    ULONG SmapAllowed: 1;
    ULONG ProcessInserted: 1;
    ULONG DefaultIoPriority: 3;
    ULONG SparePsFlags1: 2;
    LONG ExitStatus;
    WORD Spare7;
    union
    {
        struct
        {
            UCHAR SubSystemMinorVersion;
            UCHAR SubSystemMajorVersion;
        };
        WORD SubSystemVersion;
    };
    UCHAR PriorityClass;
    MM_AVL_TABLE VadRoot;
    ULONG Cookie;
    ALPC_PROCESS_CONTEXT AlpcContext;*/
} EPROCESS_, *PEPROCESS_;

#else //x64 structs

typedef struct _KEXECUTE_OPTIONS_
{
    union
    {
        ULONG ExecuteDisable: 1;
        ULONG ExecuteEnable: 1;
        ULONG DisableThunkEmulation: 1;
        ULONG Permanent: 1;
        ULONG ExecuteDispatchEnable: 1;
        ULONG ImageDispatchEnable: 1;
        ULONG DisableExceptionChainValdation: 1;
        ULONG Spare: 1;
        UCHAR ExecuteOptions;
    };

} KEXECUTE_OPTIONS_, *PKEXECUTE_OPTIONS_;

typedef struct _KAFFINITY_EX_
{
    USHORT Count;
    USHORT Size;
    ULONG Reserved;
    ULONGLONG Bitmap[4];
} KAFFINITY_EX_,*PKAFFINITY_EX_;

typedef struct _KPROCESS_
{
    DISPATCHER_HEADER Header;
    LIST_ENTRY ProfileListHead;
    ULONGLONG DirectoryTableBase;
    LIST_ENTRY ThreadListHead;
    ULONGLONG ProcessLock;
    KAFFINITY_EX_ Affinity;
    LIST_ENTRY ReadyListHead;
    SINGLE_LIST_ENTRY SwapListEntry;
    KAFFINITY_EX_ ActiveProcessors;
    union
    {
        ULONG AutoAlignment: 1;
        ULONG DisableBoost: 1;
        ULONG DisableQuantum: 1;
        ULONG ActiveGroupMask :4;
        ULONG ReservedFlags: 25;
        LONG ProcessFlags;
    };
    CHAR BasePriority;
    CHAR QuantumReset;
    UCHAR Visited;
    UCHAR Unused3;
    ULONG ThreadSeed[4] ;
    USHORT IdealNode[4] ;
    USHORT IdealGlobalNode;
    KEXECUTE_OPTIONS_ Flags;
    UCHAR Unused1;
    UCHAR Unused2;
    UCHAR Unused4;
    ULONG StackCount;
    LIST_ENTRY ProcessListEntry;
    UINT64 CycleTime;
    ULONG KernelTime;
    ULONG UserTime;
    PVOID InstrumentationCallback;
    ULONGLONG LdtDescriptor[2];
    PVOID LdtBaseAddress;
    KGUARDED_MUTEX LdtProcessLock;
    USHORT LdtFreeSelectorHint;
    USHORT LdtTableLength;
} KPROCESS, *PKPROCESS_;

typedef struct _EPROCESS_
{
    KPROCESS Pcb;
    PVOID ProcessLock; //EX_PUSH_LOCK
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;
    EX_RUNDOWN_REF RundownProtect;
    PVOID UniqueProcessId;
    LIST_ENTRY ActiveProcessLinks;
    ULONGLONG ProcessQuotaUsage[2];
    ULONGLONG ProcessQuotaPeak[2];
    ULONGLONG CommitCharge;
    PVOID QuotaBlock; //_EPROCESS_QUOTA_BLOCK *
    PVOID CpuQuotaBlock; //_PS_CPU_QUOTA_BLOCK
    ULONGLONG PeakVirtualSize;
    ULONGLONG VirtualSize;
    LIST_ENTRY SessionProcessLinks;
    PVOID DebugPort;
    /*
    //union
    //{
    // PVOID ExceptionPortData;
    // ULONG ExceptionPortValue;
    // ULONG ExceptionPortState: 3;
    //};
    PVOID ExceptionPortData;
    PVOID ObjectTable; //PHANDLE_TABLE
    BYTE Token[8]; //EX_FAST_REF
    ULONGLONG WorkingSetPage;
    BYTE AddressCreationLock[8]; //EX_PUSH_LOCK
    PVOID RotateInProgress; //PETHREAD
    PVOID ForkInProgress; //PETHREAD
    ULONGLONG HardwareTrigger;
    PVOID PhysicalVadRoot; //PMM_AVL_TABLE
    PVOID CloneRoot;
    ULONGLONG NumberOfPrivatePages;
    ULONGLONG NumberOfLockedPages;
    PVOID Win32Process;
    PVOID Job; //PEJOB
    PVOID SectionObject;
    PVOID SectionBaseAddress;

    ULONG Cookie;
    ULONG UmsScheduledThreads;
    PVOID WorkingSetWatch; //_PAGEFAULT_HISTORY *
    PVOID Win32WindowStation;
    PVOID InheritedFromUniqueProcessId;
    PVOID LdtInformation;
    PVOID Spare;
    ULONGLONG ConsoleHostProcess;
    PVOID DeviceMap;
    PVOID EtwDataSource;
    PVOID FreeTebHint;
    ULONGLONG PageDirectoryPte;	//_HARDWARE_PTE
    //union
    //{
    // HARDWARE_PTE PageDirectoryPte;
    // UINT64 Filler;
    //};
    PVOID Session;
    UCHAR ImageFileName[15];
    UCHAR PriorityClass;
    LIST_ENTRY JobLinks;
    PVOID LockedPagesList;
    LIST_ENTRY ThreadListHead;
    PVOID SecurityPort;
    PVOID Wow64Process;
    ULONG ActiveThreads;
    ULONG ImagePathHash;
    ULONG DefaultHardErrorProcessing;
    LONG LastThreadExitStatus;
    PPEB Peb;
    BYTE PrefetchTrace[8]; //EX_FAST_REF
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    ULONGLONG CommitChargeLimit;
    ULONGLONG CommitChargePeak;
    PVOID AweInfo;
    SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;
    MMSUPPORT Vm;
    LIST_ENTRY MmProcessLinks;
    PVOID HighestUserAddress;
    ULONG ModifiedPageCount;
    ULONG Flags2;
    ULONG Flags;
    LONG ExitStatus;
    BYTE VadRoot[64]; //_MM_AVL_TABLE
    BYTE AlpcContext[32]; //_ALPC_PROCESS_CONTEXT
    LIST_ENTRY TimerResolutionLink;
    ULONG RequestedTimerResolution;
    ULONG ActiveThreadsHighWatermark;
    ULONG SmallestTimerResolution;
    PVOID TimerResolutionStackRecord;//_PO_DIAG_STACK_RECORD*
    */
} EPROCESS_, *PEPROCESS_;

#endif

PVOID SetDebugPort(PEPROCESS Process, PVOID DebugPort)
{
    PEPROCESS_ Process_=(PEPROCESS_)Process;
    PVOID OldDebugPort=Process_->DebugPort;
    Process_->DebugPort=DebugPort;
    return OldDebugPort;
}

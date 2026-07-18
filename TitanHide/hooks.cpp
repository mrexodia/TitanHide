#include "hooks.h"
#include "undocumented.h"
#include "ssdt.h"
#include "hider.h"
#include "threadhidefromdbg.h"
#include "misc.h"
#include "log.h"

static HOOK hNtQueryInformationProcess = 0;
static HOOK hNtQueryInformationThread = 0;
static HOOK hNtQueryObject = 0;
static HOOK hNtQuerySystemInformation = 0;
static HOOK hNtClose = 0;
static HOOK hNtDuplicateObject = 0;
static HOOK hNtSetInformationThread = 0;
static HOOK hNtGetContextThread = 0;
static HOOK hNtSetContextThread = 0;
static HOOK hNtSystemDebugControl = 0;
static HOOK hNtCreateThreadEx = 0;
static KMUTEX gDebugPortMutex;

struct VIRTUAL_THREAD_HIDE_ENTRY
{
    HANDLE ProcessId;
    PETHREAD Thread;
};

// Retain thread identity so an exited thread queried through an open handle
// keeps its virtual state. Entries are released on unhide/unload and bounded.
#define MAX_VIRTUAL_THREAD_HIDE_ENTRIES 4096
static VIRTUAL_THREAD_HIDE_ENTRY gVirtualThreadHideEntries[MAX_VIRTUAL_THREAD_HIDE_ENTRIES];
static ULONG gVirtualThreadHideEntryCount = 0;
static KSPIN_LOCK gVirtualThreadHideLock;

//https://forum.tuts4you.com/topic/40011-debugme-vmprotect-312-build-886-anti-debug-method-improved/#comment-192824
//https://github.com/x64dbg/ScyllaHide/issues/47
//https://github.com/mrexodia/TitanHide/issues/27
#define BACKUP_RETURNLENGTH() \
    ULONG TempReturnLength = 0; \
    if(ARGUMENT_PRESENT(ReturnLength)) \
    { \
        ProbeForWrite(ReturnLength, sizeof(ULONG), 1); \
        TempReturnLength = *ReturnLength; \
    }

#define RESTORE_RETURNLENGTH() \
    if(ARGUMENT_PRESENT(ReturnLength)) \
        (*ReturnLength) = TempReturnLength

#define OBJ_PROTECT_CLOSE 0x00000001L

static bool RangesOverlap(
    const void* First,
    SIZE_T FirstSize,
    const void* Second,
    SIZE_T SecondSize)
{
    if(First == nullptr || Second == nullptr)
        return false;

    const ULONG_PTR FirstAddress = (ULONG_PTR)First;
    const ULONG_PTR SecondAddress = (ULONG_PTR)Second;
    if(FirstAddress <= SecondAddress)
        return SecondAddress - FirstAddress < FirstSize;
    return FirstAddress - SecondAddress < SecondSize;
}

struct DEBUG_OBJECT_TYPE_SIGNATURE
{
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    UCHAR TypeIndex;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
};

static DEBUG_OBJECT_TYPE_SIGNATURE gDebugObjectTypeSignature = {};
static bool gDebugObjectTypeSignatureValid = false;

static bool TypeFieldMatches(
    const void* Field,
    const void* Expected,
    SIZE_T Size,
    PULONG ReturnLength)
{
    return RangesOverlap(Field, Size, ReturnLength, sizeof(ULONG)) ||
           RtlCompareMemory(Field, Expected, Size) == Size;
}

static bool IsDebugObjectTypeDescriptor(
    const OBJECT_TYPE_INFORMATION* TypeInformation,
    PULONG ReturnLength,
    const DEBUG_OBJECT_TYPE_SIGNATURE* Signature)
{
    if(!gDebugObjectTypeSignatureValid)
        return false;

    return TypeFieldMatches(&TypeInformation->InvalidAttributes,
                            &Signature->InvalidAttributes,
                            sizeof(Signature->InvalidAttributes),
                            ReturnLength) &&
           TypeFieldMatches(&TypeInformation->GenericMapping,
                            &Signature->GenericMapping,
                            sizeof(Signature->GenericMapping),
                            ReturnLength) &&
           TypeFieldMatches(&TypeInformation->ValidAccessMask,
                            &Signature->ValidAccessMask,
                            sizeof(Signature->ValidAccessMask),
                            ReturnLength) &&
           TypeFieldMatches(&TypeInformation->SecurityRequired,
                            &Signature->SecurityRequired,
                            sizeof(Signature->SecurityRequired),
                            ReturnLength) &&
           TypeFieldMatches(&TypeInformation->MaintainHandleCount,
                            &Signature->MaintainHandleCount,
                            sizeof(Signature->MaintainHandleCount),
                            ReturnLength) &&
           TypeFieldMatches(&TypeInformation->TypeIndex,
                            &Signature->TypeIndex,
                            sizeof(Signature->TypeIndex),
                            ReturnLength) &&
           TypeFieldMatches(&TypeInformation->PoolType,
                            &Signature->PoolType,
                            sizeof(Signature->PoolType),
                            ReturnLength) &&
           TypeFieldMatches(&TypeInformation->DefaultPagedPoolCharge,
                            &Signature->DefaultPagedPoolCharge,
                            sizeof(Signature->DefaultPagedPoolCharge),
                            ReturnLength) &&
           TypeFieldMatches(&TypeInformation->DefaultNonPagedPoolCharge,
                            &Signature->DefaultNonPagedPoolCharge,
                            sizeof(Signature->DefaultNonPagedPoolCharge),
                            ReturnLength);
}

static bool IsDebugObjectTypeInformation(
    OBJECT_TYPE_INFORMATION* TypeInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength,
    const UNICODE_STRING* DebugObject,
    const DEBUG_OBJECT_TYPE_SIGNATURE* Signature)
{
    if(ObjectInformationLength < sizeof(OBJECT_TYPE_INFORMATION))
        return false;

    ProbeForRead(TypeInformation, sizeof(OBJECT_TYPE_INFORMATION), 1);
    if(IsDebugObjectTypeDescriptor(TypeInformation, ReturnLength, Signature))
        return true;

    if(ObjectInformationLength < sizeof(OBJECT_TYPE_INFORMATION) + DebugObject->Length ||
            TypeInformation->TypeName.Length != DebugObject->Length)
    {
        return false;
    }

    // NtQueryObject stores the type name directly after the fixed-size structure.
    // Do not use TypeName.Buffer here: ReturnLength is written last by the kernel
    // and callers may deliberately overlap it with that pointer.
    WCHAR* InlineTypeName = (WCHAR*)(TypeInformation + 1);
    if(RangesOverlap(InlineTypeName, DebugObject->Length, ReturnLength, sizeof(ULONG)))
        return false;
    ProbeForRead(InlineTypeName, DebugObject->Length, 1);
    return RtlCompareMemory(InlineTypeName, DebugObject->Buffer, DebugObject->Length) == DebugObject->Length;
}

static void InitializeDebugObjectTypeSignature()
{
    gDebugObjectTypeSignatureValid = false;
    RtlZeroMemory(&gDebugObjectTypeSignature,
                  sizeof(gDebugObjectTypeSignature));

    ULONG BufferSize = 0;
    NTSTATUS Status = ZwQueryObject(
                          nullptr,
                          (OBJECT_INFORMATION_CLASS)ObjectTypesInformation,
                          nullptr,
                          0,
                          &BufferSize);
    if(Status != STATUS_INFO_LENGTH_MISMATCH || BufferSize == 0)
        return;

    constexpr ULONG MaximumBufferSize = 1024 * 1024;
    for(ULONG Attempt = 0; Attempt < 4; Attempt++)
    {
        if(BufferSize > MaximumBufferSize || BufferSize > MAXULONG - PAGE_SIZE)
            return;
        BufferSize += PAGE_SIZE;

        OBJECT_ALL_INFORMATION* AllInformation =
            (OBJECT_ALL_INFORMATION*)ExAllocatePoolWithTag(
                PagedPool,
                BufferSize,
                'tObT');
        if(AllInformation == nullptr)
            return;

        ULONG RequiredSize = 0;
        Status = ZwQueryObject(
                     nullptr,
                     (OBJECT_INFORMATION_CLASS)ObjectTypesInformation,
                     AllInformation,
                     BufferSize,
                     &RequiredSize);
        if(Status == STATUS_INFO_LENGTH_MISMATCH)
        {
            ExFreePoolWithTag(AllInformation, 'tObT');
            BufferSize = RequiredSize > BufferSize ? RequiredSize : BufferSize;
            continue;
        }
        if(!NT_SUCCESS(Status))
        {
            ExFreePoolWithTag(AllInformation, 'tObT');
            return;
        }

        const UNICODE_STRING DebugObject = RTL_CONSTANT_STRING(L"DebugObject");
        unsigned char* BufferStart = (unsigned char*)AllInformation;
        unsigned char* BufferEnd = BufferStart + BufferSize;
        unsigned char* Location =
            (unsigned char*)AllInformation->ObjectTypeInformation;
        for(ULONG i = 0; i < AllInformation->NumberOfObjects; i++)
        {
            if(Location > BufferEnd ||
                    (SIZE_T)(BufferEnd - Location) < sizeof(OBJECT_TYPE_INFORMATION))
            {
                break;
            }

            OBJECT_TYPE_INFORMATION* TypeInformation =
                (OBJECT_TYPE_INFORMATION*)Location;
            unsigned char* Name = (unsigned char*)TypeInformation->TypeName.Buffer;
            if(Name < BufferStart || Name > BufferEnd ||
                    TypeInformation->TypeName.Length > (SIZE_T)(BufferEnd - Name) ||
                    TypeInformation->TypeName.MaximumLength >
                        (SIZE_T)(BufferEnd - Name))
            {
                break;
            }

            if(RtlEqualUnicodeString(&TypeInformation->TypeName,
                                     &DebugObject,
                                     FALSE))
            {
                gDebugObjectTypeSignature.InvalidAttributes =
                    TypeInformation->InvalidAttributes;
                gDebugObjectTypeSignature.GenericMapping =
                    TypeInformation->GenericMapping;
                gDebugObjectTypeSignature.ValidAccessMask =
                    TypeInformation->ValidAccessMask;
                gDebugObjectTypeSignature.SecurityRequired =
                    TypeInformation->SecurityRequired;
                gDebugObjectTypeSignature.MaintainHandleCount =
                    TypeInformation->MaintainHandleCount;
                gDebugObjectTypeSignature.TypeIndex =
                    TypeInformation->TypeIndex;
                gDebugObjectTypeSignature.PoolType =
                    TypeInformation->PoolType;
                gDebugObjectTypeSignature.DefaultPagedPoolCharge =
                    TypeInformation->DefaultPagedPoolCharge;
                gDebugObjectTypeSignature.DefaultNonPagedPoolCharge =
                    TypeInformation->DefaultNonPagedPoolCharge;
                gDebugObjectTypeSignatureValid = true;
                break;
            }

            ULONG_PTR Next = (ULONG_PTR)Name +
                             TypeInformation->TypeName.MaximumLength;
            Next = (Next + sizeof(void*) - 1) & -(LONG_PTR)sizeof(void*);
            if(Next <= (ULONG_PTR)Location || Next > (ULONG_PTR)BufferEnd)
                break;
            Location = (unsigned char*)Next;
        }

        ExFreePoolWithTag(AllInformation, 'tObT');
        return;
    }
}

bool Hooks::RegisterVirtualThreadHide(PETHREAD Thread)
{
    VIRTUAL_THREAD_HIDE_ENTRY Entry;
    Entry.ProcessId = PsGetProcessId(PsGetThreadProcess(Thread));
    Entry.Thread = Thread;

    KIRQL Irql;
    KeAcquireSpinLock(&gVirtualThreadHideLock, &Irql);
    for(ULONG i = 0; i < gVirtualThreadHideEntryCount; i++)
    {
        if(gVirtualThreadHideEntries[i].Thread == Thread)
        {
            KeReleaseSpinLock(&gVirtualThreadHideLock, Irql);
            return true;
        }
    }

    // Prefer live-thread coverage when the bounded table is full. Evicting an
    // exited entry can only affect a surviving handle after deliberate table
    // exhaustion and never applies the physical one-way flag.
    PETHREAD EvictedThread = nullptr;
    if(gVirtualThreadHideEntryCount == MAX_VIRTUAL_THREAD_HIDE_ENTRIES)
    {
        for(ULONG i = 0; i < gVirtualThreadHideEntryCount; i++)
        {
            if(PsIsThreadTerminating(gVirtualThreadHideEntries[i].Thread))
            {
                EvictedThread = gVirtualThreadHideEntries[i].Thread;
                gVirtualThreadHideEntries[i] =
                    gVirtualThreadHideEntries[--gVirtualThreadHideEntryCount];
                break;
            }
        }
    }

    const bool Registered =
        gVirtualThreadHideEntryCount < MAX_VIRTUAL_THREAD_HIDE_ENTRIES;
    if(Registered)
    {
        ObReferenceObject(Thread);
        gVirtualThreadHideEntries[gVirtualThreadHideEntryCount++] = Entry;
    }
    KeReleaseSpinLock(&gVirtualThreadHideLock, Irql);
    if(EvictedThread != nullptr)
        ObDereferenceObject(EvictedThread);

    // Unhide can race with registration. Clear the virtual state if protection
    // ended; never apply a delayed physical HideFromDebugger request.
    if(Registered &&
            !Hider::IsHidden((ULONG)(ULONG_PTR)Entry.ProcessId,
                             HideThreadHideFromDebugger))
    {
        Hooks::ClearVirtualThreadHides(
            (ULONG)(ULONG_PTR)Entry.ProcessId,
            false);
    }
    return Registered;
}

void Hooks::ClearVirtualThreadHides(ULONG ProcessId, bool AllProcesses)
{
    while(true)
    {
        PETHREAD Thread = nullptr;
        KIRQL Irql;
        KeAcquireSpinLock(&gVirtualThreadHideLock, &Irql);
        for(ULONG i = 0; i < gVirtualThreadHideEntryCount; i++)
        {
            if(AllProcesses ||
                    gVirtualThreadHideEntries[i].ProcessId ==
                        (HANDLE)(ULONG_PTR)ProcessId)
            {
                Thread = gVirtualThreadHideEntries[i].Thread;
                gVirtualThreadHideEntries[i] =
                    gVirtualThreadHideEntries[--gVirtualThreadHideEntryCount];
                break;
            }
        }
        KeReleaseSpinLock(&gVirtualThreadHideLock, Irql);

        if(Thread == nullptr)
            break;
        ObDereferenceObject(Thread);
    }
}

static bool HasVirtualThreadHide(PETHREAD Thread)
{
    bool Found = false;
    KIRQL Irql;
    KeAcquireSpinLock(&gVirtualThreadHideLock, &Irql);
    for(ULONG i = 0; i < gVirtualThreadHideEntryCount; i++)
    {
        if(gVirtualThreadHideEntries[i].Thread == Thread)
        {
            Found = true;
            break;
        }
    }
    KeReleaseSpinLock(&gVirtualThreadHideLock, Irql);
    return Found;
}

static void RegisterCreatedVirtualThreadHide(PHANDLE ThreadHandle)
{
    __try
    {
        ProbeForRead(ThreadHandle, sizeof(HANDLE), 1);
        const HANDLE CreatedThreadHandle = *ThreadHandle;

        PETHREAD Thread = nullptr;
        NTSTATUS Status = ObReferenceObjectByHandle(
                              CreatedThreadHandle,
                              0,
                              *PsThreadType,
                              ExGetPreviousMode(),
                              (PVOID*)&Thread,
                              nullptr);
        if(NT_SUCCESS(Status))
        {
            // Keep the physical flag clear even if the bounded virtual-state
            // table is exhausted. Debugger visibility takes precedence.
            Hooks::RegisterVirtualThreadHide(Thread);
            ObDereferenceObject(Thread);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        NOTHING;
    }
}

static NTSTATUS NTAPI HookNtQueryInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    if(ExGetPreviousMode() == KernelMode)
        return Undocumented::NtQueryInformationThread(
                   ThreadHandle,
                   ThreadInformationClass,
                   ThreadInformation,
                   ThreadInformationLength,
                   ReturnLength);

    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

#ifdef _WIN64 // ThreadWow64Context returns STATUS_INVALID_INFO_CLASS on x86, and STATUS_INVALID_PARAMETER if PreviousMode is kernel
    ULONG targetPid = Misc::GetProcessIDFromThreadHandle(ThreadHandle);
    if(ThreadInformationClass == ThreadWow64Context &&
            ThreadInformation != nullptr &&
            ThreadInformationLength == sizeof(WOW64_CONTEXT) &&
            ExGetPreviousMode() != KernelMode &&
            Hider::IsHidden(pid, HideNtGetContextThread) &&
            Hider::IsHidden(targetPid, HideNtGetContextThread))
    {
        PWOW64_CONTEXT Wow64Context = (PWOW64_CONTEXT)ThreadInformation;
        ULONG OriginalContextFlags = 0;
        bool DebugRegistersRequested = false;

        Log("[TITANHIDE] NtGetContextThread by %d\r\n", pid);

        __try
        {
            ProbeForWrite(&Wow64Context->ContextFlags, sizeof(ULONG), 1);
            OriginalContextFlags = Wow64Context->ContextFlags;
            Wow64Context->ContextFlags = OriginalContextFlags & ~0x10; //CONTEXT_DEBUG_REGISTERS ^ CONTEXT_AMD64/CONTEXT_i386
            DebugRegistersRequested = Wow64Context->ContextFlags != OriginalContextFlags;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            NOTHING;
        }

        const NTSTATUS Status = Undocumented::NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);

        __try
        {
            ProbeForWrite(&Wow64Context->ContextFlags, sizeof(ULONG), 1);
            Wow64Context->ContextFlags = OriginalContextFlags;

            // If debug registers were requested successfully, zero user input.
            if(NT_SUCCESS(Status) && DebugRegistersRequested)
            {
                Wow64Context->Dr0 = 0;
                Wow64Context->Dr1 = 0;
                Wow64Context->Dr2 = 0;
                Wow64Context->Dr3 = 0;
                Wow64Context->Dr6 = 0;
                Wow64Context->Dr7 = 0;
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            NOTHING;
        }

        return Status;
    }
#endif

    // Call the original function now, since querying ThreadHideFromDebugger may fail with STATUS_INVALID_INFO_CLASS (if we are on XP/2003)
    NTSTATUS Status = Undocumented::NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);

    if(NT_SUCCESS(Status) &&
            ThreadInformationClass == ThreadHideFromDebugger)
    {
        __try
        {
            BACKUP_RETURNLENGTH();

            PETHREAD Thread = nullptr;
            NTSTATUS ReferenceStatus = ObReferenceObjectByHandle(
                                           ThreadHandle,
                                           0,
                                           *PsThreadType,
                                           ExGetPreviousMode(),
                                           (PVOID*)&Thread,
                                           nullptr);
            if(NT_SUCCESS(ReferenceStatus))
            {
                if(HasVirtualThreadHide(Thread))
                {
                    Log("[TITANHIDE] NtQueryInformationThread(ThreadHideFromDebugger) by %d\r\n", pid);
                    *(BOOLEAN*)ThreadInformation = TRUE;
                }
                ObDereferenceObject(Thread);
            }

            RESTORE_RETURNLENGTH();
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            Status = GetExceptionCode();
        }
    }

    return Status;
}

static NTSTATUS NTAPI HookNtSetInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID ThreadInformation,
    IN ULONG ThreadInformationLength)
{
    if(ExGetPreviousMode() == KernelMode)
        return Undocumented::NtSetInformationThread(
                   ThreadHandle,
                   ThreadInformationClass,
                   ThreadInformation,
                   ThreadInformationLength);

    const ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    const ULONG targetPid = Misc::GetProcessIDFromThreadHandle(ThreadHandle);

    //Bug found by Aguila, thanks!
    if(ThreadInformationClass == ThreadHideFromDebugger && !ThreadInformationLength)
    {
        if(Hider::IsHidden(pid, HideThreadHideFromDebugger) &&
                Hider::IsHidden(targetPid, HideThreadHideFromDebugger))
        {
            Log("[TITANHIDE] NtSetInformationThread(ThreadHideFromDebugger) by %d\r\n", pid);
            PETHREAD Thread;
            NTSTATUS status = ObReferenceObjectByHandle(ThreadHandle,
                              THREAD_SET_INFORMATION,
                              *PsThreadType,
                              ExGetPreviousMode(),
                              (PVOID*)&Thread,
                              NULL);
            if(NT_SUCCESS(status))
            {
                // Never fall back to the real set operation: the flag is
                // one-way and would hide this thread from the debugger.
                Hooks::RegisterVirtualThreadHide(Thread);
                ObDereferenceObject(Thread);
            }
            return status;
        }
    }
    // ThreadWow64Context returns STATUS_INVALID_INFO_CLASS on x86, and STATUS_INVALID_PARAMETER if PreviousMode is kernel
#ifdef _WIN64
    else if(ThreadInformationClass == ThreadWow64Context &&
            ThreadInformation != nullptr &&
            ThreadInformationLength == sizeof(WOW64_CONTEXT) &&
            ExGetPreviousMode() != KernelMode &&
            Hider::IsHidden(pid, HideNtSetContextThread))
    {
        PWOW64_CONTEXT Wow64Context = (PWOW64_CONTEXT)ThreadInformation;
        ULONG OriginalContextFlags = 0;

        Log("[TITANHIDE] NtSetContextThread by %d\r\n", pid);

        __try
        {
            ProbeForWrite(&Wow64Context->ContextFlags, sizeof(ULONG), 1);
            OriginalContextFlags = Wow64Context->ContextFlags;
            Wow64Context->ContextFlags = OriginalContextFlags & ~0x10; //CONTEXT_DEBUG_REGISTERS ^ CONTEXT_AMD64/CONTEXT_i386
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            NOTHING;
        }

        const NTSTATUS Status = Undocumented::NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);

        __try
        {
            ProbeForWrite(&Wow64Context->ContextFlags, sizeof(ULONG), 1);
            Wow64Context->ContextFlags = OriginalContextFlags;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            NOTHING;
        }

        return Status;
    }
#endif

    return Undocumented::NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

static NTSTATUS NTAPI HookNtClose(
    IN HANDLE Handle)
{
    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    if(PreviousMode == KernelMode)
        return ObCloseHandle(Handle, KernelMode);
    if(Hider::IsHidden(pid, HideNtClose))
    {
        KeWaitForSingleObject(&gDebugPortMutex, Executive, KernelMode, FALSE, nullptr);

        // Check if this is a valid handle without raising exceptionss
        BOOLEAN AuditOnClose;
        NTSTATUS ObStatus = ObQueryObjectAuditingByHandle(Handle, &AuditOnClose);

        NTSTATUS Status;
        if(ObStatus != STATUS_INVALID_HANDLE)  // Don't change the return path for any status except this one
        {
            BOOLEAN BeingDebugged = PsGetProcessDebugPort(PsGetCurrentProcess()) != nullptr;
            OBJECT_HANDLE_INFORMATION HandleInfo = { 0 };

            if(BeingDebugged)
            {
                // Get handle info so we can check if the handle has the ProtectFromClose bit set
                PVOID Object = nullptr;
                ObStatus = ObReferenceObjectByHandle(Handle,
                                                     0,
                                                     nullptr,
                                                     PreviousMode,
                                                     &Object,
                                                     &HandleInfo);
                if(Object != nullptr)
                    ObDereferenceObject(Object);
            }

            if(BeingDebugged && NT_SUCCESS(ObStatus) &&
                    (HandleInfo.HandleAttributes & OBJ_PROTECT_CLOSE))
            {
                // Return STATUS_HANDLE_NOT_CLOSABLE instead of raising an exception
                Log("[TITANHIDE] NtClose(0x%p) (protected handle) by %d\r\n", Handle, pid);
                Status = STATUS_HANDLE_NOT_CLOSABLE;
            }
            else
            {
                Status = ObCloseHandle(Handle, PreviousMode);
            }
        }
        else
        {
            Log("[TITANHIDE] NtClose(0x%p) by %d\r\n", Handle, pid);
            Status = STATUS_INVALID_HANDLE;
        }

        KeReleaseMutex(&gDebugPortMutex, FALSE);

        return Status;
    }
    return ObCloseHandle(Handle, PreviousMode);
}

static NTSTATUS NTAPI HookNtDuplicateObject(
    IN HANDLE SourceProcessHandle,
    IN HANDLE SourceHandle,
    IN HANDLE TargetProcessHandle,
    OUT PHANDLE TargetHandle,
    IN ACCESS_MASK DesiredAccess OPTIONAL,
    IN ULONG HandleAttributes,
    IN ULONG Options)
{
    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    if(PreviousMode == KernelMode)
        return Undocumented::NtDuplicateObject(
                   SourceProcessHandle,
                   SourceHandle,
                   TargetProcessHandle,
                   TargetHandle,
                   DesiredAccess,
                   HandleAttributes,
                   Options);
    if(Hider::IsHidden(pid, HideNtClose))
    {
        BOOLEAN BeingDebugged = PsGetProcessDebugPort(PsGetCurrentProcess()) != nullptr;
        if(BeingDebugged && (Options & DUPLICATE_CLOSE_SOURCE))
        {
            // Get handle info so we can check if the handle has the ProtectFromClose bit set
            PVOID Object = nullptr;
            OBJECT_HANDLE_INFORMATION HandleInfo = { 0 };
            NTSTATUS Status = ObReferenceObjectByHandle(SourceHandle,
                              0,
                              nullptr,
                              PreviousMode,
                              &Object,
                              &HandleInfo);

            if(NT_SUCCESS(Status))
            {
                if(Object != nullptr)
                    ObDereferenceObject(Object);

                if(HandleInfo.HandleAttributes & OBJ_PROTECT_CLOSE)
                {
                    // Prevent a user mode exception from happening when ObDuplicateObject calls NtClose on the source handle.
                    // Why doesn't our NtClose hook catch this? Because the kernel uses its own RVAs instead of going through the SSDT
                    Options &= ~DUPLICATE_CLOSE_SOURCE;
                }
            }
        }
    }

    return Undocumented::NtDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
}

static NTSTATUS NTAPI HookNtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    if(ExGetPreviousMode() == KernelMode)
        return Undocumented::NtQuerySystemInformation(
                   SystemInformationClass,
                   SystemInformation,
                   SystemInformationLength,
                   ReturnLength);

    NTSTATUS ret = Undocumented::NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    if(NT_SUCCESS(ret) && SystemInformation)
    {
        ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
        switch (SystemInformationClass)
        {
        case SystemKernelDebuggerInformation:
        {
            if (Hider::IsHidden(pid, HideSystemDebuggerInformation))
            {
                Log("[TITANHIDE] SystemKernelDebuggerInformation by %d\r\n", pid);
                typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
                {
                    BOOLEAN DebuggerEnabled;
                    BOOLEAN DebuggerNotPresent;
                } SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;
                SYSTEM_KERNEL_DEBUGGER_INFORMATION* DebuggerInfo = (SYSTEM_KERNEL_DEBUGGER_INFORMATION*)SystemInformation;
                __try
                {
                    BACKUP_RETURNLENGTH();

                    DebuggerInfo->DebuggerEnabled = false;
                    DebuggerInfo->DebuggerNotPresent = true;

                    RESTORE_RETURNLENGTH();
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    ret = GetExceptionCode();
                }
            }
            break;
        }
        case SystemKernelDebuggerInformationEx:
        {
            if (Hider::IsHidden(pid, HideSystemDebuggerInformation))
            {
                Log("[TITANHIDE] SystemKernelDebuggerInformationEx by %d\r\n", pid);
                typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
                {
                    BOOLEAN DebuggerAllowed;
                    BOOLEAN DebuggerEnabled;
                    BOOLEAN DebuggerPresent;
                } SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX;
                PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX DebuggerInfo = (PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation;
                __try
                {
                    BACKUP_RETURNLENGTH();

                    DebuggerInfo->DebuggerAllowed = false;
                    DebuggerInfo->DebuggerEnabled = false;
                    DebuggerInfo->DebuggerPresent = false;

                    RESTORE_RETURNLENGTH();
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    ret = GetExceptionCode();
                }
            }
            break;
        }
        default:
            break;
        }
    }
    return ret;
}

struct DEBUG_OBJECT_CONTRIBUTION
{
    ULONG Objects;
    ULONG Handles;
};

struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};

struct SYSTEM_HANDLE_INFORMATION_EX_LOCAL
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL Handles[1];
};

static bool QueryDebugObjectContribution(DEBUG_OBJECT_CONTRIBUTION* Contribution)
{
    Contribution->Objects = 0;
    Contribution->Handles = 0;

    // The process has one active debug-port object at most. Do not query
    // ProcessDebugObjectHandle here: repeatedly opening that handle can retain
    // references to the DebugObject after both debugger and debuggee exit.
    PVOID DebugPort = PsGetProcessDebugPort(PsGetCurrentProcess());
    if(DebugPort == nullptr)
        return false;

    ULONG BufferSize = 0;
    NTSTATUS Status = Undocumented::ZwQuerySystemInformation(
                          SystemExtendedHandleInformation,
                          nullptr,
                          0,
                          &BufferSize);
    if(Status != STATUS_INFO_LENGTH_MISMATCH || BufferSize == 0)
        return false;

    constexpr ULONG MaximumBufferSize = 64 * 1024 * 1024;
    for(ULONG Attempt = 0; Attempt < 4; Attempt++)
    {
        if(BufferSize > MaximumBufferSize || BufferSize > MAXULONG - PAGE_SIZE)
            return false;
        BufferSize += PAGE_SIZE;

        SYSTEM_HANDLE_INFORMATION_EX_LOCAL* HandleInformation =
            (SYSTEM_HANDLE_INFORMATION_EX_LOCAL*)ExAllocatePoolWithTag(
                PagedPool,
                BufferSize,
                'hDbT');
        if(HandleInformation == nullptr)
            return false;

        ULONG RequiredSize = 0;
        Status = Undocumented::ZwQuerySystemInformation(
                     SystemExtendedHandleInformation,
                     HandleInformation,
                     BufferSize,
                     &RequiredSize);
        if(Status == STATUS_INFO_LENGTH_MISMATCH)
        {
            ExFreePoolWithTag(HandleInformation, 'hDbT');
            BufferSize = RequiredSize > BufferSize ? RequiredSize : BufferSize;
            continue;
        }
        if(!NT_SUCCESS(Status))
        {
            ExFreePoolWithTag(HandleInformation, 'hDbT');
            return false;
        }

        const SIZE_T HeaderSize = FIELD_OFFSET(SYSTEM_HANDLE_INFORMATION_EX_LOCAL, Handles);
        const ULONG_PTR MaximumEntries =
            BufferSize >= HeaderSize
            ? (BufferSize - HeaderSize) / sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_LOCAL)
            : 0;
        if(HandleInformation->NumberOfHandles > MaximumEntries)
        {
            ExFreePoolWithTag(HandleInformation, 'hDbT');
            return false;
        }

        Contribution->Objects = 1;
        for(ULONG_PTR i = 0; i < HandleInformation->NumberOfHandles; i++)
        {
            if(HandleInformation->Handles[i].Object == DebugPort &&
                    Contribution->Handles != MAXULONG)
            {
                Contribution->Handles++;
            }
        }

        ExFreePoolWithTag(HandleInformation, 'hDbT');
        return true;
    }

    return false;
}

static void RemoveDebugObjectContribution(
    OBJECT_TYPE_INFORMATION* TypeInformation,
    const DEBUG_OBJECT_CONTRIBUTION* Contribution)
{
    TypeInformation->TotalNumberOfObjects =
        TypeInformation->TotalNumberOfObjects > Contribution->Objects
        ? TypeInformation->TotalNumberOfObjects - Contribution->Objects
        : 0;
    TypeInformation->TotalNumberOfHandles =
        TypeInformation->TotalNumberOfHandles > Contribution->Handles
        ? TypeInformation->TotalNumberOfHandles - Contribution->Handles
        : 0;
}

static NTSTATUS NTAPI HookNtQueryObject(
    IN HANDLE Handle OPTIONAL,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation OPTIONAL,
    IN ULONG ObjectInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    // ZwQueryObject calls made by this hook must reach the original service and
    // may write to kernel buffers. Hiding is only required for user-mode callers.
    if(ExGetPreviousMode() == KernelMode)
        return Undocumented::NtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);

    NTSTATUS ret = Undocumented::NtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
    if(NT_SUCCESS(ret) && ObjectInformation)
    {
        ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
        UNICODE_STRING DebugObject;
        RtlInitUnicodeString(&DebugObject, L"DebugObject");
        if(ObjectInformationClass == ObjectTypeInformation && Hider::IsHidden(pid, HideDebugObject))
        {
            __try
            {
                BACKUP_RETURNLENGTH();

                OBJECT_TYPE_INFORMATION* type = (OBJECT_TYPE_INFORMATION*)ObjectInformation;
                DEBUG_OBJECT_CONTRIBUTION Contribution;
                if(QueryDebugObjectContribution(&Contribution) &&
                        IsDebugObjectTypeInformation(type,
                                                     ObjectInformationLength,
                                                     ReturnLength,
                                                     &DebugObject,
                                                     &gDebugObjectTypeSignature))
                {
                    Log("[TITANHIDE] DebugObject by %d\r\n", pid);
                    RemoveDebugObjectContribution(type, &Contribution);
                }

                RESTORE_RETURNLENGTH();
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                ret = GetExceptionCode();
            }
        }
        else if(ObjectInformationClass == ObjectTypesInformation && Hider::IsHidden(pid, HideDebugObject))
        {
            //NCC Group Security Advisory
            __try
            {
                BACKUP_RETURNLENGTH();

                OBJECT_ALL_INFORMATION* pObjectAllInfo = (OBJECT_ALL_INFORMATION*)ObjectInformation;
                unsigned char* pObjInfoLocation = (unsigned char*)pObjectAllInfo->ObjectTypeInformation;
                SIZE_T ReturnedLength = ObjectInformationLength;
                if(ReturnLength != nullptr && TempReturnLength < ReturnedLength)
                    ReturnedLength = TempReturnLength;
                unsigned char* BufferEnd = (unsigned char*)ObjectInformation + ReturnedLength;
                if(BufferEnd < (unsigned char*)ObjectInformation)
                {
                    RESTORE_RETURNLENGTH();
                    return ret;
                }

                DEBUG_OBJECT_CONTRIBUTION Contribution;
                if(QueryDebugObjectContribution(&Contribution))
                {
                    // ReturnLength is the authoritative byte bound. Use the
                    // native object count too unless ReturnLength overwrote it.
                    const bool ObjectCountValid =
                        !RangesOverlap(&pObjectAllInfo->NumberOfObjects,
                                       sizeof(pObjectAllInfo->NumberOfObjects),
                                       ReturnLength,
                                       sizeof(ULONG));
                    const ULONG TotalObjects = pObjectAllInfo->NumberOfObjects;
                    ULONG ObjectsVisited = 0;
                    while(pObjInfoLocation <= BufferEnd &&
                            (SIZE_T)(BufferEnd - pObjInfoLocation) >= sizeof(OBJECT_TYPE_INFORMATION) &&
                            (!ObjectCountValid || ObjectsVisited < TotalObjects))
                    {
                        OBJECT_TYPE_INFORMATION* pObjectTypeInfo =
                            (OBJECT_TYPE_INFORMATION*)pObjInfoLocation;
                        ProbeForRead(pObjectTypeInfo, sizeof(OBJECT_TYPE_INFORMATION), 1);

                        unsigned char* InlineTypeName =
                            (unsigned char*)(pObjectTypeInfo + 1);
                        const bool DescriptorMatches =
                            IsDebugObjectTypeDescriptor(
                                pObjectTypeInfo,
                                ReturnLength,
                                &gDebugObjectTypeSignature);
                        const bool NameMatches =
                            (SIZE_T)(BufferEnd - InlineTypeName) >=
                                DebugObject.Length + sizeof(WCHAR) &&
                            !RangesOverlap(InlineTypeName,
                                           DebugObject.Length + sizeof(WCHAR),
                                           ReturnLength,
                                           sizeof(ULONG)) &&
                            RtlCompareMemory(InlineTypeName,
                                             DebugObject.Buffer,
                                             DebugObject.Length) == DebugObject.Length &&
                            *(WCHAR*)(InlineTypeName + DebugObject.Length) == L'\0';
                        if(DescriptorMatches || NameMatches)
                        {
                            Log("[TITANHIDE] DebugObject by %d\r\n", pid);
                            RemoveDebugObjectContribution(pObjectTypeInfo, &Contribution);
                            break;
                        }

                        SIZE_T InlineAllocationLength = 0;
                        if(!RangesOverlap(&pObjectTypeInfo->TypeName.MaximumLength,
                                          sizeof(pObjectTypeInfo->TypeName.MaximumLength),
                                          ReturnLength,
                                          sizeof(ULONG)) &&
                                pObjectTypeInfo->TypeName.MaximumLength >= sizeof(WCHAR) &&
                                pObjectTypeInfo->TypeName.MaximumLength <=
                                    (SIZE_T)(BufferEnd - InlineTypeName))
                        {
                            InlineAllocationLength = pObjectTypeInfo->TypeName.MaximumLength;
                        }
                        else
                        {
                            WCHAR* Character = (WCHAR*)InlineTypeName;
                            while((SIZE_T)(BufferEnd - (unsigned char*)Character) >= sizeof(WCHAR) &&
                                    *Character != L'\0')
                            {
                                Character++;
                            }
                            if((SIZE_T)(BufferEnd - (unsigned char*)Character) < sizeof(WCHAR))
                                break;
                            InlineAllocationLength =
                                (SIZE_T)((unsigned char*)(Character + 1) - InlineTypeName);
                        }

                        ULONG_PTR Next = (ULONG_PTR)InlineTypeName + InlineAllocationLength;
                        Next = (Next + sizeof(void*) - 1) & -(LONG_PTR)sizeof(void*);
                        if(Next <= (ULONG_PTR)pObjInfoLocation || Next > (ULONG_PTR)BufferEnd)
                            break;
                        pObjInfoLocation = (unsigned char*)Next;
                        ObjectsVisited++;
                    }
                }

                RESTORE_RETURNLENGTH();
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                ret = GetExceptionCode();
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
    // Internal ZwQueryInformationProcess calls use kernel buffers and must not
    // be filtered as anti-debug queries from the hidden process.
    if(ExGetPreviousMode() == KernelMode)
        return Undocumented::NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

    ULONG pid = Misc::GetProcessIDFromProcessHandle(ProcessHandle);

    // Handle ProcessDebugObjectHandle early
    if(ProcessInformationClass == ProcessDebugObjectHandle &&
            ProcessInformation != nullptr &&
            ProcessInformationLength == sizeof(HANDLE) &&
            Hider::IsHidden(pid, HideProcessDebugObjectHandle))
    {
        // The native service checks the output alignment before validating the
        // process handle or its access rights. Keep that ordering observable to
        // callers using a restricted handle and a deliberately bad buffer.
        if(((ULONG_PTR)ProcessInformation & (sizeof(ULONG) - 1)) != 0)
            return STATUS_DATATYPE_MISALIGNMENT;

        PEPROCESS Process;
        NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle,
                          PROCESS_QUERY_INFORMATION,
                          *PsProcessType,
                          ExGetPreviousMode(),
                          (PVOID*)&Process,
                          nullptr);
        if(!NT_SUCCESS(Status))
            return Status;

        // (The kernel calls DbgkOpenProcessDebugPort here)

        ObDereferenceObject(Process);

        __try
        {
            // Alignment was checked above; probe accessibility only after the
            // process handle has passed PROCESS_QUERY_INFORMATION validation.
            ProbeForWrite(ProcessInformation, sizeof(HANDLE), 1);

            if (ReturnLength != nullptr)
                ProbeForWrite(ReturnLength, sizeof(ULONG), 1);

            *(PHANDLE)ProcessInformation = nullptr;

            if (ReturnLength != nullptr)
                *ReturnLength = sizeof(HANDLE);
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            return GetExceptionCode();
        }
        return STATUS_PORT_NOT_SET;
    }

    NTSTATUS ret = Undocumented::NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
    if(NT_SUCCESS(ret) &&
            ProcessInformation &&
            ProcessInformationClass != ProcessBasicInformation) //prevent stack overflow
    {
        if(ProcessInformationClass == ProcessDebugFlags)
        {
            if(Hider::IsHidden(pid, HideProcessDebugFlags))
            {
                Log("[TITANHIDE] ProcessDebugFlags by %d\r\n", pid);
                __try
                {
                    BACKUP_RETURNLENGTH();

                    *(unsigned int*)ProcessInformation = TRUE;

                    RESTORE_RETURNLENGTH();
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    ret = GetExceptionCode();
                }
            }
        }
        else if(ProcessInformationClass == ProcessDebugPort)
        {
            if(Hider::IsHidden(pid, HideProcessDebugPort))
            {
                Log("[TITANHIDE] ProcessDebugPort by %d\r\n", pid);
                __try
                {
                    BACKUP_RETURNLENGTH();

                    *(ULONG_PTR*)ProcessInformation = 0;

                    RESTORE_RETURNLENGTH();
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    ret = GetExceptionCode();
                }
            }
        }
    }
    return ret;
}

static NTSTATUS NTAPI HookNtGetContextThread(
    IN HANDLE ThreadHandle,
    IN OUT PCONTEXT Context)
{
    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    ULONG targetPid = Misc::GetProcessIDFromThreadHandle(ThreadHandle);
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    bool IsHidden = PreviousMode != KernelMode &&
                    Hider::IsHidden(pid, HideNtGetContextThread) &&
                    Hider::IsHidden(targetPid, HideNtGetContextThread);
    ULONG OriginalContextFlags = 0;
    bool DebugRegistersRequested = false;
    if(IsHidden)
    {
        Log("[TITANHIDE] NtGetContextThread by %d\r\n", pid);
        __try
        {
            ProbeForWrite(&Context->ContextFlags, sizeof(ULONG), 1);
            OriginalContextFlags = Context->ContextFlags;
            Context->ContextFlags = OriginalContextFlags & ~0x10; //CONTEXT_DEBUG_REGISTERS ^ CONTEXT_AMD64/CONTEXT_i386
            DebugRegistersRequested = Context->ContextFlags != OriginalContextFlags;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            IsHidden = false;
        }
    }
    NTSTATUS ret = Undocumented::NtGetContextThread(ThreadHandle, Context);
    if(IsHidden)
    {
        __try
        {
            ProbeForWrite(&Context->ContextFlags, sizeof(ULONG), 1);
            Context->ContextFlags = OriginalContextFlags;

            // Failed queries must leave the caller's output untouched.
            if(NT_SUCCESS(ret) && DebugRegistersRequested)
            {
                Context->Dr0 = 0;
                Context->Dr1 = 0;
                Context->Dr2 = 0;
                Context->Dr3 = 0;
                Context->Dr6 = 0;
                Context->Dr7 = 0;
#ifdef _WIN64
                Context->LastBranchToRip = 0;
                Context->LastBranchFromRip = 0;
                Context->LastExceptionToRip = 0;
                Context->LastExceptionFromRip = 0;
#endif
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }
    return ret;
}

static NTSTATUS NTAPI HookNtSetContextThread(
    IN HANDLE ThreadHandle,
    IN PCONTEXT Context)
{
    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    bool IsHidden = PreviousMode != KernelMode && Hider::IsHidden(pid, HideNtSetContextThread);
    ULONG OriginalContextFlags = 0;
    if(IsHidden)
    {
        //http://lifeinhex.com/dont-touch-this-writing-good-drivers-is-really-hard
        //http://lifeinhex.com/when-software-is-good-enough
        Log("[TITANHIDE] NtSetContextThread by %d\r\n", pid);
        __try
        {
            ProbeForWrite(&Context->ContextFlags, sizeof(ULONG), 1);
            OriginalContextFlags = Context->ContextFlags;
            Context->ContextFlags = OriginalContextFlags & ~0x10; //CONTEXT_DEBUG_REGISTERS ^ CONTEXT_AMD64/CONTEXT_i386
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            IsHidden = false;
        }
    }
    NTSTATUS ret = Undocumented::NtSetContextThread(ThreadHandle, Context);
    if(IsHidden)
    {
        __try
        {
            ProbeForWrite(&Context->ContextFlags, sizeof(ULONG), 1);
            Context->ContextFlags = OriginalContextFlags;
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }
    return ret;
}

static NTSTATUS NTAPI HookNtSystemDebugControl(
    IN SYSDBG_COMMAND Command,
    IN PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer,
    IN ULONG OutputBufferLength,
    OUT PULONG ReturnLength)
{
    if(ExGetPreviousMode() == KernelMode)
        return Undocumented::NtSystemDebugControl(
                   Command,
                   InputBuffer,
                   InputBufferLength,
                   OutputBuffer,
                   OutputBufferLength,
                   ReturnLength);

    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    if(Command != SysDbgGetTriageDump && Command != SysDbgGetLiveKernelDump &&
            Hider::IsHidden(pid, HideNtSystemDebugControl))
    {
        Log("[TITANHIDE] NtSystemDebugControl by %d\r\n", pid);
        return STATUS_DEBUGGER_INACTIVE;
    }
    return Undocumented::NtSystemDebugControl(Command, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength);
}

static NTSTATUS NTAPI HookNtCreateThreadEx(
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
    if(ExGetPreviousMode() == KernelMode)
        return Undocumented::NtCreateThreadEx(
                   ThreadHandle,
                   DesiredAccess,
                   ObjectAttributes,
                   ProcessHandle,
                   StartRoutine,
                   Argument,
                   CreateFlags,
                   ZeroBits,
                   StackSize,
                   MaximumStackSize,
                   AttributeList);

    const ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    const ULONG targetPid = Misc::GetProcessIDFromProcessHandle(ProcessHandle);
    const bool VirtualizeThreadHide =
        (CreateFlags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER) != 0 &&
        Hider::IsHidden(pid, HideThreadHideFromDebugger) &&
        Hider::IsHidden(targetPid, HideThreadHideFromDebugger);
    if(VirtualizeThreadHide)
    {
        CreateFlags &= ~THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
        Log("[TITANHIDE] NtCreateThreadEx with THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER by %u\r\n", pid);
    }

    NTSTATUS Status = Undocumented::NtCreateThreadEx(
                          ThreadHandle,
                          DesiredAccess,
                          ObjectAttributes,
                          ProcessHandle,
                          StartRoutine,
                          Argument,
                          CreateFlags,
                          ZeroBits,
                          StackSize,
                          MaximumStackSize,
                          AttributeList);
    if(NT_SUCCESS(Status) && VirtualizeThreadHide)
        RegisterCreatedVirtualThreadHide(ThreadHandle);
    return Status;
}

int Hooks::Initialize()
{
    InitializeDebugObjectTypeSignature();
    KeInitializeMutex(&gDebugPortMutex, 0);
    KeInitializeSpinLock(&gVirtualThreadHideLock);
    gVirtualThreadHideEntryCount = 0;

    int hook_count = 0;
    hNtQueryInformationProcess = SSDT::Hook("NtQueryInformationProcess", (void*)HookNtQueryInformationProcess);
    if(hNtQueryInformationProcess)
        hook_count++;
    hNtQueryInformationThread = SSDT::Hook("NtQueryInformationThread", (void*)HookNtQueryInformationThread);
    if(hNtQueryInformationThread)
        hook_count++;
    hNtQueryObject = SSDT::Hook("NtQueryObject", (void*)HookNtQueryObject);
    if(hNtQueryObject)
        hook_count++;
    hNtQuerySystemInformation = SSDT::Hook("NtQuerySystemInformation", (void*)HookNtQuerySystemInformation);
    if(hNtQuerySystemInformation)
        hook_count++;
    hNtSetInformationThread = SSDT::Hook("NtSetInformationThread", (void*)HookNtSetInformationThread);
    if(hNtSetInformationThread)
        hook_count++;
    hNtClose = SSDT::Hook("NtClose", (void*)HookNtClose);
    if(hNtClose)
        hook_count++;
    hNtDuplicateObject = SSDT::Hook("NtDuplicateObject", (void*)HookNtDuplicateObject);
    if(hNtDuplicateObject)
        hook_count++;
    hNtGetContextThread = SSDT::Hook("NtGetContextThread", (void*)HookNtGetContextThread);
    if(hNtGetContextThread)
        hook_count++;
    hNtSetContextThread = SSDT::Hook("NtSetContextThread", (void*)HookNtSetContextThread);
    if(hNtSetContextThread)
        hook_count++;
    hNtSystemDebugControl = SSDT::Hook("NtSystemDebugControl", (void*)HookNtSystemDebugControl);
    if(hNtSystemDebugControl)
        hook_count++;
    if((NtBuildNumber & 0xFFFF) >= 6000)
    {
        hNtCreateThreadEx = SSDT::Hook("NtCreateThreadEx", (void*)HookNtCreateThreadEx);
        if(hNtCreateThreadEx)
            hook_count++;
    }
    return hook_count;
}

void Hooks::Deinitialize()
{
    SSDT::Unhook(hNtQueryInformationProcess, true);
    SSDT::Unhook(hNtQueryInformationThread, true);
    SSDT::Unhook(hNtQueryObject, true);
    SSDT::Unhook(hNtQuerySystemInformation, true);
    SSDT::Unhook(hNtSetInformationThread, true);
    SSDT::Unhook(hNtClose, true);
    SSDT::Unhook(hNtDuplicateObject, true);
    SSDT::Unhook(hNtGetContextThread, true);
    SSDT::Unhook(hNtSetContextThread, true);
    SSDT::Unhook(hNtSystemDebugControl, true);
    if((NtBuildNumber & 0xFFFF) >= 6000)
    {
        SSDT::Unhook(hNtCreateThreadEx, true);
    }

    ClearVirtualThreadHides(0, true);
}

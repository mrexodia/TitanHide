#include "threadhidefromdbg.h"
#include "undocumented.h"
#include "log.h"

// Exclude false positive matches in the KTHREAD/Tcb header
#ifdef _M_AMD64
#define PS_THREAD_SEARCH_START                  0x400
#else
#define PS_THREAD_SEARCH_START                  0x200
#endif

// 'Terminated' and 'HideFromDebugger' flags in ETHREAD's CrossThreadFlags. Other flags can't be used as they have changed between versions
#define PS_CROSS_THREAD_FLAGS_TERMINATED        0x00000001UL
#define PS_CROSS_THREAD_FLAGS_HIDEFROMDBG       0x00000004UL

ULONG CrossThreadFlagsOffset = 0;

NTSTATUS ReferenceProcessByName(_Outptr_ PEPROCESS* Process, _In_ PUNICODE_STRING ProcessName)
{
    ULONG Size;
    if(Undocumented::ZwQuerySystemInformation(SystemProcessInformation, nullptr, 0, &Size) != STATUS_INFO_LENGTH_MISMATCH)
        return STATUS_UNSUCCESSFUL;
    const PSYSTEM_PROCESS_INFORMATION SystemProcessInfo =
        (PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, 2 * Size, 'croP');
    if(SystemProcessInfo == nullptr)
        return STATUS_NO_MEMORY;
    NTSTATUS Status = Undocumented::ZwQuerySystemInformation(SystemProcessInformation, SystemProcessInfo, 2 * Size, nullptr);
    if(!NT_SUCCESS(Status))
    {
        ExFreePool(SystemProcessInfo);
        return Status;
    }

    PSYSTEM_PROCESS_INFORMATION Entry = SystemProcessInfo;
    Status = STATUS_NOT_FOUND;

    while(true)
    {
        if(Entry->ImageName.Buffer != nullptr &&
                RtlCompareUnicodeString(&Entry->ImageName, ProcessName, TRUE) == 0)
        {
            Status = PsLookupProcessByProcessId(Entry->UniqueProcessId, Process);
            if(NT_SUCCESS(Status))
                break;
        }

        if(Entry->NextEntryOffset == 0)
            break;

        Entry = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)Entry + Entry->NextEntryOffset);
    }
    ExFreePoolWithTag(SystemProcessInfo, 'croP');

    return Status;
}

// Finds the offset of CrossThreadFlags
NTSTATUS FindCrossThreadFlagsOffset(_Out_ PULONG Offset)
{
    *Offset = 0;

    UNICODE_STRING SvchostName = RTL_CONSTANT_STRING(L"svchost.exe");
    OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES((PUNICODE_STRING)nullptr, OBJ_KERNEL_HANDLE);
    PEPROCESS Process = nullptr;
    BOOLEAN Attached = FALSE;
    KAPC_STATE ApcState;
    HANDLE ThreadHandle = nullptr;
    PETHREAD Thread = nullptr;
    ULONG LastMatchFound = 0, MatchesFound = 0;
    ULONG_PTR End;

    // If we are on XP/2003, skip finding the offset dynamically since NtCreateThreadEx was only added in Vista.
    // (NtCreateThread requires elaborate setup of the user mode context, whereas NtCreateThreadEx will work with a NULL thread start address.)
    // Fortunately we can just return hardcoded offsets for these OSes since they will never be updated again
    const ULONG BuildNumber = NtBuildNumber & 0xFFFF;
    if(BuildNumber < 6000)
    {
        if(BuildNumber != 3790
#if defined(_X86_)
                && BuildNumber != 2600
#endif
          )
        {
            Log("[TITANHIDE] FindCrossThreadFlagsOffset: unsupported OS!\r\n");
            return STATUS_NOT_SUPPORTED;
        }

#ifdef _M_AMD64
        *Offset = 0x3FC;
#elif defined(_X86_)
        *Offset = BuildNumber == 3790 ? 0x240 : 0x248;
#endif
        return STATUS_SUCCESS;
    }

    // Since the ETHREAD struct is opaque and we don't know its size, allocate for 4K possible offsets
    const PULONG CandidateOffsets = (PULONG)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * sizeof(ULONG), 'drhT');
    if(CandidateOffsets == nullptr)
        return STATUS_NO_MEMORY;

    // Because on the first scan, a viable candidate for CrossThreadFlags may in fact have value 0, initialize to -1 instead
    RtlFillMemory(CandidateOffsets, sizeof(ULONG) * PAGE_SIZE, (ULONG) - 1);

    // Find and attach to a random svchost.exe, because we cannot make user mode threads in the system process
    NTSTATUS Status = ReferenceProcessByName(&Process, &SvchostName);
    if(!NT_SUCCESS(Status))
        goto Exit;

    KeStackAttachProcess(Process, &ApcState);
    Attached = TRUE;

    // Create a dummy thread
    Status = Undocumented::ZwCreateThreadEx(&ThreadHandle,
                                            THREAD_SET_INFORMATION,
                                            &ObjectAttributes,
                                            NtCurrentProcess(),
                                            nullptr,
                                            nullptr,
                                            THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
                                            0,
                                            0,
                                            0,
                                            nullptr);
    if(!NT_SUCCESS(Status))
        goto Exit;

    Status = ObReferenceObjectByHandle(ThreadHandle,
                                       THREAD_SET_INFORMATION,
                                       *PsThreadType,
                                       KernelMode,
                                       (PVOID*)&Thread,
                                       nullptr);
    if(!NT_SUCCESS(Status))
        goto Exit;

    // We now have a freshly created thread with a minimal amount of noise in its ETHREAD, and two predictable values
    // in its CrossThreadFlags: we know that the thread has neither the Terminated nor the ThreadHideFromDebugger bit set.

    End = ALIGN_UP_BY(Thread, PAGE_SIZE) - (ULONG_PTR)Thread;
    for(ULONG_PTR i = PS_THREAD_SEARCH_START; i < End; i += sizeof(ULONG))
    {
        const ULONG Candidate = *(ULONG*)((PUCHAR)Thread + i);
        if((Candidate & PS_CROSS_THREAD_FLAGS_TERMINATED) == 0 &&
                (Candidate & PS_CROSS_THREAD_FLAGS_HIDEFROMDBG) == 0)
        {
            CandidateOffsets[i] = Candidate;
        }
    }

    // Set the flag we are looking for
    Status = Undocumented::ZwSetInformationThread(ThreadHandle, ThreadHideFromDebugger, nullptr, 0);
    if(!NT_SUCCESS(Status))
        goto Exit;

    // Go over the offsets again and see if we can find any values that have not changed except for the addition of this flag
    for(ULONG_PTR i = PS_THREAD_SEARCH_START; i < End; i += sizeof(ULONG))
    {
        if(CandidateOffsets[i] == (ULONG) - 1)
            continue;

        const ULONG Candidate = *(ULONG*)((PUCHAR)Thread + i);
        if(Candidate == (CandidateOffsets[i] | PS_CROSS_THREAD_FLAGS_HIDEFROMDBG))
        {
            LastMatchFound = (ULONG)i;
            MatchesFound++;
        }
    }

    if(MatchesFound != 1)
    {
        Log("[TITANHIDE] Failed to find reliable match for CrossThreadFlags offset: wanted 1 match, found %u.\r\n", MatchesFound);
        Status = STATUS_NOT_FOUND;
        goto Exit;
    }

    *Offset = LastMatchFound;
    Log("[TITANHIDE] Found CrossThreadFlags at offset +0x%04X. 'HideFromDebugger' will be stripped from running threads in target processes.\r\n", *Offset);

Exit:
    if(Thread != nullptr)
        ObDereferenceObject(Thread);
    if(ThreadHandle != nullptr)
    {
        Undocumented::ZwTerminateThread(ThreadHandle, STATUS_SUCCESS);
        ObCloseHandle(ThreadHandle, ExGetPreviousMode());
    }
    if(Attached)
        KeUnstackDetachProcess(&ApcState);
    if(Process != nullptr)
        ObDereferenceObject(Process);
    ExFreePoolWithTag(CandidateOffsets, 'drhT');
    return Status;
}

// The NtQueryInformationThread hook prevents a process from enabling ThreadHideFromDebugger on
// new threads, but there is no kernel API to disable this flag on threads that already have it.
// This function uses DKOM to strip the HideFromDebugger flag from all threads in a process.
NTSTATUS UndoHideFromDebuggerInRunningThreads(_In_ ULONG Pid)
{
    PSYSTEM_PROCESS_INFORMATION SystemProcessInfo = nullptr, Entry;
    BOOLEAN Found = FALSE;
    ULONG NumThreadFlagsStripped = 0;

    if(CrossThreadFlagsOffset == 0)
        return STATUS_NOT_FOUND;

    PEPROCESS Process;
    NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Process);
    if(!NT_SUCCESS(Status))
        return Status;

    ULONG Size;
    Status = Undocumented::ZwQuerySystemInformation(SystemProcessInformation, nullptr, 0, &Size);
    if(Status != STATUS_INFO_LENGTH_MISMATCH)
        goto Exit;

    SystemProcessInfo = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, 2 * Size, 'croP');
    if(SystemProcessInfo == nullptr)
    {
        Status = STATUS_NO_MEMORY;
        goto Exit;
    }

    Status = Undocumented::ZwQuerySystemInformation(SystemProcessInformation, SystemProcessInfo, 2 * Size, nullptr);
    if(!NT_SUCCESS(Status))
        goto Exit;

    // Iterate over all processes to find our process
    Entry = SystemProcessInfo;
    while(true)
    {
        if(Entry->UniqueProcessId == (HANDLE)(ULONG_PTR)Pid)
        {
            for(ULONG i = 0; i < Entry->NumberOfThreads; ++i)
            {
                PETHREAD Thread;
                Status = PsLookupThreadByThreadId(Entry->Threads[i].ClientId.UniqueThread, &Thread);
                if(NT_SUCCESS(Status))
                {
                    LONG* CrossThreadFlagsAddress = (LONG*)((ULONG_PTR)Thread + CrossThreadFlagsOffset);
                    if((InterlockedAnd(CrossThreadFlagsAddress, ~PS_CROSS_THREAD_FLAGS_HIDEFROMDBG) & PS_CROSS_THREAD_FLAGS_HIDEFROMDBG) != 0)
                    {
                        NumThreadFlagsStripped++;
                        Log("[TITANHIDE] Stripped ThreadHideFromDebugger flag from PID %u, TID %u!\r\n",
                            Pid, (ULONG)(ULONG_PTR)Entry->Threads[i].ClientId.UniqueThread);
                    }
                    ObDereferenceObject(Thread);
                }
            }
            Found = TRUE;
            break;
        }
        if(Entry->NextEntryOffset == 0)
            break;

        Entry = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)Entry + Entry->NextEntryOffset);
    }

    if(!Found)
    {
        Log("[TITANHIDE] PID %u was not found in the process list!\r\n", Pid);
    }
    else
    {
        if(NumThreadFlagsStripped == 0)
            Log("[TITANHIDE] PID %u does not have any threads with the ThreadHideFromDebugger flag set.\r\n", Pid);
        else
            Log("[TITANHIDE] Stripped ThreadHideFromDebugger flag from %u threads in PID %u!\r\n", NumThreadFlagsStripped, Pid);
    }

    Status = Found ? STATUS_SUCCESS : STATUS_NOT_FOUND;

Exit:
    if(SystemProcessInfo != nullptr)
        ExFreePool(SystemProcessInfo);
    ObDereferenceObject(Process);

    return Status;
}

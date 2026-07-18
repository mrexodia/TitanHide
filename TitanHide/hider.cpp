#include "hider.h"
#include "log.h"
#include "threadhidefromdbg.h"
#include "hooks.h"

struct HIDE_ENTRY
{
    ULONG Type;
    ULONG Pid;
};

#define MAX_HIDE_ENTRIES 65536

static HIDE_ENTRY HideEntries[MAX_HIDE_ENTRIES];
static LONG TotalHideEntries = 0;
static KSPIN_LOCK HideEntriesLock;

//entry management
static void EntryAdd(HIDE_ENTRY* NewEntry)
{
    if(TotalHideEntries >= MAX_HIDE_ENTRIES)
        return;
    RtlCopyMemory(&HideEntries[TotalHideEntries], &NewEntry[0], sizeof(HIDE_ENTRY));
    int NewTotalHideEntries = TotalHideEntries + 1;
    InterlockedExchange(&TotalHideEntries, NewTotalHideEntries);
}

static void EntryClear()
{
    InterlockedExchange(&TotalHideEntries, 0);
}

static void EntryDel(int EntryIndex)
{
    if(EntryIndex < TotalHideEntries)
    {
        int NewTotalHideEntries = TotalHideEntries - 1;
        if(!NewTotalHideEntries)  //nothing left
        {
            EntryClear();
            return;
        }
        // Entry order is irrelevant; replace the removed slot with the last
        // entry so updates remain bounded while the spin lock is held.
        HideEntries[EntryIndex] = HideEntries[NewTotalHideEntries];
        InterlockedExchange(&TotalHideEntries, NewTotalHideEntries);
    }
}

static int EntryFind(ULONG Pid)
{
    for(int i = 0; i < TotalHideEntries; i++)
    {
        if(HideEntries[i].Pid == Pid)
        {
            return i;
        }
    }
    return -1;
}

static ULONG EntryGet(int EntryIndex)
{
    ULONG Type = 0;
    if(EntryIndex < TotalHideEntries)
    {
        Type = HideEntries[EntryIndex].Type;
    }
    return Type;
}

static void EntrySet(int EntryIndex, ULONG Type)
{
    if(EntryIndex < TotalHideEntries)
    {
        HideEntries[EntryIndex].Type |= Type;
    }
}

static void EntryUnset(int EntryIndex, ULONG Type)
{
    if(EntryIndex < TotalHideEntries)
    {
        HideEntries[EntryIndex].Type &= ~Type;
    }
}

//usable functions
void Hider::Initialize()
{
    KeInitializeSpinLock(&HideEntriesLock);
    TotalHideEntries = 0;
}

bool Hider::ProcessData(PVOID Buffer, ULONG Size)
{
    if(Size % sizeof(HIDE_INFO))
        return false;
    size_t HideInfoCount = Size / sizeof(HIDE_INFO);
    HIDE_INFO* HideInfo = (HIDE_INFO*)Buffer;
    for(size_t i = 0; i < HideInfoCount; i++)
    {
        switch(HideInfo[i].Command)
        {
        case HidePid:
        {
            KIRQL Irql;
            KeAcquireSpinLock(&HideEntriesLock, &Irql);
            int FoundEntry = EntryFind(HideInfo[i].Pid);
            if(FoundEntry == -1)
            {
                HIDE_ENTRY HideEntry;
                HideEntry.Pid = HideInfo[i].Pid;
                HideEntry.Type = HideInfo[i].Type;
                EntryAdd(&HideEntry);
            }
            else
            {
                EntrySet(FoundEntry, HideInfo[i].Type);
            }
            KeReleaseSpinLock(&HideEntriesLock, Irql);

            // Use DKOM to disable HideThreadHideFromDebugger in any threads in the target process that already have this flag set
            if((HideInfo[i].Type & (ULONG)HideThreadHideFromDebugger) != 0 && CrossThreadFlagsOffset != 0)
            {
                const NTSTATUS Status = UndoHideFromDebuggerInRunningThreads(HideInfo[i].Pid);
                if(!NT_SUCCESS(Status))
                {
                    Log("[TITANHIDE] Failed to undo HideThreadHideFromDebugger in running threads! Status = 0x%08lX\n", Status);
                }
            }
        }
        break;

        case UnhidePid:
        {
            KIRQL Irql;
            KeAcquireSpinLock(&HideEntriesLock, &Irql);
            int FoundEntry = EntryFind(HideInfo[i].Pid);
            if(FoundEntry != -1)
            {
                EntryUnset(FoundEntry, HideInfo[i].Type);
                if(!EntryGet(FoundEntry))  //nothing left to hide for PID
                    EntryDel(FoundEntry);
            }
            KeReleaseSpinLock(&HideEntriesLock, Irql);
            if((HideInfo[i].Type & (ULONG)HideThreadHideFromDebugger) != 0)
                Hooks::ClearVirtualThreadHides(HideInfo[i].Pid, false);
        }
        break;

        case UnhideAll:
        {
            KIRQL Irql;
            KeAcquireSpinLock(&HideEntriesLock, &Irql);
            EntryClear();
            KeReleaseSpinLock(&HideEntriesLock, Irql);
            Hooks::ClearVirtualThreadHides(0, true);
        }
        break;
        }
    }
    return true;
}

bool Hider::IsHidden(ULONG Pid, HIDE_TYPE Type)
{
    bool Hidden = false;
    KIRQL Irql;
    KeAcquireSpinLock(&HideEntriesLock, &Irql);
    int FoundEntry = EntryFind(Pid);
    if(FoundEntry != -1)
    {
        ULONG uType = (ULONG)Type;
        Hidden = (EntryGet(FoundEntry) & uType) == uType;
    }
    KeReleaseSpinLock(&HideEntriesLock, Irql);
    return Hidden;
}
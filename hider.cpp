#include "hider.h"
#include "misc.h"

static HIDE_ENTRY* HideEntries=0;
static int TotalHideEntries=0;

//simple locking library
static FAST_MUTEX* FastMutex=0;

static void lock()
{
    /*if(!FastMutex)
        ExInitializeFastMutex(FastMutex);
    ExAcquireFastMutex(FastMutex);*/
}

static void unlock()
{
    //ExReleaseFastMutex(FastMutex);
}

//entry management
static void EntryAdd(HIDE_ENTRY* NewEntry)
{
    lock();
    int NewTotalHideEntries=TotalHideEntries+1;
    HIDE_ENTRY* NewHideEntries=(HIDE_ENTRY*)RtlAllocateMemory(true, NewTotalHideEntries*sizeof(HIDE_ENTRY));
    if(!NewHideEntries)
    {
        unlock();
        return;
    }
    RtlCopyMemory(&NewHideEntries[0], &HideEntries[0], TotalHideEntries*sizeof(HIDE_ENTRY));
    RtlCopyMemory(&NewHideEntries[TotalHideEntries], &NewEntry[0], sizeof(HIDE_ENTRY));
    if(HideEntries)
        RtlFreeMemory(HideEntries);
    HideEntries=NewHideEntries;
    TotalHideEntries=NewTotalHideEntries;
    unlock();
}

static void EntryDel(int EntryIndex)
{
    lock();
    if(EntryIndex<TotalHideEntries && HideEntries)
    {
        int NewTotalHideEntries=TotalHideEntries-1;
        HIDE_ENTRY* NewHideEntries=(HIDE_ENTRY*)RtlAllocateMemory(true, NewTotalHideEntries*sizeof(HIDE_ENTRY));
        if(!NewHideEntries)
        {
            unlock();
            return;
        }
        if(!EntryIndex)
            RtlCopyMemory(&NewHideEntries[0], &HideEntries[1], NewTotalHideEntries*sizeof(HIDE_ENTRY));
        else
        {
            RtlCopyMemory(&NewHideEntries[0], &HideEntries[0], EntryIndex*sizeof(HIDE_ENTRY));
            RtlCopyMemory(&NewHideEntries[EntryIndex], &HideEntries[EntryIndex+1], (NewTotalHideEntries-EntryIndex)*sizeof(HIDE_ENTRY));
        }
        RtlCopyMemory(NewHideEntries, HideEntries, TotalHideEntries*sizeof(HIDE_ENTRY));
        RtlFreeMemory(HideEntries);
        HideEntries=NewHideEntries;
        TotalHideEntries=NewTotalHideEntries;
    }
    unlock();
}

static void EntrySet(int EntryIndex, ULONG Type)
{
    lock();
    if(EntryIndex<TotalHideEntries && HideEntries)
    {
        HideEntries[EntryIndex].Type|=Type;
    }
    unlock();
}

static void EntryUnset(int EntryIndex, ULONG Type)
{
    lock();
    if(EntryIndex<TotalHideEntries && HideEntries)
    {
        HideEntries[EntryIndex].Type&=~Type;
    }
    unlock();
}

static int EntryFind(ULONG Pid)
{
    lock();
    if(!HideEntries)
    {
        unlock();
        return -1;
    }
    for(int i=0; i<TotalHideEntries; i++)
    {
        if(HideEntries[i].Pid==Pid)
        {
            unlock();
            return i;
        }
    }
    unlock();
    return -1;
}

static void EntryClear()
{
    lock();
    TotalHideEntries=0;
    if(HideEntries)
        RtlFreeMemory(HideEntries);
    unlock();
}

static ULONG EntryGet(int EntryIndex)
{
    ULONG Type=0;
    lock();
    if(EntryIndex<TotalHideEntries && HideEntries)
    {
        Type=HideEntries[EntryIndex].Type;
    }
    unlock();
    return Type;
}

//usable functions
bool HiderProcessData(PVOID Buffer, ULONG Size)
{
    if(Size%sizeof(HIDE_INFO))
        return false;
    int HideInfoCount=Size/sizeof(HIDE_INFO);
    HIDE_INFO* HideInfo=(HIDE_INFO*)Buffer;
    for(int i=0; i<HideInfoCount; i++)
    {
        switch(HideInfo[i].Command)
        {
        case HidePid:
        {
            int FoundEntry=EntryFind(HideInfo[i].Pid);
            if(FoundEntry==-1)
            {
                HIDE_ENTRY HideEntry;
                HideEntry.Pid=HideInfo[i].Pid;
                HideEntry.Type=HideInfo[i].Type;
                HideEntry.Arg=HideInfo[i].Arg;
                EntryAdd(&HideEntry);
            }
            else
            {
                EntrySet(FoundEntry, HideInfo[i].Type);
            }
        }
        break;

        case UnhidePid:
        {
            int FoundEntry=EntryFind(HideInfo[i].Pid);
            if(FoundEntry!=-1)
            {
                EntryUnset(FoundEntry, HideInfo[i].Type);
                if(!EntryGet(FoundEntry)) //nothing left to hide for PID
                    EntryDel(FoundEntry);
            }
        }
        break;

        case UnhideAll:
        {
            EntryClear();
        }
        break;
        }
    }
    return true;
}

bool HiderIsHidden(ULONG Pid, HIDE_TYPE Type)
{
    int FoundEntry=EntryFind(Pid);
    if(FoundEntry==-1)
        return false;
    ULONG uType=(ULONG)Type;
    if((EntryGet(FoundEntry)&uType)==uType)
        return true;
    return false;
}
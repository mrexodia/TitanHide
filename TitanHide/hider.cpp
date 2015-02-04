#include "hider.h"

struct HIDE_ENTRY
{
	ULONG Type;
	ULONG Pid;
};

#define MAX_HIDE_ENTRIES 65536

static HIDE_ENTRY HideEntries[MAX_HIDE_ENTRIES];
static LONG TotalHideEntries = 0;

//entry management
static void EntryAdd(HIDE_ENTRY* NewEntry)
{
	if (TotalHideEntries >= MAX_HIDE_ENTRIES || !HideEntries)
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
	if (EntryIndex < TotalHideEntries && HideEntries)
	{
		int NewTotalHideEntries = TotalHideEntries - 1;
		if (!NewTotalHideEntries) //nothing left
		{
			EntryClear();
			return;
		}
		if (!EntryIndex)
			RtlCopyMemory(&HideEntries[0], &HideEntries[1], NewTotalHideEntries * sizeof(HIDE_ENTRY));
		else
		{
			RtlCopyMemory(&HideEntries[EntryIndex], &HideEntries[EntryIndex + 1], (NewTotalHideEntries - EntryIndex)*sizeof(HIDE_ENTRY));
		}
		InterlockedExchange(&TotalHideEntries, NewTotalHideEntries);
	}
}

static int EntryFind(ULONG Pid)
{
	for (int i = 0; i < TotalHideEntries; i++)
	{
		if (HideEntries[i].Pid == Pid)
		{
			return i;
		}
	}
	return -1;
}

static ULONG EntryGet(int EntryIndex)
{
	ULONG Type = 0;
	if (EntryIndex < TotalHideEntries && HideEntries)
	{
		Type = HideEntries[EntryIndex].Type;
	}
	return Type;
}

static void EntrySet(int EntryIndex, ULONG Type)
{
	if (EntryIndex < TotalHideEntries && HideEntries)
	{
		HideEntries[EntryIndex].Type |= Type;
	}
}

static void EntryUnset(int EntryIndex, ULONG Type)
{
	if (EntryIndex < TotalHideEntries && HideEntries)
	{
		HideEntries[EntryIndex].Type &= ~Type;
	}
}

//usable functions
bool Hider::ProcessData(PVOID Buffer, ULONG Size)
{
	if (Size % sizeof(HIDE_INFO))
		return false;
	int HideInfoCount = Size / sizeof(HIDE_INFO);
	HIDE_INFO* HideInfo = (HIDE_INFO*)Buffer;
	for (int i = 0; i < HideInfoCount; i++)
	{
		switch (HideInfo[i].Command)
		{
		case HidePid:
		{
			int FoundEntry = EntryFind(HideInfo[i].Pid);
			if (FoundEntry == -1)
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
		}
			break;

		case UnhidePid:
		{
			int FoundEntry = EntryFind(HideInfo[i].Pid);
			if (FoundEntry != -1)
			{
				EntryUnset(FoundEntry, HideInfo[i].Type);
				if (!EntryGet(FoundEntry)) //nothing left to hide for PID
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

bool Hider::IsHidden(ULONG Pid, HIDE_TYPE Type)
{
	int FoundEntry = EntryFind(Pid);
	if (FoundEntry == -1)
		return false;
	ULONG uType = (ULONG)Type;
	if ((EntryGet(FoundEntry)&uType) == uType)
		return true;
	return false;
}
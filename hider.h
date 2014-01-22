#ifndef _HIDER_H
#define _HIDER_H

#include <ntddk.h>

#define BIT(x) (1<<(x-1))

//enums
enum HIDE_TYPE
{
    HideProcessDebugFlags=BIT(1), //NtQueryInformationProcess
    HideProcessDebugPort=BIT(2), //NtQueryInformationProcess
    HideProcessDebugObjectHandle=BIT(3), //NtQueryInformationProcess
    HideDebugObject=BIT(4) //NtQueryObject
};

enum HIDE_COMMAND
{
    HidePid, //Hide a process
    UnhidePid, //Unhide a process
    UnhideAll //Unhide everything
};

//structures
struct HIDE_INFO
{
    HIDE_COMMAND Command;
    ULONG Type;
    ULONG Pid;
    ULONG Arg;
};

struct HIDE_ENTRY
{
    ULONG Type;
    ULONG Pid;
    ULONG Arg;
};

bool HiderProcessData(PVOID Buffer, ULONG Size);
bool HiderIsHidden(ULONG Pid, HIDE_TYPE Type);

#endif
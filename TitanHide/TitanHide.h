#ifndef _TITANHIDE_H
#define _TITANHIDE_H

#define BIT(x) (1<<(x-1))

//enums
enum HIDE_TYPE
{
	HideProcessDebugFlags = BIT(1), //NtQueryInformationProcess
	HideProcessDebugPort = BIT(2), //NtQueryInformationProcess
	HideProcessDebugObjectHandle = BIT(3), //NtQueryInformationProcess
	HideDebugObject = BIT(4), //NtQueryObject
	HideSystemDebuggerInformation = BIT(5), //NtQuerySystemInformation
	HideNtClose = BIT(6), //NtClose
	HideThreadHideFromDebugger = BIT(7), //NtSetInformationThread
	HideNtSetContextThread = BIT(8), //NtSetContextThread
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
};

#endif // _TITANHIDE_H

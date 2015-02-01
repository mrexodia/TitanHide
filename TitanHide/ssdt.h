#ifndef _SSDT_H
#define _SSDT_H

#include "_global.h"
#include "hooklib.h"

//structures
struct SSDTStruct
{
	PVOID pServiceTable;
	PVOID pCounterTable;
#ifdef _WIN64
	ULONGLONG NumberOfServices;
#else
	ULONG NumberOfServices;
#endif
	PCHAR pArgumentTable;
};

//functions
PVOID SSDTgpa(const wchar_t* apiname);
HOOK SSDThook(const wchar_t* apiname, void* newfunc);
void SSDThook(HOOK hHook);
void SSDTunhook(HOOK hHook, bool free);
void SSDTunhook(HOOK hHook);

#endif
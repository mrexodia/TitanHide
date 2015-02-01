#ifndef _HIDER_H
#define _HIDER_H

#include "_global.h"
#include "TitanHide.h"

struct HIDE_ENTRY
{
	ULONG Type;
	ULONG Pid;
};

bool HiderProcessData(PVOID Buffer, ULONG Size);
bool HiderIsHidden(ULONG Pid, HIDE_TYPE Type);

#endif
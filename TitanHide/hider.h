#ifndef _HIDER_H
#define _HIDER_H

#include "_global.h"
#include "TitanHide.h"

class Hider
{
public:
	static bool ProcessData(PVOID Buffer, ULONG Size);
	static bool IsHidden(ULONG Pid, HIDE_TYPE Type);
};

#endif
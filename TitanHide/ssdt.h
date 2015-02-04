#ifndef _SSDT_H
#define _SSDT_H

#include "_global.h"
#include "hooklib.h"

class SSDT
{
public:
	static PVOID GetFunctionAddress(const char* apiname);
	static HOOK Hook(const char* apiname, void* newfunc);
	static void Hook(HOOK hHook);
	static void Unhook(HOOK hHook, bool free = false);
};

#endif
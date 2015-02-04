#ifndef _MISC_H
#define _MISC_H

#include "_global.h"

class Misc
{
public:
	static ULONG GetProcessIDFromProcessHandle(HANDLE ProcessHandle);
	static ULONG GetProcessIDFromThreadHandle(HANDLE ThreadHandle);
};

#endif
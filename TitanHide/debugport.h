#ifndef _DEBUGPORT_H
#define _DEBUGPORT_H

#include "_global.h"

class DebugPort
{
public:
	static PVOID Set(PEPROCESS Process, PVOID DebugPort);
};

#endif //_DEBUGPORT_H
#ifndef _HOOKS_H
#define _HOOKS_H

#include "_global.h"

class Hooks
{
public:
    static int Initialize();
    static void Deinitialize();
    static bool RegisterVirtualThreadHide(PETHREAD Thread);
    static void ClearVirtualThreadHides(ULONG ProcessId, bool AllProcesses);
};

#endif
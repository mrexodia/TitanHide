#pragma once

#include "_global.h"

extern ULONG CrossThreadFlagsOffset;

extern "C"
{
    NTSTATUS FindCrossThreadFlagsOffset(_Out_ PULONG Offset);
    NTSTATUS UndoHideFromDebuggerInRunningThreads(_In_ ULONG Pid);
}

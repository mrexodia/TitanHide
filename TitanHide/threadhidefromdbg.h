#pragma once

#include "_global.h"

extern ULONG CrossThreadFlagsOffset;

extern "C"
{
    NTSTATUS FindCrossThreadFlagsOffset(_Out_ PULONG Offset);
    VOID RestoreHideFromDebugger(_In_ PETHREAD Thread);
    NTSTATUS UndoHideFromDebuggerInRunningThreads(_In_ ULONG Pid);
}

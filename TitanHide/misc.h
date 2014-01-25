#ifndef _MISC_H
#define _MISC_H

#include "_global.h"

void* RtlAllocateMemory(bool InZeroMemory, SIZE_T InSize);
void RtlFreeMemory(void* InPointer);
ULONG GetProcessIDFromProcessHandle(HANDLE ProcessHandle);
ULONG GetProcessIDFromThreadHandle(HANDLE ThreadHandle);

#endif
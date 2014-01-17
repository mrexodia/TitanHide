#ifndef _MISC_H
#define _MISC_H

#include <ntddk.h>

void* RtlAllocateMemory(bool InZeroMemory, SIZE_T InSize);
void RtlFreeMemory(void* InPointer);

#endif
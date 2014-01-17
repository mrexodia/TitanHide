#include "misc.h"

void* RtlAllocateMemory(bool InZeroMemory, SIZE_T InSize)
{
    void* Result=ExAllocatePoolWithTag(NonPagedPool, InSize, 'HOOK');
    if(InZeroMemory && (Result!=NULL))
        RtlZeroMemory(Result, InSize);
    return Result;
}

void RtlFreeMemory(void* InPointer)
{
	ExFreePool(InPointer);
}
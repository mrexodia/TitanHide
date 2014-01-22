#include "misc.h"
#include "stdafx.h"

void* RtlAllocateMemory(bool InZeroMemory, SIZE_T InSize)
{
    void* Result=ExAllocatePoolWithTag(NonPagedPool, InSize, 'HIDE');
    if(InZeroMemory && (Result!=NULL))
        RtlZeroMemory(Result, InSize);
    return Result;
}

void RtlFreeMemory(void* InPointer)
{
    ExFreePool(InPointer);
}

#ifndef _SSDT_H
#define _SSDT_H

#include <ntddk.h>

//structures
struct SSDTStruct
{ 
    PVOID pServiceTable;
    PVOID pCounterTable;
#ifdef _WIN64
    ULONGLONG NumberOfServices;
#else
    ULONG NumberOfServices;
#endif
    PCHAR pArgumentTable;
};

//functions
bool SSDTinit();
PVOID SSDTfind();
PVOID SSDTgpa(const char* apiname);

#endif
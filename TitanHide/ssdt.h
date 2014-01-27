#ifndef _SSDT_H
#define _SSDT_H

#include "_global.h"

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
PVOID SSDTgpa(const wchar_t* apiname);

#endif
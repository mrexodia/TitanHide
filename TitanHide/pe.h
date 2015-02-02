#ifndef _PE_H
#define _PE_H

#include "_global.h"

#define PE_ERROR_VALUE (ULONG_PTR)-1

PVOID PeGetPageBase(PVOID lpHeader, ULONG* Size, PVOID ptr);
ULONG_PTR GetExportOffset(const unsigned char* FileData, ULONG_PTR FileSize, const char* ExportName);

#endif
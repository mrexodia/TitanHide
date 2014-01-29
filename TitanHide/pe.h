#ifndef _PE_H
#define _PE_H

#include <windef.h>

PVOID PeGetPageBase(PVOID lpHeader, ULONG* Size, PVOID ptr);

#endif
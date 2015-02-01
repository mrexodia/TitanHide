#ifndef _PE_H
#define _PE_H

#include "_global.h"

PVOID PeGetPageBase(PVOID lpHeader, ULONG* Size, PVOID ptr);

#endif
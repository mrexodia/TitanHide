#ifndef _GLOBAL_H
#define _GLOBAL_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#ifdef __cplusplus
extern "C" 
{
#endif

#include "VisualDDKHelpers.h"
#include <ntddk.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>

#ifdef __cplusplus
}
#endif

#ifdef _WIN64
typedef unsigned long long duint;
typedef signed long long dsint;
#else
typedef unsigned long duint;
typedef signed long dsint;
#endif //_WIN64

#define BIT(x) (1<<(x-1))

#endif
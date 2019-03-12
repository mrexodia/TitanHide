#ifndef _LOG_H
#define _LOG_H

#include "_global.h"

#if defined(__RESHARPER__)
#define PRINTF_ATTR(FormatIndex, FirstToCheck) \
    [[gnu::format(printf, FormatIndex, FirstToCheck)]]
#elif defined(__GNUC__)
#define PRINTF_ATTR(FormatIndex, FirstToCheck) \
    __attribute__((format(printf, FormatIndex, FirstToCheck)))
#else
#define PRINTF_ATTR(FormatIndex, FirstToCheck)
#endif

PRINTF_ATTR(1, 2) void Log(const char* format, ...);

#endif
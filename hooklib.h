#ifndef _HOOKLIB_H_
#define _HOOKLIB_H_

#include <ntddk.h>

#ifdef _WIN64
typedef unsigned long long duint;
typedef signed long long dsint;
#else
typedef unsigned long duint;
typedef signed long dsint;
#endif //_WIN64

#pragma pack(push,1)
struct opcode
{
#ifdef _WIN64
    unsigned short int mov;
#else
    unsigned char mov;
#endif
    duint addr;
    unsigned char push;
    unsigned char ret;
};
#pragma pack(pop)

struct hookstruct
{
    duint addr;
    opcode hook;
    unsigned char orig[sizeof(opcode)];
};

typedef hookstruct* HOOK;

int init_hook();
VOID uninit_hook();
HOOK hook(PVOID api, void* newfunc);
HOOK hook(wchar_t* api, void* newfunc);
bool unhook(HOOK hook, bool free);
bool unhook(HOOK hook);
bool hook(HOOK hook);

#endif //_HOOKLIB_H_

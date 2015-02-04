#ifndef _HOOKLIB_H_
#define _HOOKLIB_H_

#include "_global.h"

#pragma pack(push,1)
struct HOOKOPCODES
{
#ifdef _WIN64
	unsigned short int mov;
#else
	unsigned char mov;
#endif
	ULONG_PTR addr;
	unsigned char push;
	unsigned char ret;
};
#pragma pack(pop)

typedef struct HOOKSTRUCT
{
	ULONG_PTR addr;
	HOOKOPCODES hook;
	unsigned char orig[sizeof(HOOKOPCODES)];
	//SSDT extension
	int SSDTindex;
	ULONG SSDTold;
	ULONG SSDTnew;
	ULONG_PTR SSDTaddress;
} *HOOK;

class Hooklib
{
public:
	static HOOK Hook(PVOID api, void* newfunc);
	static bool Hook(HOOK hook);
	static bool Unhook(HOOK hook, bool free = false);
};

#endif //_HOOKLIB_H_

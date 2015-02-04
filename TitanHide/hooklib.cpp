#include "hooklib.h"
#include "log.h"

static HOOK hook_internal(ULONG_PTR addr, void* newfunc)
{
	//allocate structure
	HOOK hook = (HOOK)RtlAllocateMemory(true, sizeof(hookstruct));
	//set hooking address
	hook->addr = addr;
	//set hooking opcode
#ifdef _WIN64
	hook->hook.mov = 0xB848;
#else
	hook->hook.mov = 0xB8;
#endif
	hook->hook.addr = (ULONG_PTR)newfunc;
	hook->hook.push = 0x50;
	hook->hook.ret = 0xc3;
	//set original data
	RtlCopyMemory(&hook->orig, (const void*)addr, sizeof(opcode));
	if (!NT_SUCCESS(RtlSuperCopyMemory((void*)addr, &hook->hook, sizeof(opcode))))
	{
		RtlFreeMemory(hook);
		return 0;
	}
	return hook;
}

HOOK hook(PVOID api, void* newfunc)
{
	ULONG_PTR addr = (ULONG_PTR)api;
	if (!addr)
		return 0;
	Log("[TITANHIDE] hook(0x%p, 0x%p)\n", addr, newfunc);
	return hook_internal(addr, newfunc);
}

bool unhook(HOOK hook, bool free)
{
	if (!hook || !hook->addr)
		return false;
	if (NT_SUCCESS(RtlSuperCopyMemory((void*)hook->addr, hook->orig, sizeof(opcode))))
	{
		if (free)
			RtlFreeMemory(hook);
		return true;
	}
	return false;
}

bool hook(HOOK hook)
{
	if (!hook)
		return false;
	return (NT_SUCCESS(RtlSuperCopyMemory((void*)hook->addr, &hook->hook, sizeof(opcode))));
}

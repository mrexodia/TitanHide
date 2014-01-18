#include "hooklib.h"
#include "misc.h"
#include "stdafx.h"

static NTSTATUS SuperRtlCopyMemory(IN VOID UNALIGNED *Destination, IN CONST VOID UNALIGNED *Source, IN SIZE_T Length)
{
    //Change memory properties.
    PMDL g_pmdl = IoAllocateMdl(Destination, sizeof(opcode), 0, 0, NULL);
    if(!g_pmdl)
        return STATUS_UNSUCCESSFUL;
    MmBuildMdlForNonPagedPool(g_pmdl);
    unsigned int* Mapped=(unsigned int*)MmMapLockedPages(g_pmdl, KernelMode);
    if(!Mapped)
        return STATUS_UNSUCCESSFUL;
    KIRQL kirql=KeRaiseIrqlToDpcLevel();
    RtlCopyMemory(Mapped, Source, Length);
    KeLowerIrql(kirql);
    //Restore memory properties.
    if(g_pmdl)
    {
        MmUnmapLockedPages((PVOID)Mapped, g_pmdl);
        IoFreeMdl(g_pmdl);
    }
    return STATUS_SUCCESS;
}

static void* gpa(wchar_t* proc)
{
	if(!proc)
		return 0;
	UNICODE_STRING usfn;
    RtlInitUnicodeString(&usfn, proc);
    return MmGetSystemRoutineAddress(&usfn);
}

HOOK hook(wchar_t* api, void* newfunc)
{
	duint addr=(duint)gpa(api);
	if(!addr)
		return 0;
	DbgPrint("[TESTDRIVER] hook(%ws:0x%p, 0x%p)\n", api, addr, newfunc);
	//allocate structure
	HOOK hook=(HOOK)RtlAllocateMemory(true, sizeof(hookstruct));
	//set hooking address
	hook->addr=addr;
	//set hooking opcode
#ifdef _WIN64
	hook->hook.mov=0xB848;
#else
	hook->hook.mov=0xB8;
#endif
	hook->hook.addr=(duint)newfunc;
    hook->hook.push=0x50;
    hook->hook.ret=0xc3;
	//set original data
	RtlCopyMemory(&hook->orig, (const void*)addr, sizeof(opcode));
	if(!NT_SUCCESS(SuperRtlCopyMemory((void*)addr, &hook->hook, sizeof(opcode))))
	{
		RtlFreeMemory(hook);
		return 0;
	}
	return hook;
}

bool unhook(HOOK hook, bool free)
{
	if(!hook)
		return false;
	if(NT_SUCCESS(SuperRtlCopyMemory((void*)hook->addr, hook->orig, sizeof(opcode))))
	{
		if(free)
			RtlFreeMemory(hook);
		return true;
	}
	return false;
}

bool unhook(HOOK hook)
{
	return unhook(hook, false);
}

bool hook(HOOK hook)
{
	if(!hook)
		return false;
	return (NT_SUCCESS(SuperRtlCopyMemory((void*)hook->addr, &hook->hook, sizeof(opcode))));
}

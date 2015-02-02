#include "hooklib.h"
#include "misc.h"
#include "ssdt.h"
#include "log.h"

//Based on: http://leguanyuan.blogspot.nl/2013/09/x64-inline-hook-zwcreatesection.html

static NTSTATUS SuperRtlCopyMemory(IN VOID UNALIGNED* Destination, IN CONST VOID UNALIGNED* Source, IN SIZE_T Length)
{
	//Change memory properties.
	PMDL g_pmdl = IoAllocateMdl(Destination, sizeof(opcode), 0, 0, NULL);
	if (!g_pmdl)
		return STATUS_UNSUCCESSFUL;
	MmBuildMdlForNonPagedPool(g_pmdl);
	unsigned int* Mapped = (unsigned int*)MmMapLockedPages(g_pmdl, KernelMode);
	if (!Mapped)
	{
		IoFreeMdl(g_pmdl);
		return STATUS_UNSUCCESSFUL;
	}
	KIRQL kirql = KeRaiseIrqlToDpcLevel();
	RtlCopyMemory(Mapped, Source, Length);
	KeLowerIrql(kirql);
	//Restore memory properties.
	MmUnmapLockedPages((PVOID)Mapped, g_pmdl);
	IoFreeMdl(g_pmdl);
	return STATUS_SUCCESS;
}

static void* gpa(const wchar_t* proc)
{
	if (!proc)
		return 0;
	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, proc);
	PVOID addr = MmGetSystemRoutineAddress(&routineName);
	if (!addr)
		addr = SSDTgpa(proc);
	if (!addr)
		Log("[TITANHIDE] No such procedure %ws...\n", proc);
	return addr;
}

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
	if (!NT_SUCCESS(SuperRtlCopyMemory((void*)addr, &hook->hook, sizeof(opcode))))
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

HOOK hook(const wchar_t* api, void* newfunc)
{
	ULONG_PTR addr = (ULONG_PTR)gpa(api);
	if (!addr)
		return 0;
	Log("[TITANHIDE] hook(%ws:0x%p, 0x%p)\n", api, addr, newfunc);
	return hook_internal(addr, newfunc);
}

bool unhook(HOOK hook, bool free)
{
	if (!hook || !hook->addr)
		return false;
	if (NT_SUCCESS(SuperRtlCopyMemory((void*)hook->addr, hook->orig, sizeof(opcode))))
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
	return (NT_SUCCESS(SuperRtlCopyMemory((void*)hook->addr, &hook->hook, sizeof(opcode))));
}

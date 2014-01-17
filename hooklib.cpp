#include "hooklib.h"
#include "misc.h"

/*
x64 inline hook ZwCreateSection.
Why not x64 ssdt hook, reasons ? :
1.ssdt function inside less .
2 Microsoft's official statement , this will patchguard detected and blue .
3.ssdt not exported , so you need to get .

made by correy
made at 2013.09.06
email: kouleguan at hotmail dot com
homepage: http://correy.webs.com
*/

/*
The code test environment : windows server 2008 R2 X64
Test object : ZwCreateSection

0: kd> vertarget
Windows 7 Kernel Version 7601 (Service Pack 1) MP (2 procs) Free x64
Product: Server, suite: Enterprise TerminalServer SingleUserTS
Built by: 7601.18205.amd64fre.win7sp1_gdr.130708-1532
Machine Name:
Kernel base = 0xfffff800`01617000 PsLoadedModuleList = 0xfffff800`0185a6d0
Debug session time: Thu Sep  5 20:21:57.396 2013 (UTC + 8:00)
System Uptime: 0 days 0:11:39.021
0: kd> u nt!ZwCreateSection
nt!ZwCreateSection:
fffff800`016c3a60 488bc4          mov     rax,rsp
fffff800`016c3a63 fa              cli
fffff800`016c3a64 4883ec10        sub     rsp,10h
fffff800`016c3a68 50              push    rax
fffff800`016c3a69 9c              pushfq
fffff800`016c3a6a 6a10            push    10h
fffff800`016c3a6c 488d055d290000  lea     rax,[nt!KiServiceLinkage (fffff800`016c63d0)]
fffff800`016c3a73 50              push    rax
*/

/*
After compilation , the search found the following machine code . Prompted by push 0x9999999999 is not acceptable. Only one byte.
48b89999999909000000 mov rax, 999999999h
50 push rax
c3 retn
retn nothing should affect the experiment it !

The 12 bytes , just the first few instructions ZwCreateSection of correspondence .
If you do not correspond to the back you can add NOP.
*/
/*#pragma pack(1) //this line is essential.
#ifdef _WIN64
typedef struct _opcode
{
    unsigned short int mov_rax;
    unsigned __int64 my_fn;
    unsigned char push_rax;
    unsigned char retn;
} opcode, *popcode;
#else
typedef struct _opcode
{
    unsigned char mov_eax;
    unsigned int my_fn;
    unsigned char push_eax;
    unsigned char retn;
} opcode, *popcode;
#endif*/

//global variables
/*opcode g_op;
unsigned char g_original[sizeof(opcode)];//save function for the first few bytes.
int hooked = 0;
PVOID g_pfn = 0;*/

NTSTATUS SuperRtlCopyMemory(IN VOID UNALIGNED *Destination, IN CONST VOID UNALIGNED *Source, IN SIZE_T Length)
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

/*NTSTATUS MyZwOpenProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    // Can also bu nt!ZwOpenProcess, to see whether there jump to here.
    //KdBreakPoint();//DbgBreakPoint()

    //This is an example : print a message, and then backtrack , no filtering .

    DbgPrint("[TESTDRIVER] ZwOpenProcess(%u)\n", (ULONG)ProcessHandle);

    SuperRtlCopyMemory(g_pfn, g_original, sizeof(opcode));

    //Doubt between two SuperRtlCopyMemory function call , and then call occurs ZwCreateSection estimated to be less than the intercept .
    status = ZwOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

    SuperRtlCopyMemory(g_pfn, &g_op, sizeof(opcode));

    //if (0) // if rejected
    //{
    //    //Direct return to , need not be complicated operation to the next row. Note that this does not test .
    //    //Set ZwOpenProcess of sizeof (opcode) +1 = 0xc3, so that the main function returns.
    //}
    //else
    //{
    //    //Restore settings ( plus DPC and memory read and write ) , including : ZwOpenProcess of sizeof (opcode) +1 = 0xc3 recovery.
    //    //Call the original function . / / Allowed else in the call this time the function has been completed.
    //    //Set the hook. ( Plus DPC and memory read and write )
    //}

    return status;
}*/

static void* gpa(wchar_t* proc)
{
	if(!proc)
		return 0;
	UNICODE_STRING usfn;
    RtlInitUnicodeString(&usfn, proc);
    return MmGetSystemRoutineAddress(&usfn);
}

/*NTSTATUS hook_(wchar_t * pfn, unsigned __int64 p_my_fn)
{
    g_pfn = gpa(pfn);
    if (g_pfn == NULL)
    {
        return STATUS_UNSUCCESSFUL;
    }

#ifdef _WIN64
	g_op.mov = 0xb848;
#else
	g_op.mov = 0xb8;
#endif
	g_op.addr = p_my_fn;
    g_op.push = 0x50;
    g_op.ret = 0xc3;

    RtlCopyMemory(g_original, g_pfn, sizeof(opcode));

    return SuperRtlCopyMemory(g_pfn, &g_op, sizeof(opcode));
}

int init_hook()
{
	if(hooked)
		return 0;
	DbgPrint("[TESTDRIVER] NtQueryInformationProcess: 0x%llX\n", (unsigned __int64)NtQueryInformationProcess);
    //KdBreakPoint();//DbgBreakPoint()
    if(NT_SUCCESS(hook_(L"ZwOpenProcess", (unsigned __int64)MyZwOpenProcess)))
		hooked=1;
	else
		hooked=0;
	return hooked;
}

VOID uninit_hook()
{
	if(hooked)
		SuperRtlCopyMemory(g_pfn, g_original, sizeof(opcode));
}*/

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
	hook->hook.addr=addr;
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

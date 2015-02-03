#include "ssdt.h"
#include "undocumented.h"
#include "misc.h"
#include "pe.h"
#include "log.h"
#include "ntdll.h"

//Based on: https://code.google.com/p/volatility/issues/detail?id=189#c2
static PVOID SSDTfind()
{
	static PVOID SSDT = 0;
	if (!SSDT)
	{
		UNICODE_STRING routineName;
#ifndef _WIN64
		//x86 code
		RtlInitUnicodeString(&routineName, L"KeServiceDescriptorTable");
		SSDT = MmGetSystemRoutineAddress(&routineName);
#else
		//x64 code
		RtlInitUnicodeString(&routineName, L"KeAddSystemServiceTable");
		PVOID KeASST = MmGetSystemRoutineAddress(&routineName);
		if (!KeASST)
			return 0;
		unsigned char function[1024];
		unsigned int function_size = 0;
		RtlCopyMemory(function, KeASST, sizeof(function));
		for (unsigned int i = 0; i < sizeof(function); i++)
		{
			if (function[i] == 0xC3)
			{
				function_size = i + 1;
				break;
			}
		}
		if (!function_size)
			return 0;
		unsigned int rvaSSDT = 0;
		for (unsigned int i = 0; i < function_size; i++)
		{
			if (((*(unsigned int*)(function + i)) & 0xFFFFF0) == 0xBC8340 && !*(unsigned char*)(function + i + 8)) //4?83bc?? ???????? 00 cmp qword ptr [r?+r?+????????h],0
			{
				rvaSSDT = *(unsigned int*)(function + i + 4);
				break;
			}
		}
		if (!rvaSSDT)
			return 0;
		Log("[TITANHIDE] SSDT RVA: 0x%X\n", rvaSSDT);
		PVOID base = Undocumented::GetKernelBase();
		if (!base)
		{

			return 0;
		}
		Log("[TITANHIDE] GetKernelBase()->0x%p\n", base);
		SSDT = (PVOID)((unsigned char*)base + rvaSSDT);
#endif
	}
	return SSDT;
}

PVOID SSDTgpa(const char* apiname)
{
	//read address from SSDT
	SSDTStruct* SSDT = (SSDTStruct*)SSDTfind();
	if (!SSDT)
	{
		Log("[TITANHIDE] SSDT not found...\n");
		return 0;
	}
	unsigned long long SSDTbase = (unsigned long long)SSDT->pServiceTable;
	if (!SSDTbase)
	{
		Log("[TITANHIDE] ServiceTable not found...\n");
		return 0;
	}
	ULONG readOffset = Ntdll::GetSsdtOffset(apiname);
	if (readOffset == -1)
		return 0;
	if (readOffset >= SSDT->NumberOfServices)
	{
		Log("[TITANHIDE] Invalid read offset...\n");
		return 0;
	}
#ifdef _WIN64
	return (PVOID)((((LONG*)SSDT->pServiceTable)[readOffset] >> 4) + SSDTbase);
#else
	return (PVOID)((LONG*)SSDT->pServiceTable)[readOffset];
#endif
}

static void InterlockedSet(LONG* Destination, LONG Source)
{
	//Change memory properties.
	PMDL g_pmdl = IoAllocateMdl(Destination, sizeof(LONG), 0, 0, NULL);
	if (!g_pmdl)
		return;
	MmBuildMdlForNonPagedPool(g_pmdl);
	LONG* Mapped = (LONG*)MmMapLockedPages(g_pmdl, KernelMode);
	if (!Mapped)
	{
		IoFreeMdl(g_pmdl);
		return;
	}
	InterlockedExchange(Mapped, Source);
	//Restore memory properties.
	MmUnmapLockedPages((PVOID)Mapped, g_pmdl);
	IoFreeMdl(g_pmdl);
}

#ifdef _WIN64
static PVOID FindCaveAddress(PVOID CodeStart, ULONG CodeSize, ULONG CaveSize)
{
	unsigned char* Code = (unsigned char*)CodeStart;

	for (unsigned int i = 0, j = 0; i < CodeSize; i++)
	{
		if (Code[i] == 0x90 || Code[i] == 0xCC)
			j++;
		else
			j = 0;
		if (j == CaveSize)
			return (PVOID)((ULONG_PTR)CodeStart + i - CaveSize + 1);
	}
	return 0;
}
#endif //_WIN64

HOOK SSDThook(const char* apiname, void* newfunc)
{
	SSDTStruct* SSDT = (SSDTStruct*)SSDTfind();
	if (!SSDT)
	{
		Log("[TITANHIDE] SSDT not found...\n");
		return 0;
	}
	ULONG_PTR SSDTbase = (ULONG_PTR)SSDT->pServiceTable;
	if (!SSDTbase)
	{
		Log("[TITANHIDE] ServiceTable not found...\n");
		return 0;
	}
	ULONG apiOffset = Ntdll::GetSsdtOffset(apiname);
	if (apiOffset == -1)
		return 0;
	if (apiOffset >= SSDT->NumberOfServices)
	{
		Log("[TITANHIDE] Invalid API offset...\n");
		return 0;
	}

	HOOK hHook = 0;
	LONG* SSDT_Table = (LONG*)SSDTbase;
	ULONG oldValue = SSDT_Table[apiOffset];
	ULONG newValue;

#ifdef _WIN64
	/*
	x64 SSDT Hook;
	1) find API addr
	2) get code page+size
	3) find cave address
	4) hook cave address (using hooklib)
	5) change SSDT value
	*/

	static ULONG CodeSize = 0;
	static PVOID CodeStart = 0;
	if (!CodeStart)
	{
		ULONG_PTR Lowest = SSDTbase;
		ULONG_PTR Highest = Lowest + 0x0FFFFFFF;
		Log("[TITANHIDE] Range: 0x%p-0x%p\n", Lowest, Highest);
		CodeSize = 0;
		CodeStart = PeGetPageBase(Undocumented::GetKernelBase(), &CodeSize, (PVOID)((oldValue >> 4) + SSDTbase));
		if (!CodeStart || !CodeSize)
		{
			Log("[TITANHIDE] PeGetPageBase failed...\n");
			return 0;
		}
		Log("[TITANHIDE] CodeStart: 0x%p, CodeSize: 0x%X\n", CodeStart, CodeSize);
		if ((ULONG_PTR)CodeStart < Lowest) //start of the page is out of range (impossible, but whatever)
		{
			CodeSize -= (ULONG)(Lowest - (ULONG_PTR)CodeStart);
			CodeStart = (PVOID)Lowest;
			Log("[TITANHIDE] CodeStart: 0x%p, CodeSize: 0x%X\n", CodeStart, CodeSize);
		}
		Log("[TITANHIDE] Range: 0x%p-0x%p\n", CodeStart, (ULONG_PTR)CodeStart + CodeSize);
	}

	PVOID CaveAddress = FindCaveAddress(CodeStart, CodeSize, sizeof(opcode));
	if (!CaveAddress)
	{
		Log("[TITANHIDE] FindCaveAddress failed...\n");
		return 0;
	}
	Log("[TITANHIDE] CaveAddress: 0x%p\n", CaveAddress);

	hHook = hook(CaveAddress, (void*)newfunc);
	if (!hHook)
		return 0;

	newValue = (ULONG)((ULONG_PTR)CaveAddress - SSDTbase);
	newValue = (newValue << 4) | oldValue & 0xF;

	//update HOOK structure
	hHook->SSDToffset = apiOffset;
	hHook->SSDTold = oldValue;
	hHook->SSDTnew = newValue;
	hHook->SSDTaddress = (oldValue >> 4) + SSDTbase;

#else
	/*
	x86 SSDT Hook:
	1) change SSDT value
	*/
	newValue = (ULONG)newfunc;

	hHook = (HOOK)RtlAllocateMemory(true, sizeof(hookstruct));

	//update HOOK structure
	hHook->SSDToffset = apiOffset;
	hHook->SSDTold = oldValue;
	hHook->SSDTnew = newValue;
	hHook->SSDTaddress = oldValue;

#endif

	InterlockedSet(&SSDT_Table[apiOffset], newValue);

	Log("[TITANHIDE] SSDThook(%s:0x%p, 0x%p)\n", apiname, hHook->SSDTold, hHook->SSDTnew);

	return hHook;
}

void SSDThook(HOOK hHook)
{
	if (!hHook)
		return;
	SSDTStruct* SSDT = (SSDTStruct*)SSDTfind();
	if (!SSDT)
	{
		Log("[TITANHIDE] SSDT not found...\n");
		return;
	}
	LONG* SSDT_Table = (LONG*)SSDT->pServiceTable;
	if (!SSDT_Table)
	{
		Log("[TITANHIDE] ServiceTable not found...\n");
		return;
	}
	InterlockedSet(&SSDT_Table[hHook->SSDToffset], hHook->SSDTnew);
}

void SSDTunhook(HOOK hHook, bool free)
{
	if (!hHook)
		return;
	SSDTStruct* SSDT = (SSDTStruct*)SSDTfind();
	if (!SSDT)
	{
		Log("[TITANHIDE] SSDT not found...\n");
		return;
	}
	LONG* SSDT_Table = (LONG*)SSDT->pServiceTable;
	if (!SSDT_Table)
	{
		Log("[TITANHIDE] ServiceTable not found...\n");
		return;
	}
	InterlockedSet(&SSDT_Table[hHook->SSDToffset], hHook->SSDTold);
#ifdef _WIN64
	if (free)
		unhook(hHook, true);
#else
	UNREFERENCED_PARAMETER(free);
#endif
}
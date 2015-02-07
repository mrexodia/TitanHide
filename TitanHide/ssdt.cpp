#include "ssdt.h"
#include "undocumented.h"
#include "pe.h"
#include "log.h"
#include "ntdll.h"

//structures
struct SSDTStruct
{
	LONG* pServiceTable;
	PVOID pCounterTable;
#ifdef _WIN64
	ULONGLONG NumberOfServices;
#else
	ULONG NumberOfServices;
#endif
	PCHAR pArgumentTable;
};

//Based on: https://code.google.com/p/volatility/issues/detail?id=189#c2
static SSDTStruct* SSDTfind()
{
	static SSDTStruct* SSDT = 0;
	if (!SSDT)
	{
		UNICODE_STRING routineName;
#ifndef _WIN64
		//x86 code
		RtlInitUnicodeString(&routineName, L"KeServiceDescriptorTable");
		SSDT = (SSDTStruct*)MmGetSystemRoutineAddress(&routineName);
#else
		//x64 code
		RtlInitUnicodeString(&routineName, L"KeAddSystemServiceTable");
		PVOID KeASST = MmGetSystemRoutineAddress(&routineName);
		if (!KeASST)
		{
			Log("[TITANHIDE] Failed to find KeAddSystemServiceTable!\n");
			return 0;
		}
		unsigned char function[1024];
		unsigned int function_size = 0;
		RtlCopyMemory(function, KeASST, sizeof(function));
		for (unsigned int i = 0; i < sizeof(function); i++)
		{
			if (function[i] == 0xC3) //ret
			{
				function_size = i + 1;
				break;
			}
		}
		if (!function_size)
		{
			Log("[TITANHIDE] Failed to get function size of KeAddSystemServiceTable!\n");
			return 0;
		}

		/*
		000000014050EA4A 48 C1 E0 05                shl rax, 5
		000000014050EA4E 48 83 BC 18 80 3A 36 00 00 cmp qword ptr [rax+rbx+363A80h], 0 <- we are looking for this instruction
		000000014050EA57 0F 85 B2 5C 0A 00          jnz loc_1405B470F
		000000014050EA5D 48 8D 8B C0 3A 36 00       lea rcx, rva KeServiceDescriptorTableShadow[rbx]
		000000014050EA64 48 03 C8                   add rcx, rax
		000000014050EA67 48 83 39 00                cmp qword ptr [rcx], 0
		*/
		int rvaSSDT = 0;
		for (unsigned int i = 0; i < function_size; i++)
		{
			if (((*(unsigned int*)(function + i)) & 0x00FFFFF0) == 0xBC8340 &&
				!*(unsigned char*)(function + i + 8)) //4?83bc?? ???????? 00 cmp qword ptr [r?+r?+????????h],0
			{
				rvaSSDT = *(int*)(function + i + 4);
				break;
			}
		}
		if (rvaSSDT) //this method worked
		{
			Log("[TITANHIDE] SSDT RVA: 0x%X\n", rvaSSDT);
			PVOID base = Undocumented::GetKernelBase();
			if (!base)
			{
				Log("[TITANHIDE] GetKernelBase() failed!\n");
				return 0;
			}
			Log("[TITANHIDE] GetKernelBase()->0x%p\n", base);
			SSDT = (SSDTStruct*)((unsigned char*)base + rvaSSDT);
		}
		else
		{
			/*
			Windows 10 Technical Preview:
			fffff800e21b30ec 757f             jne nt!KeAddSystemServiceTable+0x91 (fffff800e21b316d)
			fffff800e21b30ee 48833deafee4ff00 cmp qword ptr [nt!KeServiceDescriptorTable+0x20 (fffff800e2002fe0)],0 <- we are looking for this instruction
			fffff800e21b30f6 7575             jne nt!KeAddSystemServiceTable+0x91 (fffff800e21b316d)
			fffff800e21b30f8 48833da0fee4ff00 cmp qword ptr [nt!KeServiceDescriptorTableShadow+0x20 (fffff800e2002fa0)],0
			fffff800e21b3100 756b             jne nt!KeAddSystemServiceTable+0x91 (fffff800e21b316d)
			*/
			int rvaFound = -1;
			for (unsigned int i = 0; i < function_size; i++)
			{
				if (((*(unsigned int*)(function + i)) & 0x00FFFFFF) == 0x3D8348 &&
					!*(unsigned char*)(function + i + 7)) //48833d ???????? 00 cmp qword ptr [X],0
				{
					rvaFound = i;
					rvaSSDT = *(int*)(function + i + 3);
					break;
				}
			}
			if (rvaFound == -1)
			{
				Log("[TITANHIDE] Failed to find pattern...\n");
				return 0;
			}
			//Sanity check SSDT & contents
			__try
			{
				SSDT = (SSDTStruct*)((ULONG_PTR)KeASST + rvaFound + rvaSSDT + 8 - 0x20);
				ULONG_PTR check = (ULONG_PTR)KeASST & 0xFFFFFFFF00000000;
				if (((ULONG_PTR)SSDT & 0xFFFFFFFF00000000) != check ||
					((ULONG_PTR)SSDT->pServiceTable & 0xFFFFFFFF00000000) != check ||
					(SSDT->NumberOfServices & 0xFFFFFFFFFFFF0000) != 0 ||
					((ULONG_PTR)SSDT->pArgumentTable & 0xFFFFFFFF00000000) != check)
				{
					Log("[TITANHIDE] Found SSDT didn't pass all checks...\n");
					return 0;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				Log("[TITANHIDE] An exception was thrown while accessing the SSDT...\n");
				return 0;
			}
		}
#endif
	}
	return SSDT;
}

PVOID SSDT::GetFunctionAddress(const char* apiname)
{
	//read address from SSDT
	SSDTStruct* SSDT = SSDTfind();
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
	ULONG readOffset = NTDLL::GetExportSsdtIndex(apiname);
	if (readOffset == -1)
		return 0;
	if (readOffset >= SSDT->NumberOfServices)
	{
		Log("[TITANHIDE] Invalid read offset...\n");
		return 0;
	}
#ifdef _WIN64
	return (PVOID)((SSDT->pServiceTable[readOffset] >> 4) + SSDTbase);
#else
	return (PVOID)SSDT->pServiceTable[readOffset];
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
		if (Code[i] == 0x90 || Code[i] == 0xCC) //NOP or INT3
			j++;
		else
			j = 0;
		if (j == CaveSize)
			return (PVOID)((ULONG_PTR)CodeStart + i - CaveSize + 1);
	}
	return 0;
}
#endif //_WIN64

HOOK SSDT::Hook(const char* apiname, void* newfunc)
{
	SSDTStruct* SSDT = SSDTfind();
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
	ULONG FunctionIndex = NTDLL::GetExportSsdtIndex(apiname);
	if (FunctionIndex == -1)
		return 0;
	if (FunctionIndex >= SSDT->NumberOfServices)
	{
		Log("[TITANHIDE] Invalid API offset...\n");
		return 0;
	}

	HOOK hHook = 0;
	ULONG oldValue = SSDT->pServiceTable[FunctionIndex];
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
		CodeStart = PE::GetPageBase(Undocumented::GetKernelBase(), &CodeSize, (PVOID)((oldValue >> 4) + SSDTbase));
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

	PVOID CaveAddress = FindCaveAddress(CodeStart, CodeSize, sizeof(HOOKOPCODES));
	if (!CaveAddress)
	{
		Log("[TITANHIDE] FindCaveAddress failed...\n");
		return 0;
	}
	Log("[TITANHIDE] CaveAddress: 0x%p\n", CaveAddress);

	hHook = Hooklib::Hook(CaveAddress, (void*)newfunc);
	if (!hHook)
		return 0;

	newValue = (ULONG)((ULONG_PTR)CaveAddress - SSDTbase);
	newValue = (newValue << 4) | oldValue & 0xF;

	//update HOOK structure
	hHook->SSDTindex = FunctionIndex;
	hHook->SSDTold = oldValue;
	hHook->SSDTnew = newValue;
	hHook->SSDTaddress = (oldValue >> 4) + SSDTbase;

#else
	/*
	x86 SSDT Hook:
	1) change SSDT value
	*/
	newValue = (ULONG)newfunc;

	hHook = (HOOK)RtlAllocateMemory(true, sizeof(HOOKSTRUCT));

	//update HOOK structure
	hHook->SSDTindex = FunctionIndex;
	hHook->SSDTold = oldValue;
	hHook->SSDTnew = newValue;
	hHook->SSDTaddress = oldValue;

#endif

	InterlockedSet(&SSDT->pServiceTable[FunctionIndex], newValue);

	Log("[TITANHIDE] SSDThook(%s:0x%p, 0x%p)\n", apiname, hHook->SSDTold, hHook->SSDTnew);

	return hHook;
}

void SSDT::Hook(HOOK hHook)
{
	if (!hHook)
		return;
	SSDTStruct* SSDT = SSDTfind();
	if (!SSDT)
	{
		Log("[TITANHIDE] SSDT not found...\n");
		return;
	}
	LONG* SSDT_Table = SSDT->pServiceTable;
	if (!SSDT_Table)
	{
		Log("[TITANHIDE] ServiceTable not found...\n");
		return;
	}
	InterlockedSet(&SSDT_Table[hHook->SSDTindex], hHook->SSDTnew);
}

void SSDT::Unhook(HOOK hHook, bool free)
{
	if (!hHook)
		return;
	SSDTStruct* SSDT = SSDTfind();
	if (!SSDT)
	{
		Log("[TITANHIDE] SSDT not found...\n");
		return;
	}
	LONG* SSDT_Table = SSDT->pServiceTable;
	if (!SSDT_Table)
	{
		Log("[TITANHIDE] ServiceTable not found...\n");
		return;
	}
	InterlockedSet(&SSDT_Table[hHook->SSDTindex], hHook->SSDTold);
#ifdef _WIN64
	if (free)
		Hooklib::Unhook(hHook, true);
#else
	UNREFERENCED_PARAMETER(free);
#endif
}
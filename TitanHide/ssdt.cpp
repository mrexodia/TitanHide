#include "ssdt.h"
#include "undocumented.h"
#include "misc.h"
#include "pe.h"
#include "log.h"

static int SSDTgetOffset(const wchar_t* apiname)
{
	//hard-coded offsets
	static int offsetNtQueryObject = 0;
	static int offsetNtQueryInformationProcess = 0;
	static int offsetNtQuerySystemInformation = 0;
	static int offsetNtSetInformationThread = 0;
	static int offsetNtClose = 0;
	static int offsetNtSetContextThread = 0;
	static int offsetNtContinue = 0;

	static bool initDone = false;
	if (!initDone)
	{
		RTL_OSVERSIONINFOEXW OS;
		RtlZeroMemory(&OS, sizeof(OS));
		OS.dwOSVersionInfoSize = sizeof(OS);
		if (!NT_SUCCESS(RtlGetVersion((PRTL_OSVERSIONINFOW)&OS)))
			return -1;
		int ma = OS.dwMajorVersion;
		int mi = OS.dwMinorVersion;
		int sp = OS.wServicePackMajor;
		int pt = OS.wProductType;

		initDone = true;

		Log("[TITANHIDE] RtlGetVersion: %d.%d SP%d\n", ma, mi, sp);

		//Offset list from: http://j00ru.vexillium.org/ntapi_64/ for x64 and http://j00ru.vexillium.org/ntapi/ for x86
		if (ma == 5 && (mi == 1 || (mi == 2 && pt == VER_NT_WORKSTATION))) //Windows XP (x86/x64)
		{
			Log("[TITANHIDE] Windows XP ");
#ifdef _WIN64
			offsetNtQueryObject = 0x000d;
			offsetNtQueryInformationProcess = 0x0016;
			offsetNtQuerySystemInformation = 0x0033;
			offsetNtSetInformationThread = 0x000a;
			offsetNtClose = 0x000c;
			offsetNtSetContextThread = 0x00f6;
			offsetNtContinue = 0x0040;
#else
			offsetNtQueryObject = 0x00a3;
			offsetNtQueryInformationProcess = 0x009a;
			offsetNtQuerySystemInformation = 0x00ad;
			offsetNtSetInformationThread = 0x00e5;
			offsetNtClose = 0x0019;
			offsetNtSetContextThread = 0x00d5;
			offsetNtContinue = 0x0020;
#endif
			switch (sp)
			{
			case 0:
			{
				Log("SP0 ");
			}
				break;
			case 1:
			{
				Log("SP1 ");
			}
				break;
			case 2:
			{
				Log("SP2 ");
			}
				break;
			case 3:
			{
				Log("SP3 ");
			}
				break;
			}
			Log("detected!\n");
		}
		else if (ma == 5 && mi == 1) //Windows Server 2003
		{
			Log("[TITANHIDE] Windows Server 2003 ");
#ifdef _WIN64
			offsetNtQueryObject = 0x000d;
			offsetNtQueryInformationProcess = 0x0016;
			offsetNtQuerySystemInformation = 0x0033;
			offsetNtSetInformationThread = 0x000a;
			offsetNtClose = 0x000c;
			offsetNtSetContextThread = 0x00f6;
			offsetNtContinue = 0x0040;
#else
			offsetNtQueryObject = 0x00aa;
			offsetNtQueryInformationProcess = 0x00a1;
			offsetNtQuerySystemInformation = 0x00b5;
			offsetNtSetInformationThread = 0x00ee;
			offsetNtClose = 0x001b;
			offsetNtSetContextThread = 0x00dd;
			offsetNtContinue = 0x0022;
#endif
			switch (sp)
			{
			case 0:
			{
				Log("SP0 ");
			}
				break;
			case 1:
			{
				Log("SP1 ");
			}
				break;
			case 2:
			{
				Log("SP2 ");
			}
				break;
			}
			Log("detected!\n");
		}
		else if (ma == 6 && mi == 0 && pt == VER_NT_WORKSTATION) //Windows Vista
		{
			Log("[TITANHIDE] Windows Vista ");
#ifdef _WIN64
			offsetNtQueryObject = 0x000d;
			offsetNtQueryInformationProcess = 0x0016;
			offsetNtQuerySystemInformation = 0x0033;
			offsetNtSetInformationThread = 0x000a;
			offsetNtClose = 0x000c;
			offsetNtSetContextThread = 0x0149;
			offsetNtContinue = 0x0040;
#else
			offsetNtQueryObject = 0x00ed;
			offsetNtQueryInformationProcess = 0x00e4;
			offsetNtQuerySystemInformation = 0x00f8;
			offsetNtSetInformationThread = 0x0132;
			offsetNtClose = 0x0030;
			offsetNtSetContextThread = 0x0121;
			offsetNtContinue = 0x0037;
#endif
			switch (sp)
			{
			case 0:
			{
#ifndef _WIN64
				offsetNtSetInformationThread = 0x0136; //x86 SP0 is different
				offsetNtSetContextThread = 0x0125;
#else
				offsetNtSetContextThread = 0x014f;
#endif
				Log("SP0 ");
			}
				break;
			case 1:
			{
				Log("SP1 ");
			}
				break;
			case 2:
			{
				Log("SP2 ");
			}
				break;
			}
			Log("detected!\n");
		}
		else if (ma == 6 && mi == 0 && pt != VER_NT_WORKSTATION) //Windows Server 2008
		{
			Log("[TITANHIDE] Windows Server 2008 ");
#ifdef _WIN64
			offsetNtQueryObject = 0x000d;
			offsetNtQueryInformationProcess = 0x0016;
			offsetNtQuerySystemInformation = 0x0033;
			offsetNtSetInformationThread = 0x000a;
			offsetNtClose = 0x000c;
			offsetNtSetContextThread = 0x0149;
			offsetNtContinue = 0x0040;
#else
			offsetNtQueryObject = 0x00ed;
			offsetNtQueryInformationProcess = 0x00e4;
			offsetNtQuerySystemInformation = 0x00f8;
			offsetNtSetInformationThread = 0x0132;
			offsetNtClose = 0x0030;
			offsetNtSetContextThread = 0x0121;
			offsetNtContinue = 0x0037;
#endif
			switch (sp)
			{
			case 0:
			{
				Log("SP0 ");
			}
				break;
			case 1:
			{
				Log("SP1 ");
			}
				break;
			case 2:
			{
				Log("SP2 ");
			}
				break;
			}
			Log("detected!\n");
		}
		else if (ma == 6 && mi == 1 && pt == VER_NT_WORKSTATION) //Windows 7
		{
			Log("[TITANHIDE] Windows 7 ");
#ifdef _WIN64
			offsetNtQueryObject = 0x000d;
			offsetNtQueryInformationProcess = 0x0016;
			offsetNtQuerySystemInformation = 0x0033;
			offsetNtSetInformationThread = 0x000a;
			offsetNtClose = 0x000c;
			offsetNtSetContextThread = 0x0150;
			offsetNtContinue = 0x0040;
#else
			offsetNtQueryObject = 0x00f8;
			offsetNtQueryInformationProcess = 0x00ea;
			offsetNtQuerySystemInformation = 0x0105;
			offsetNtSetInformationThread = 0x014f;
			offsetNtClose = 0x0032;
			offsetNtSetContextThread = 0x013c;
			offsetNtContinue = 0x003c;
#endif
			switch (sp)
			{
			case 0:
			{
				Log("SP0 ");
			}
				break;
			case 1:
			{
				Log("SP1 ");
			}
				break;
			}
			Log("detected!\n");
		}
		else if (ma == 6 && mi == 2 && pt != VER_NT_WORKSTATION) //Windows Server 2012
		{
			Log("[TITANHIDE] Windows Server 2012 ");
			offsetNtQueryObject = 0x000e;
			offsetNtQueryInformationProcess = 0x0017;
			offsetNtQuerySystemInformation = 0x0034;
			offsetNtSetInformationThread = 0x000b;
			offsetNtClose = 0x000d;
			offsetNtSetContextThread = 0x0165;
			offsetNtContinue = 0x0041;
			switch (sp)
			{
			case 0:
			{
				Log("SP0 ");
			}
				break;
			}
			Log("detected!\n");
		}
		else if (ma == 6 && mi == 2 && pt == VER_NT_WORKSTATION) //Windows 8
		{
			Log("[TITANHIDE] Windows 8 ");
#ifdef _WIN64
			offsetNtQueryObject = 0x000e;
			offsetNtQueryInformationProcess = 0x0017;
			offsetNtQuerySystemInformation = 0x0034;
			offsetNtSetInformationThread = 0x000b;
			offsetNtClose = 0x000d;
			offsetNtSetContextThread = 0x0165;
			offsetNtContinue = 0x0041;
#else
			offsetNtQueryObject = 0x00a2;
			offsetNtQueryInformationProcess = 0x00b0;
			offsetNtQuerySystemInformation = 0x0095;
			offsetNtSetInformationThread = 0x0048;
			offsetNtClose = 0x0173;
			offsetNtSetContextThread = 0x005b;
			offsetNtContinue = 0x016a;
#endif
			switch (sp)
			{
			case 0:
			{
				Log("SP0 ");
			}
				break;
			}
			Log("detected!\n");
		}
		else if (ma == 6 && mi == 3 && pt == VER_NT_WORKSTATION) //Windows 8.1
		{
			Log("[TITANHIDE] Windows 8.1 ");
#ifdef _WIN64
			offsetNtQueryObject = 0x000f;
			offsetNtQueryInformationProcess = 0x0018;
			offsetNtQuerySystemInformation = 0x0035;
			offsetNtSetInformationThread = 0x000c;
			offsetNtClose = 0x000e;
			offsetNtSetContextThread = 0x0168;
			offsetNtContinue = 0x0042;
#else
			offsetNtQueryObject = 0x00a5;
			offsetNtQueryInformationProcess = 0x00b3;
			offsetNtQuerySystemInformation = 0x0098;
			offsetNtSetInformationThread = 0x004b;
			offsetNtClose = 0x00178;
			offsetNtSetContextThread = 0x005e;
			offsetNtContinue = 0x016f;
#endif
			switch (sp)
			{
			case 0:
			{
				Log("SP0 ");
			}
				break;
			}
			Log("detected!\n");
		}
		else
		{
			Log("[TITANHIDE] OS Unsupported...\n");
			return 0;
		}
	}

	//get read offset
	int readOffset = -1;
	if (!_wcsicmp(apiname, L"NtQueryObject")) //NtQueryObject
		readOffset = offsetNtQueryObject;
	else if (!_wcsicmp(apiname, L"NtQueryInformationProcess")) //NtQueryInformationProcess
		readOffset = offsetNtQueryInformationProcess;
	else if (!_wcsicmp(apiname, L"NtQuerySystemInformation")) //NtQuerySystemInformation
		readOffset = offsetNtQuerySystemInformation;
	else if (!_wcsicmp(apiname, L"NtSetInformationThread")) //NtSetInformationThread
		readOffset = offsetNtSetInformationThread;
	else if (!_wcsicmp(apiname, L"NtClose")) //NtClose
		readOffset = offsetNtClose;
	else if (!_wcsicmp(apiname, L"NtSetContextThread")) //NtSetContextThread
		readOffset = offsetNtSetContextThread;
	else if (!_wcsicmp(apiname, L"NtContinue")) //NtContinue
		readOffset = offsetNtContinue;

	if (readOffset == -1)
	{
		Log("[TITANHIDE] Unknown function...\n");
	}
	return readOffset;
}

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

PVOID SSDTgpa(const wchar_t* apiname)
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
	ULONG readOffset = SSDTgetOffset(apiname);
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

HOOK SSDThook(const wchar_t* apiname, void* newfunc)
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
	ULONG apiOffset = SSDTgetOffset(apiname);
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

	Log("[TITANHIDE] SSDThook(%ws:0x%p, 0x%p)\n", apiname, hHook->SSDTold, hHook->SSDTnew);

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
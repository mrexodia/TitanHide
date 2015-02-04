#include "debugport.h"
#include "log.h"

static int GetDebugPortOffset()
{
	static int DebugPortOffset = -1;
	if (DebugPortOffset != -1)
		return DebugPortOffset;

	//Get OS-independent DebugPort offset
	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, L"PsGetProcessDebugPort");
	unsigned char* data = (unsigned char*)MmGetSystemRoutineAddress(&routineName);
	if (data)
	{
		/*
		nt!PsGetProcessDebugPort:
		fffff803`a5b7c170 488b8110040000  mov     rax,qword ptr [rcx+410h]
		fffff803`a5b7c177 c3              ret
		*/
		for (int i = 0; i < 20; i++) //20 bytes should be enough
		{
#ifdef _WIN64
			if (data[i] == 0x48 && data[i + 1] == 0x8B && (data[i + 2] & 0xF0) == 0x80) //mov rax,[r64+X]
			{
				DebugPortOffset = *(int*)(data + i + 3);
				break;
			}
#else
			if (data[i] == 0x8B && (data[i + 1] & 0xF0) == 0x80) //mov eax,[r32+X]
			{
				DebugPortOffset = *(int*)(data + i + 2);
				break;
			}
#endif
		}
		if (DebugPortOffset != -1)
			Log("[TITANHIDE] DebugPortOffset=%X\n", DebugPortOffset);
	}

	//Hard-coded offsets
	if (DebugPortOffset == -1)
	{
		RTL_OSVERSIONINFOEXW OS;
		RtlZeroMemory(&OS, sizeof(OS));
		OS.dwOSVersionInfoSize = sizeof(OS);
		if (!NT_SUCCESS(RtlGetVersion((PRTL_OSVERSIONINFOW)&OS)))
			return -1;
		int ma = OS.dwMajorVersion;
		int mi = OS.dwMinorVersion;
		int pt = OS.wProductType;
		//Thanks to Insid3Code: http://www.insid3code.blogspot.com
		if (ma == 5 && (mi == 1 || (mi == 2 && pt == VER_NT_WORKSTATION))) //Windows XP (x86/x64)
		{
#ifdef _WIN64
			DebugPortOffset = 0x148;
#else
			DebugPortOffset = 0x0bc;
#endif
		}
		else if (ma == 5 && mi == 1) //Windows Server 2003
		{
			//TODO: Verify these offsets
#ifdef _WIN64
			DebugPortOffset = 0x148;
#else
			DebugPortOffset = 0x0bc;
#endif
		}
		else if (ma == 6 && mi == 0 && pt == VER_NT_WORKSTATION) //Windows Vista
		{
#ifdef _WIN64
			DebugPortOffset = 0x150;
#else
			DebugPortOffset = 0x0d4;
#endif
		}
		else if (ma == 6 && mi == 0 && pt != VER_NT_WORKSTATION) //Windows Server 2008
		{
			//TODO: Verify these offsets
#ifdef _WIN64
			DebugPortOffset = 0x150;
#else
			DebugPortOffset = 0x0d4;
#endif
		}
		else if (ma == 6 && mi == 1 && pt == VER_NT_WORKSTATION) //Windows 7
		{
#ifdef _WIN64
			DebugPortOffset = 0x1f0;
#else
			DebugPortOffset = 0x0ec;
#endif
		}
		else if (ma == 6 && mi == 2 && pt != VER_NT_WORKSTATION) //Windows Server 2012
		{
			DebugPortOffset = 0x2f8;
		}
		else if (ma == 6 && mi == 2 && pt == VER_NT_WORKSTATION) //Windows 8
		{
#ifdef _WIN64
			DebugPortOffset = 0x2f8;
#else
			DebugPortOffset = 0x154;
#endif
		}
		else if (ma == 6 && mi == 3 && pt == VER_NT_WORKSTATION) //Windows 8.1
		{
#ifdef _WIN64
			DebugPortOffset = 0x410;
#else
			DebugPortOffset = 0x154;
#endif
		}
	}
	return DebugPortOffset;
}

PVOID DebugPort::Set(PEPROCESS Process, PVOID DebugPort)
{
	int DebugPortOffset = GetDebugPortOffset();
	if (DebugPortOffset == -1)
		return 0;
	PVOID* _DebugPort = (PVOID*)((unsigned char*)Process + DebugPortOffset);
	PVOID OldDebugPort = *_DebugPort;
	*_DebugPort = DebugPort;
	return OldDebugPort;
}

#include <windows.h>
#include <stdio.h>
#include <Subauth.h>
#include "..\TitanHide\TitanHide.h"

//Thanks to:
//http://www.codeproject.com/Articles/30815/An-Anti-Reverse-Engineering-Guide
//http://pferrie.host22.com/papers/antidebug.pdf
//http://resources.infosecinstitute.com/anti-debugging-detecting-system-debugger/

bool CheckProcessDebugFlags()
{
	// Much easier in ASM but C/C++ looks so much better
	typedef int (WINAPI* pNtQueryInformationProcess)
		(HANDLE, UINT, PVOID, ULONG, PULONG);

	DWORD NoDebugInherit = 0;
	int Status;

	// Get NtQueryInformationProcess
	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
		GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),
		"NtQueryInformationProcess");


	Status = NtQIP(GetCurrentProcess(),
		0x1f, // ProcessDebugFlags
		&NoDebugInherit, sizeof(NoDebugInherit), NULL);

	if (Status != 0x00000000)
	{
		printf("NtQueryInformationProcess failed with %X\n", Status);
		return false;
	}

	if (NoDebugInherit == FALSE)
		return true;
	else
		return false;
}

bool CheckProcessDebugPort()
{
	// Much easier in ASM but C/C++ looks so much better
	typedef int (WINAPI* pNtQueryInformationProcess)
		(HANDLE, UINT, PVOID, ULONG, PULONG);

	DWORD_PTR DebugPort = 0;
	ULONG ReturnSize = 0;
	int Status;

	// Get NtQueryInformationProcess
	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
		GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),
		"NtQueryInformationProcess");

	Status = NtQIP(GetCurrentProcess(),
		0x7, // ProcessDebugPort
		&DebugPort, sizeof(DebugPort), &ReturnSize);

	if (Status != 0x00000000)
	{
		printf("NtQueryInformationProcess failed with %X, %d\n", Status, ReturnSize);
		return false;
	}

	if (DebugPort)
		return true;
	else
		return false;
}

bool CheckProcessDebugObjectHandle()
{
	// Much easier in ASM but C/C++ looks so much better
	typedef int (WINAPI* pNtQueryInformationProcess)
		(HANDLE, UINT, PVOID, ULONG, PULONG);

	DWORD_PTR DebugHandle = 0;
	int Status;
	ULONG ReturnSize = 0;

	// Get NtQueryInformationProcess
	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
		GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),
		"NtQueryInformationProcess");

	Status = NtQIP(GetCurrentProcess(),
		30, // ProcessDebugHandle
		&DebugHandle, sizeof(DebugHandle), &ReturnSize);

	if (Status != 0x00000000)
	{
		if (Status != 0xC0000353) //STATUS_PORT_NOT_SET
			printf("NtQueryInformationProcess failed with %X, %d\n", Status, ReturnSize);
		return false;
	}


	if (DebugHandle)
	{
		CloseHandle((HANDLE)DebugHandle);
		return true;
	}

	else
		return false;
}

bool HideFromDebugger()
{
	typedef NTSTATUS(NTAPI* NT_SET_INFORMATION_THREAD)(
		IN HANDLE ThreadHandle,
		IN ULONG ThreadInformationClass,
		IN PVOID ThreadInformation,
		IN ULONG ThreadInformationLength
		);
	NT_SET_INFORMATION_THREAD NtSIT = (NT_SET_INFORMATION_THREAD)
		GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),
		"NtSetInformationThread");
	return NT_SUCCESS(NtSIT(GetCurrentThread(),
		0x11, //ThreadHideFromDebugger
		0,
		0));
}

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfHandles;
	ULONG TotalNumberOfObjects;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_ALL_INFORMATION
{
	ULONG NumberOfObjects;
	OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];
} OBJECT_ALL_INFORMATION, *POBJECT_ALL_INFORMATION;

typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllInformation,
	ObjectDataInformation
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

// ObjectListCheck uses NtQueryObject to check the environments
// list of objects and more specifically for the number of
// debug objects. This function can cause an exception (although rarely)
// so either surround it in a try catch or __try __except block
// but that shouldn't happen unless one tinkers with the function
bool CheckObjectList()
{
	__try
	{
		typedef NTSTATUS(NTAPI* pNtQueryObject)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

		POBJECT_ALL_INFORMATION pObjectAllInfo = NULL;
		void* pMemory = NULL;
		NTSTATUS Status;
		ULONG Size = 0;

		// Get NtQueryObject
		pNtQueryObject NtQO = (pNtQueryObject)GetProcAddress(
			GetModuleHandle(TEXT("ntdll.dll")),
			"NtQueryObject");

		// Get the size of the list
		Status = NtQO(NULL, ObjectAllInformation, //ObjectAllTypesInformation
			&Size, sizeof(ULONG), &Size);

		// Allocate room for the list
		pMemory = VirtualAlloc(NULL, Size, MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE);

		if (pMemory == NULL)
			return false;

		// Now we can actually retrieve the list
		Status = NtQO(GetCurrentProcess(), ObjectAllInformation, pMemory, Size, NULL);

		// Status != STATUS_SUCCESS
		if (Status != STATUS_SUCCESS)
		{
			VirtualFree(pMemory, 0, MEM_RELEASE);
			return false;
		}

		// We have the information we need
		pObjectAllInfo = (POBJECT_ALL_INFORMATION)pMemory;

		unsigned char* pObjInfoLocation = (unsigned char*)pObjectAllInfo->ObjectTypeInformation;

		ULONG NumObjects = pObjectAllInfo->NumberOfObjects;

		for (UINT i = 0; i < NumObjects; i++)
		{
			POBJECT_TYPE_INFORMATION pObjectTypeInfo = (POBJECT_TYPE_INFORMATION)pObjInfoLocation;

			// The debug object will always be present
			wchar_t DebugObject[] = L"DebugObject";
			int DebugObjectLength = lstrlenW(DebugObject) * sizeof(wchar_t);
			if (pObjectTypeInfo->TypeName.Length == DebugObjectLength && !memcmp(pObjectTypeInfo->TypeName.Buffer, DebugObject, DebugObjectLength)) //UNICODE_STRING is not NULL-terminated (pointed to by deepzero!)
			{
				// Are there any objects?
				if (pObjectTypeInfo->TotalNumberOfObjects || pObjectTypeInfo->TotalNumberOfHandles)
				{
					VirtualFree(pMemory, 0, MEM_RELEASE);
					return true;
				}
				else
				{
					VirtualFree(pMemory, 0, MEM_RELEASE);
					return false;
				}
			}

			// Get the address of the current entries
			// string so we can find the end
			pObjInfoLocation = (unsigned char*)pObjectTypeInfo->TypeName.Buffer;

			// Add the size
			pObjInfoLocation += pObjectTypeInfo->TypeName.MaximumLength;

			// Skip the trailing null and alignment bytes
			ULONG_PTR tmp = ((ULONG_PTR)pObjInfoLocation) & -(int)sizeof(void*);

			// Not pretty but it works
			if ((ULONG_PTR)tmp != (ULONG_PTR)pObjInfoLocation)
				tmp += sizeof(void*);
			pObjInfoLocation = ((unsigned char*)tmp);

		}

		VirtualFree(pMemory, 0, MEM_RELEASE);
		return false;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		puts("exception!");
		return false;
	}
}

enum PROCESSINFOCLASS
{
	ProcessBasicInformation = 0, // 0, q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
	ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
	ProcessIoCounters, // q: IO_COUNTERS
	ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX
	ProcessTimes, // q: KERNEL_USER_TIMES
	ProcessBasePriority, // s: KPRIORITY
	ProcessRaisePriority, // s: ULONG
	ProcessDebugPort, // q: HANDLE
	ProcessExceptionPort, // s: HANDLE
	ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
	ProcessLdtInformation, // 10
	ProcessLdtSize,
	ProcessDefaultHardErrorMode, // qs: ULONG
	ProcessIoPortHandlers, // (kernel-mode only)
	ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
	ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
	ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
	ProcessWx86Information,
	ProcessHandleCount, // 20, q: ULONG, PROCESS_HANDLE_INFORMATION
	ProcessAffinityMask, // s: KAFFINITY
	ProcessPriorityBoost, // qs: ULONG
	ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
	ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
	ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
	ProcessWow64Information, // q: ULONG_PTR
	ProcessImageFileName, // q: UNICODE_STRING
	ProcessLUIDDeviceMapsEnabled, // q: ULONG
	ProcessBreakOnTermination, // qs: ULONG
	ProcessDebugObjectHandle, // 30, q: HANDLE
	ProcessDebugFlags, // qs: ULONG
	ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
	ProcessIoPriority, // qs: ULONG
	ProcessExecuteFlags, // qs: ULONG
	ProcessResourceManagement,
	ProcessCookie, // q: ULONG
	ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
	ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION
	ProcessPagePriority, // q: ULONG
	ProcessInstrumentationCallback, // 40
	ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
	ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
	ProcessImageFileNameWin32, // q: UNICODE_STRING
	ProcessImageFileMapping, // q: HANDLE (input)
	ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
	ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
	ProcessGroupInformation, // q: USHORT[]
	ProcessTokenVirtualizationEnabled, // s: ULONG
	ProcessConsoleHostProcess, // q: ULONG_PTR
	ProcessWindowInformation, // 50, q: PROCESS_WINDOW_INFORMATION
	ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
	ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
	ProcessDynamicFunctionTableInformation,
	ProcessHandleCheckingMode,
	ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
	ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
	MaxProcessInfoClass
};

bool NTAPI NtSetInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	IN PVOID ProcessInformation,
	IN ULONG ProcessInformationLength
	)
{
	typedef NTSTATUS(NTAPI* NTSETINFORMATIONPROCESS)
		(
		IN HANDLE ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		IN PVOID ProcessInformation,
		IN ULONG ProcessInformationLength
		);
	static NTSETINFORMATIONPROCESS NtSIP = 0;
	if (!NtSIP)
	{
		NtSIP = (NTSETINFORMATIONPROCESS)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
		if (!NtSIP)
			return false;
	}
	return NT_SUCCESS(NtSIP(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength));
}

bool CheckSystemDebugger()
{
	typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
	{
		BOOLEAN DebuggerEnabled;
		BOOLEAN DebuggerNotPresent;
	} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;
	enum SYSTEM_INFORMATION_CLASS { SystemKernelDebuggerInformation = 35 };
	typedef NTSTATUS(__stdcall * ZW_QUERY_SYSTEM_INFORMATION)(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, IN OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength);
	ZW_QUERY_SYSTEM_INFORMATION ZwQuerySystemInformation;
	SYSTEM_KERNEL_DEBUGGER_INFORMATION Info;
	ZwQuerySystemInformation = (ZW_QUERY_SYSTEM_INFORMATION)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwQuerySystemInformation");
	if (ZwQuerySystemInformation == NULL)
	{
		return false;
	}
	if (NT_SUCCESS(ZwQuerySystemInformation(SystemKernelDebuggerInformation, &Info, sizeof(Info), NULL)))
	{
		if (Info.DebuggerEnabled || !Info.DebuggerNotPresent)
		{
			return true;
		}
	}
	return false;
}

bool CheckNtClose()
{
	__try
	{
		CloseHandle((HANDLE)0x1234);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return true;
	}
	return false;
}

int main(int argc, char* argv[])
{
	char title[256] = "";
	sprintf_s(title, "pid: %d", (int)GetCurrentProcessId());
	SetConsoleTitleA(title);
	while (1)
	{
		printf("ProcessDebugFlags: %d\n", CheckProcessDebugFlags());
		printf("ProcessDebugPort: %d\n", CheckProcessDebugPort());
		printf("ProcessDebugObjectHandle: %d\n", CheckProcessDebugObjectHandle());
		printf("NtQueryObject: %d\n", CheckObjectList());
		printf("CheckSystemDebugger: %d\n", CheckSystemDebugger());
		printf("CheckNtClose: %d\n", CheckNtClose());
		//printf("ThreadHideFromDebugger: %d\n", HideFromDebugger());
		puts("");
		Sleep(1000);
	}
	/*int pid=0;
	printf("pid: ");
	scanf("%d", &pid);
	if(OpenProcess(PROCESS_ALL_ACCESS, false, pid))
	puts("OpenProcess OK!");
	else
	puts("OpenProcess FAILED...");
	printf("%u\n", GetCurrentProcessId());*/
	/*HANDLE hDevice=CreateFileA("\\\\.\\TitanHide", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
	if(hDevice==INVALID_HANDLE_VALUE)
	puts("invalid handle...");
	else
	{
	puts("handle ok!");
	printf("pid: ");
	ULONG pid=0;
	scanf("%d", &pid);
	DWORD written=0;
	HIDE_INFO HideInfo;
	HideInfo.Pid=pid;
	HideInfo.Arg=0;
	HideInfo.Command=HidePid;
	HideInfo.Type=HideProcessDebugFlags|HideProcessDebugPort|HideProcessDebugObjectHandle|HideDebugObject;
	WriteFile(hDevice, &HideInfo, sizeof(HIDE_INFO), &written, 0);
	CloseHandle(hDevice);
	}
	system("pause");*/
	return 0;
}

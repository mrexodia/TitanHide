#include <windows.h>
#include "pebhider.h"

///////////////////////////////////////////////////////////////////////////////////////
//Evolution of Process Environment Block (PEB) http://blog.rewolf.pl/blog/?p=573
//March 2, 2013 / ReWolf posted in programming, reverse engineering, source code, x64 /

template <class T>
struct LIST_ENTRY_T
{
    T Flink;
    T Blink;
};

template <class T>
struct UNICODE_STRING_T
{
    union
    {
        struct
        {
            WORD Length;
            WORD MaximumLength;
        };
        T dummy;
    };
    T _Buffer;
};

template <class T, class NGF, int A>
struct _PEB_T
{
    union
    {
        struct
        {
            BYTE InheritedAddressSpace;
            BYTE ReadImageFileExecOptions;
            BYTE BeingDebugged;
            BYTE _SYSTEM_DEPENDENT_01;
        };
        T dummy01;
    };
    T Mutant;
    T ImageBaseAddress;
    T Ldr;
    T ProcessParameters;
    T SubSystemData;
    T ProcessHeap;
    T FastPebLock;
    T _SYSTEM_DEPENDENT_02;
    T _SYSTEM_DEPENDENT_03;
    T _SYSTEM_DEPENDENT_04;
    union
    {
        T KernelCallbackTable;
        T UserSharedInfoPtr;
    };
    DWORD SystemReserved;
    DWORD _SYSTEM_DEPENDENT_05;
    T _SYSTEM_DEPENDENT_06;
    T TlsExpansionCounter;
    T TlsBitmap;
    DWORD TlsBitmapBits[2];
    T ReadOnlySharedMemoryBase;
    T _SYSTEM_DEPENDENT_07;
    T ReadOnlyStaticServerData;
    T AnsiCodePageData;
    T OemCodePageData;
    T UnicodeCaseTableData;
    DWORD NumberOfProcessors;
    union
    {
        DWORD NtGlobalFlag;
        NGF dummy02;
    };
    LARGE_INTEGER CriticalSectionTimeout;
    T HeapSegmentReserve;
    T HeapSegmentCommit;
    T HeapDeCommitTotalFreeThreshold;
    T HeapDeCommitFreeBlockThreshold;
    DWORD NumberOfHeaps;
    DWORD MaximumNumberOfHeaps;
    T ProcessHeaps;

    //FULL PEB not needed
    /*    T GdiSharedHandleTable;
    T ProcessStarterHelper;
    T GdiDCAttributeList;
    T LoaderLock;
    DWORD OSMajorVersion;
    DWORD OSMinorVersion;
    WORD OSBuildNumber;
    WORD OSCSDVersion;
    DWORD OSPlatformId;
    DWORD ImageSubsystem;
    DWORD ImageSubsystemMajorVersion;
    T ImageSubsystemMinorVersion;
    union
    {
        T ImageProcessAffinityMask;
        T ActiveProcessAffinityMask;
    };
    T GdiHandleBuffer[A];
    T PostProcessInitRoutine;
    T TlsExpansionBitmap;
    DWORD TlsExpansionBitmapBits[32];
    T SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    T pShimData;
    T AppCompatInfo;
    UNICODE_STRING_T<T> CSDVersion;
    T ActivationContextData;
    T ProcessAssemblyStorageMap;
    T SystemDefaultActivationContextData;
    T SystemAssemblyStorageMap;
    T MinimumStackCommit;*/
};

typedef _PEB_T<DWORD, DWORD64, 34> PEB32;
typedef _PEB_T<DWORD64, DWORD, 30> PEB64;

#ifdef _WIN64
typedef PEB64 PEB_CURRENT;
#else
typedef PEB32 PEB_CURRENT;
#endif

// Global.Engine.Hider.functions:
static bool isAtleastVista()
{
    static bool isAtleastVista = false;
    static bool isSet = false;
    if(isSet)
        return isAtleastVista;
    OSVERSIONINFO versionInfo = {0};
    versionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&versionInfo);
    isAtleastVista = versionInfo.dwMajorVersion >= 6;
    isSet = true;
    return isAtleastVista;
}

//Quote from The Ultimate Anti-Debugging Reference by Peter Ferrie
//Flags field exists at offset 0x0C in the heap on the 32-bit versions of Windows NT, Windows 2000, and Windows XP; and at offset 0x40 on the 32-bit versions of Windows Vista and later.
//Flags field exists at offset 0x14 in the heap on the 64-bit versions of Windows XP, and at offset 0x70 in the heap on the 64-bit versions of Windows Vista and later.
//ForceFlags field exists at offset 0x10 in the heap on the 32-bit versions of Windows NT, Windows 2000, and Windows XP; and at offset 0x44 on the 32-bit versions of Windows Vista and later.
//ForceFlags field exists at offset 0x18 in the heap on the 64-bit versions of Windows XP, and at offset 0x74 in the heap on the 64-bit versions of Windows Vista and later.

static int getHeapFlagsOffset(bool x64)
{
    if(x64)  //x64 offsets
    {
        if(isAtleastVista())
        {
            return 0x70;
        }
        else
        {
            return 0x14;
        }
    }
    else //x86 offsets
    {
        if(isAtleastVista())
        {
            return 0x40;
        }
        else
        {
            return 0x0C;
        }
    }
}

static int getHeapForceFlagsOffset(bool x64)
{
    if(x64)  //x64 offsets
    {
        if(isAtleastVista())
        {
            return 0x74;
        }
        else
        {
            return 0x18;
        }
    }
    else //x86 offsets
    {
        if(isAtleastVista())
        {
            return 0x44;
        }
        else
        {
            return 0x10;
        }
    }
}

typedef struct _PROCESS_BASIC_INFORMATION
{
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION* PPROCESS_BASIC_INFORMATION;

static void* GetPEBLocation(HANDLE hProcess)
{
    ULONG RequiredLen = 0;
    void* PebAddress = 0;
    PROCESS_BASIC_INFORMATION myProcessBasicInformation[5] = {};

    typedef DWORD (NTAPI * NtQIP)
    (
        IN HANDLE ProcessHandle,
        IN ULONG ProcessInformationClass,
        OUT PVOID ProcessInformation,
        IN ULONG ProcessInformationLength,
        OUT PULONG ReturnLength
    );

    NtQIP NtQueryInformationProcess = (NtQIP)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if(!NtQueryInformationProcess)
        return 0;

    if(NtQueryInformationProcess(hProcess, 0, myProcessBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), &RequiredLen) == 0)
    {
        PebAddress = (void*)myProcessBasicInformation->PebBaseAddress;
    }
    else
    {
        if(NtQueryInformationProcess(hProcess, 0, myProcessBasicInformation, RequiredLen, &RequiredLen) == 0)
        {
            PebAddress = (void*)myProcessBasicInformation->PebBaseAddress;
        }
    }

    return PebAddress;
}

#ifndef _WIN64
static bool IsThisProcessWow64()
{
    typedef BOOL (WINAPI * tIsWow64Process)(HANDLE hProcess, PBOOL Wow64Process);
    BOOL bIsWow64 = FALSE;
    tIsWow64Process fnIsWow64Process = (tIsWow64Process)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsWow64Process");

    if(fnIsWow64Process)
    {
        fnIsWow64Process(GetCurrentProcess(), &bIsWow64);
    }

    return (bIsWow64 != FALSE);
}
#endif

static void* GetPEBLocation64(HANDLE hProcess)
{
#ifndef _WIN64
    if(IsThisProcessWow64())
    {
        //Only WOW64 processes have 2 PEBs
        DWORD peb32 = (DWORD)GetPEBLocation(hProcess);
        if(peb32)
        {
            peb32 += 0x1000; //PEB64 after PEB32
            return (void*)peb32;
        }
    }
#endif //_WIN64
    return 0;
}


bool HidePEB(HANDLE hProcess, bool Hide)
{
    PEB_CURRENT myPEB = {};
    SIZE_T ueNumberOfBytesRead = 0;
    void* heapFlagsAddress = 0;
    DWORD heapFlags = 0;
    void* heapForceFlagsAddress = 0;
    DWORD heapForceFlags = 0;

#ifndef _WIN64
    PEB64 myPEB64 = {};
    void* AddressOfPEB64 = GetPEBLocation64(hProcess);
#endif

    void* AddressOfPEB = GetPEBLocation(hProcess);

    if(!AddressOfPEB)
        return false;

    if(ReadProcessMemory(hProcess, AddressOfPEB, (void*)&myPEB, sizeof(PEB_CURRENT), &ueNumberOfBytesRead))
    {
#ifndef _WIN64
        if(AddressOfPEB64)
        {
            ReadProcessMemory(hProcess, AddressOfPEB64, (void*)&myPEB64, sizeof(PEB64), &ueNumberOfBytesRead);
        }
#endif

        if(Hide)
        {
            //TODO: backup GlobalFlag
            myPEB.BeingDebugged = FALSE;
            myPEB.NtGlobalFlag &= ~0x70;

#ifndef _WIN64
            myPEB64.BeingDebugged = FALSE;
            myPEB64.NtGlobalFlag &= ~0x70;
#endif

            //TODO: backup heap flags
#ifdef _WIN64
            heapFlagsAddress = (void*)((LONG_PTR)myPEB.ProcessHeap + getHeapFlagsOffset(true));
            heapForceFlagsAddress = (void*)((LONG_PTR)myPEB.ProcessHeap + getHeapForceFlagsOffset(true));
#else
            heapFlagsAddress = (void*)((LONG_PTR)myPEB.ProcessHeap + getHeapFlagsOffset(false));
            heapForceFlagsAddress = (void*)((LONG_PTR)myPEB.ProcessHeap + getHeapForceFlagsOffset(false));
#endif //_WIN64
            ReadProcessMemory(hProcess, heapFlagsAddress, &heapFlags, sizeof(DWORD), 0);
            ReadProcessMemory(hProcess, heapForceFlagsAddress, &heapForceFlags, sizeof(DWORD), 0);

            heapFlags &= HEAP_GROWABLE;
            heapForceFlags = 0;

            WriteProcessMemory(hProcess, heapFlagsAddress, &heapFlags, sizeof(DWORD), 0);
            WriteProcessMemory(hProcess, heapForceFlagsAddress, &heapForceFlags, sizeof(DWORD), 0);
        }
        else
        {
            myPEB.BeingDebugged = TRUE;
#ifndef _WIN64
            myPEB64.BeingDebugged = TRUE;
#endif
        }

        if(WriteProcessMemory(hProcess, AddressOfPEB, (void*)&myPEB, sizeof(PEB_CURRENT), &ueNumberOfBytesRead))
        {
#ifndef _WIN64
            if(AddressOfPEB64)
            {
                WriteProcessMemory(hProcess, AddressOfPEB64, (void*)&myPEB64, sizeof(PEB64), &ueNumberOfBytesRead);
            }
#endif
            return true;
        }
    }
    return false;
}

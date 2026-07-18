#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <Subauth.h>
#include "..\TitanHide\TitanHide.h"

//Thanks to:
//http://www.codeproject.com/Articles/30815/An-Anti-Reverse-Engineering-Guide
//http://pferrie.host22.com/papers/antidebug.pdf
//http://resources.infosecinstitute.com/anti-debugging-detecting-system-debugger/

bool CheckProcessDebugFlags()
{
    // Much easier in ASM but C/C++ looks so much better
    typedef int (WINAPI * pNtQueryInformationProcess)
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

    if(Status != 0x00000000)
    {
        printf("NtQueryInformationProcess failed with %X\n", Status);
        return false;
    }

    if(NoDebugInherit == FALSE)
        return true;
    else
        return false;
}

bool CheckProcessDebugPort()
{
    // Much easier in ASM but C/C++ looks so much better
    typedef int (WINAPI * pNtQueryInformationProcess)
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

    if(Status != 0x00000000)
    {
        printf("NtQueryInformationProcess failed with %X, %u\n", Status, ReturnSize);
        return false;
    }

    if(DebugPort)
        return true;
    else
        return false;
}

bool CheckProcessDebugObjectHandle()
{
    typedef NTSTATUS(NTAPI * pNtQueryInformationProcess)
    (HANDLE, UINT, PVOID, ULONG, PULONG);

    const NTSTATUS StatusInfoLengthMismatch = (NTSTATUS)0xC0000004L;
    const NTSTATUS StatusAccessViolation = (NTSTATUS)0xC0000005L;
    const NTSTATUS StatusAccessDenied = (NTSTATUS)0xC0000022L;
    const NTSTATUS StatusPortNotSet = (NTSTATUS)0xC0000353L;
    const NTSTATUS StatusDatatypeMisalignment = (NTSTATUS)0x80000002L;
    const ULONG SentinelReturnLength = 0xB6B6B6B6;
#ifdef _WIN64
    const ULONG UnwrittenReturnLength = SentinelReturnLength;
#else
    // The WOW64 thunk leaves this value when the native call does not write
    // ReturnLength.
    const ULONG UnwrittenReturnLength = (ULONG)-(LONG)sizeof(ULONG);
#endif
    const ULONG_PTR SentinelHandle = (ULONG_PTR)-1;

    pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
                                       GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),
                                               "NtQueryInformationProcess");
    if(NtQIP == nullptr)
        return false;

    bool Detected = false;
    ULONG_PTR DebugHandle = SentinelHandle;
    ULONG ReturnSize = SentinelReturnLength;

    // Length validation happens before all handle and buffer validation. It does
    // not write either output, including ReturnLength.
    const ULONG InvalidLengths[] = { sizeof(DebugHandle) - 1, sizeof(DebugHandle) + 1 };
    for(ULONG Length : InvalidLengths)
    {
        DebugHandle = SentinelHandle;
        ReturnSize = SentinelReturnLength;
        NTSTATUS Status = NtQIP(GetCurrentProcess(),
                                30, // ProcessDebugObjectHandle
                                &DebugHandle,
                                Length,
                                &ReturnSize);
        if(Status != StatusInfoLengthMismatch ||
                DebugHandle != SentinelHandle ||
                ReturnSize != UnwrittenReturnLength)
        {
            printf("ProcessDebugObjectHandle length contract mismatch: %08X, %p, %08X, %u\n",
                   Status, (PVOID)DebugHandle, ReturnSize, Length);
            Detected = true;
        }
    }

    // A null output with the exact length is probed after process-handle access.
    ReturnSize = SentinelReturnLength;
    NTSTATUS Status = NtQIP(GetCurrentProcess(),
                            30,
                            nullptr,
                            sizeof(DebugHandle),
                            &ReturnSize);
    if(Status != StatusAccessViolation || ReturnSize != UnwrittenReturnLength)
    {
        printf("ProcessDebugObjectHandle null-buffer contract mismatch: %08X, %08X\n", Status, ReturnSize);
        Detected = true;
    }

#ifdef _WIN64
    __declspec(align(8)) unsigned char Output[sizeof(HANDLE) + 8];
    HANDLE LimitedProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                        FALSE,
                                        GetCurrentProcessId());
    if(LimitedProcess != nullptr)
    {
        memset(Output, 0xA5, sizeof(Output));
        ReturnSize = SentinelReturnLength;
        Status = NtQIP(LimitedProcess,
                       30,
                       Output + 1,
                       sizeof(HANDLE),
                       &ReturnSize);
        if(Status != StatusDatatypeMisalignment || ReturnSize != SentinelReturnLength)
        {
            printf("ProcessDebugObjectHandle validation-order mismatch: %08X\n", Status);
            Detected = true;
        }

        memset(Output, 0xA5, sizeof(Output));
        ReturnSize = SentinelReturnLength;
        Status = NtQIP(LimitedProcess,
                       30,
                       Output,
                       sizeof(HANDLE),
                       &ReturnSize);
        if(Status != StatusAccessDenied || ReturnSize != SentinelReturnLength)
        {
            printf("ProcessDebugObjectHandle access contract mismatch: %08X\n", Status);
            Detected = true;
        }
        CloseHandle(LimitedProcess);
    }

    // Native x64 requires four-byte rather than pointer-size alignment.
    memset(Output, 0xA5, sizeof(Output));
    ReturnSize = SentinelReturnLength;
    Status = NtQIP(GetCurrentProcess(),
                   30,
                   Output + 4,
                   sizeof(HANDLE),
                   &ReturnSize);
    ULONG_PTR UnalignedHandle = SentinelHandle;
    memcpy(&UnalignedHandle, Output + 4, sizeof(UnalignedHandle));
    if(Status == STATUS_SUCCESS && UnalignedHandle != 0 && UnalignedHandle != SentinelHandle)
        CloseHandle((HANDLE)UnalignedHandle);
    if(Status != StatusPortNotSet || UnalignedHandle != 0 || ReturnSize != sizeof(HANDLE))
    {
        printf("ProcessDebugObjectHandle alignment contract mismatch: %08X\n", Status);
        Detected = true;
    }
#endif

    DebugHandle = SentinelHandle;
    ReturnSize = SentinelReturnLength;
    Status = NtQIP(GetCurrentProcess(),
                   30,
                   &DebugHandle,
                   sizeof(DebugHandle),
                   &ReturnSize);
    if(Status == STATUS_SUCCESS)
    {
        if(DebugHandle != 0 && DebugHandle != SentinelHandle)
            CloseHandle((HANDLE)DebugHandle);
        return true;
    }
    if(Status != StatusPortNotSet || ReturnSize != sizeof(HANDLE)
#ifdef _WIN64
            || DebugHandle != 0
#endif
      )
    {
        printf("ProcessDebugObjectHandle result contract mismatch: %08X, %u\n", Status, ReturnSize);
        Detected = true;
    }

    // The output is written before ReturnLength. This order is observable when
    // both pointers overlap.
    DebugHandle = SentinelHandle;
    Status = NtQIP(GetCurrentProcess(),
                   30,
                   &DebugHandle,
                   sizeof(DebugHandle),
                   (PULONG)&DebugHandle);
    if(Status != StatusPortNotSet || DebugHandle != sizeof(HANDLE))
    {
        printf("ProcessDebugObjectHandle overlap contract mismatch: %08X\n", Status);
        Detected = true;
    }

    return Detected;
}

bool HideFromDebugger()
{
    typedef NTSTATUS(NTAPI * NT_SET_INFORMATION_THREAD)(
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

static DWORD WINAPI ContractThreadProc(PVOID)
{
    return 0;
}

bool CheckThreadHideFromDebuggerContract()
{
    typedef NTSTATUS(NTAPI * NT_QUERY_INFORMATION_THREAD)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);
    typedef NTSTATUS(NTAPI * NT_SET_INFORMATION_THREAD)(
        HANDLE, ULONG, PVOID, ULONG);
    typedef NTSTATUS(NTAPI * NT_CREATE_THREAD_EX)(
        PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG,
        SIZE_T, SIZE_T, SIZE_T, PVOID);

    NT_QUERY_INFORMATION_THREAD NtQIT = (NT_QUERY_INFORMATION_THREAD)
            GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQueryInformationThread");
    NT_SET_INFORMATION_THREAD NtSIT = (NT_SET_INFORMATION_THREAD)
            GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtSetInformationThread");
    NT_CREATE_THREAD_EX NtCTE = (NT_CREATE_THREAD_EX)
            GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtCreateThreadEx");
    if(NtQIT == nullptr || NtSIT == nullptr || NtCTE == nullptr)
        return false;

    HANDLE Thread = CreateThread(nullptr, 0, ContractThreadProc, nullptr, CREATE_SUSPENDED, nullptr);
    if(Thread == nullptr)
        return false;

    bool Detected = false;
    BOOLEAN Hidden = TRUE;
    ULONG ReturnLength = 0;
    NTSTATUS Status = NtQIT(Thread, 0x11, &Hidden, sizeof(Hidden), &ReturnLength);
    if(!NT_SUCCESS(Status) || Hidden != FALSE || ReturnLength != sizeof(Hidden))
    {
        printf("ThreadHideFromDebugger initial-state mismatch: %08X, %u, %u\n",
               Status, Hidden, ReturnLength);
        Detected = true;
    }

    Status = NtSIT(Thread, 0x11, nullptr, 0);
    if(!NT_SUCCESS(Status))
    {
        printf("ThreadHideFromDebugger set failed: %08X\n", Status);
        Detected = true;
    }

    Hidden = FALSE;
    ReturnLength = 0;
    Status = NtQIT(Thread, 0x11, &Hidden, sizeof(Hidden), &ReturnLength);
    if(!NT_SUCCESS(Status) || Hidden != TRUE || ReturnLength != sizeof(Hidden))
    {
        printf("ThreadHideFromDebugger virtual-state mismatch: %08X, %u, %u\n",
               Status, Hidden, ReturnLength);
        Detected = true;
    }

    TerminateThread(Thread, 0);
    WaitForSingleObject(Thread, INFINITE);
    Hidden = FALSE;
    ReturnLength = 0;
    Status = NtQIT(Thread, 0x11, &Hidden, sizeof(Hidden), &ReturnLength);
    if(!NT_SUCCESS(Status) || Hidden != TRUE || ReturnLength != sizeof(Hidden))
    {
        printf("Exited ThreadHideFromDebugger state mismatch: %08X, %u, %u\n",
               Status, Hidden, ReturnLength);
        Detected = true;
    }
    CloseHandle(Thread);

    // A thread created with the hide flag has the same observable state as one
    // hidden later through NtSetInformationThread.
    const ULONG ThreadCreateFlagsCreateSuspended = 0x1;
    const ULONG ThreadCreateFlagsHideFromDebugger = 0x4;
    Thread = nullptr;
    Status = NtCTE(&Thread,
                   THREAD_ALL_ACCESS,
                   nullptr,
                   GetCurrentProcess(),
                   (PVOID)ContractThreadProc,
                   nullptr,
                   ThreadCreateFlagsCreateSuspended | ThreadCreateFlagsHideFromDebugger,
                   0,
                   0,
                   0,
                   nullptr);
    if(!NT_SUCCESS(Status) || Thread == nullptr)
    {
        printf("NtCreateThreadEx hide-state setup failed: %08X\n", Status);
        return true;
    }

    Hidden = FALSE;
    ReturnLength = 0;
    Status = NtQIT(Thread, 0x11, &Hidden, sizeof(Hidden), &ReturnLength);
    if(!NT_SUCCESS(Status) || Hidden != TRUE || ReturnLength != sizeof(Hidden))
    {
        printf("NtCreateThreadEx hide-state mismatch: %08X, %u, %u\n",
               Status, Hidden, ReturnLength);
        Detected = true;
    }

    TerminateThread(Thread, 0);
    CloseHandle(Thread);
    return Detected;
}

bool CheckGetContextFailureContract()
{
    typedef NTSTATUS(NTAPI * NT_GET_CONTEXT_THREAD)(HANDLE, PCONTEXT);
    NT_GET_CONTEXT_THREAD NtGCT = (NT_GET_CONTEXT_THREAD)
            GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtGetContextThread");
    if(NtGCT == nullptr)
        return false;

    HANDLE LimitedThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION,
                                      FALSE,
                                      GetCurrentThreadId());
    if(LimitedThread == nullptr)
        return false;

    __declspec(align(16)) CONTEXT Context;
    memset(&Context, 0xA5, sizeof(Context));
    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    CONTEXT OriginalContext;
    memcpy(&OriginalContext, &Context, sizeof(Context));

    NTSTATUS Status = NtGCT(LimitedThread, &Context);
    CloseHandle(LimitedThread);

    const NTSTATUS StatusAccessDenied = (NTSTATUS)0xC0000022L;
    if(Status != StatusAccessDenied || memcmp(&Context, &OriginalContext, sizeof(Context)) != 0)
    {
        printf("NtGetContextThread failure contract mismatch: %08X\n", Status);
        return true;
    }
    return false;
}

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    UCHAR TypeIndex;
    CHAR ReservedByte;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
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
    ObjectTypesInformation,
    ObjectDataInformation
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

typedef struct _TEST_OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} TEST_OBJECT_ATTRIBUTES, *PTEST_OBJECT_ATTRIBUTES;

bool CheckObjectTypeInformation()
{
    typedef NTSTATUS(NTAPI * pNtCreateDebugObject)(PHANDLE, ULONG, PTEST_OBJECT_ATTRIBUTES, ULONG);
    typedef NTSTATUS(NTAPI * pNtQueryObject)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

    pNtCreateDebugObject NtCDO = (pNtCreateDebugObject)GetProcAddress(
                                      GetModuleHandle(TEXT("ntdll.dll")),
                                      "NtCreateDebugObject");
    pNtQueryObject NtQO = (pNtQueryObject)GetProcAddress(
                              GetModuleHandle(TEXT("ntdll.dll")),
                              "NtQueryObject");
    if(NtCDO == NULL || NtQO == NULL)
        return false;

    TEST_OBJECT_ATTRIBUTES ObjectAttributes = { sizeof(TEST_OBJECT_ATTRIBUTES) };
    HANDLE DebugObjectHandle = NULL;
    NTSTATUS Status = NtCDO(&DebugObjectHandle, 0x0008, &ObjectAttributes, 0);
    if(!NT_SUCCESS(Status))
        return false;

    // Preserve every handle owned by the protected process, not merely one.
    // The active debugger may independently hold multiple handles to its own
    // debug object, all of which should be removed from the reported total.
    HANDLE DuplicateHandles[2] = {};
    ULONG OwnedHandleCount = 1;
    for(HANDLE& DuplicatedHandle : DuplicateHandles)
    {
        if(DuplicateHandle(
                    GetCurrentProcess(),
                    DebugObjectHandle,
                    GetCurrentProcess(),
                    &DuplicatedHandle,
                    0,
                    FALSE,
                    DUPLICATE_SAME_ACCESS))
        {
            OwnedHandleCount++;
        }
    }

    bool Detected = false;
    ULONG RequiredLength = 0;
    Status = NtQO(DebugObjectHandle, ObjectTypeInformation, NULL, 0, &RequiredLength);
    if(Status != (NTSTATUS)0xC0000004L || RequiredLength < sizeof(OBJECT_TYPE_INFORMATION)) // STATUS_INFO_LENGTH_MISMATCH
    {
        Detected = true;
    }
    else
    {
        OBJECT_TYPE_INFORMATION* TypeInformation = (OBJECT_TYPE_INFORMATION*)HeapAlloc(
                    GetProcessHeap(), HEAP_ZERO_MEMORY, RequiredLength);
        if(TypeInformation == NULL)
        {
            Detected = true;
        }
        else
        {
            Status = NtQO(DebugObjectHandle, ObjectTypeInformation, TypeInformation, RequiredLength, NULL);
            if(!NT_SUCCESS(Status) ||
                    TypeInformation->TotalNumberOfObjects == 0 ||
                    TypeInformation->TotalNumberOfHandles < OwnedHandleCount)
            {
                Detected = true;
            }

            // VMProtect 3.9.5+ overlaps ReturnLength with TypeName.Buffer.
            Status = NtQO(DebugObjectHandle,
                          ObjectTypeInformation,
                          TypeInformation,
                          RequiredLength,
                          (PULONG)&TypeInformation->TypeName.Buffer);
            if(!NT_SUCCESS(Status) ||
                    *(PULONG)&TypeInformation->TypeName.Buffer != RequiredLength ||
                    TypeInformation->TotalNumberOfObjects == 0 ||
                    TypeInformation->TotalNumberOfHandles < OwnedHandleCount)
            {
                Detected = true;
            }

            HeapFree(GetProcessHeap(), 0, TypeInformation);
        }
    }

    for(HANDLE DuplicatedHandle : DuplicateHandles)
    {
        if(DuplicatedHandle != NULL)
            CloseHandle(DuplicatedHandle);
    }
    CloseHandle(DebugObjectHandle);
    return Detected;
}

// ObjectListCheck uses NtQueryObject to check the environments
// list of objects and more specifically for the number of
// debug objects. This function can cause an exception (although rarely)
// so either surround it in a try catch or __try __except block
// but that shouldn't happen unless one tinkers with the function
bool CheckObjectList()
{
    __try
    {
        typedef NTSTATUS(NTAPI * pNtQueryObject)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

        POBJECT_ALL_INFORMATION pObjectAllInfo = NULL;
        void* pMemory = NULL;
        NTSTATUS Status;
        ULONG Size = 0;

        // Get NtQueryObject
        pNtQueryObject NtQO = (pNtQueryObject)GetProcAddress(
                                  GetModuleHandle(TEXT("ntdll.dll")),
                                  "NtQueryObject");

        // Get the size of the list
        Status = NtQO(NULL, ObjectTypesInformation, //ObjectAllTypesInformation
                      &Size, sizeof(ULONG), &Size);

        // Allocate room for the list
        pMemory = VirtualAlloc(NULL, SIZE_T(Size), MEM_RESERVE | MEM_COMMIT,
                               PAGE_READWRITE);

        if(pMemory == NULL)
            return false;

        // Now we can actually retrieve the list
        Status = NtQO(GetCurrentProcess(), ObjectTypesInformation, pMemory, Size, NULL);

        // Status != STATUS_SUCCESS
        if(Status != STATUS_SUCCESS)
        {
            VirtualFree(pMemory, 0, MEM_RELEASE);
            return false;
        }

        // We have the information we need
        pObjectAllInfo = (POBJECT_ALL_INFORMATION)pMemory;

        unsigned char* pObjInfoLocation = (unsigned char*)pObjectAllInfo->ObjectTypeInformation;

        ULONG NumObjects = pObjectAllInfo->NumberOfObjects;

        for(UINT i = 0; i < NumObjects; i++)
        {
            POBJECT_TYPE_INFORMATION pObjectTypeInfo = (POBJECT_TYPE_INFORMATION)pObjInfoLocation;

            // The debug object will always be present
            wchar_t DebugObject[] = L"DebugObject";
            auto DebugObjectLength = wcslen(DebugObject) * sizeof(wchar_t);
            if(pObjectTypeInfo->TypeName.Length == DebugObjectLength && !memcmp(pObjectTypeInfo->TypeName.Buffer, DebugObject, DebugObjectLength))  //UNICODE_STRING is not NULL-terminated (pointed to by deepzero!)
            {
                // Are there any objects?
                if(pObjectTypeInfo->TotalNumberOfObjects || pObjectTypeInfo->TotalNumberOfHandles)
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
            if((ULONG_PTR)tmp != (ULONG_PTR)pObjInfoLocation)
                tmp += sizeof(void*);
            pObjInfoLocation = ((unsigned char*)tmp);

        }

        VirtualFree(pMemory, 0, MEM_RELEASE);
        return false;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        puts("exception!");
        return false;
    }
}

bool CheckObjectTypesInformationOverlapContract()
{
    typedef NTSTATUS(NTAPI * pNtQueryObject)(
        HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    pNtQueryObject NtQO = (pNtQueryObject)GetProcAddress(
                              GetModuleHandle(TEXT("ntdll.dll")),
                              "NtQueryObject");
    if(NtQO == nullptr)
        return false;

    ULONG Size = 0;
    NTSTATUS Status = NtQO(nullptr, ObjectTypesInformation, nullptr, 0, &Size);
    if(Status != (NTSTATUS)0xC0000004L || Size == 0)
        return false;

    const ULONG BufferSize = Size + 0x10000;
    unsigned char* Buffer = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BufferSize);
    if(Buffer == nullptr)
        return false;

    ULONG ActualLength = 0;
    Status = NtQO(nullptr, ObjectTypesInformation, Buffer, BufferSize, &ActualLength);
    if(!NT_SUCCESS(Status))
    {
        printf("ObjectTypesInformation baseline query failed: %08X\n", Status);
        HeapFree(GetProcessHeap(), 0, Buffer);
        return true;
    }

    OBJECT_ALL_INFORMATION* All = (OBJECT_ALL_INFORMATION*)Buffer;
    unsigned char* Location = (unsigned char*)All->ObjectTypeInformation;
    SIZE_T DebugObjectOffset = (SIZE_T)-1;
    SIZE_T PreviousObjectOffset = (SIZE_T)-1;
    SIZE_T PreviousOffset = (SIZE_T)-1;
    const wchar_t DebugObject[] = L"DebugObject";
    const USHORT DebugObjectLength = sizeof(DebugObject) - sizeof(wchar_t);
    for(ULONG i = 0; i < All->NumberOfObjects; i++)
    {
        OBJECT_TYPE_INFORMATION* Type = (OBJECT_TYPE_INFORMATION*)Location;
        if(Type->TypeName.Length == DebugObjectLength &&
                memcmp(Type->TypeName.Buffer, DebugObject, DebugObjectLength) == 0)
        {
            DebugObjectOffset = (SIZE_T)(Location - Buffer);
            PreviousObjectOffset = PreviousOffset;
            break;
        }
        PreviousOffset = (SIZE_T)(Location - Buffer);
        Location = (unsigned char*)Type->TypeName.Buffer + Type->TypeName.MaximumLength;
        Location = (unsigned char*)(((ULONG_PTR)Location + sizeof(void*) - 1) &
                                    -(LONG_PTR)sizeof(void*));
    }

    bool Detected = DebugObjectOffset == (SIZE_T)-1 ||
                    PreviousObjectOffset == (SIZE_T)-1;
    if(Detected)
        puts("ObjectTypesInformation did not contain a preceding DebugObject entry");
    if(!Detected)
    {
        const SIZE_T OverlapOffsets[] =
        {
            DebugObjectOffset + FIELD_OFFSET(OBJECT_TYPE_INFORMATION, TypeName.Buffer),
            PreviousObjectOffset + FIELD_OFFSET(OBJECT_TYPE_INFORMATION, TypeName.MaximumLength),
            DebugObjectOffset + sizeof(OBJECT_TYPE_INFORMATION),
            DebugObjectOffset + FIELD_OFFSET(OBJECT_TYPE_INFORMATION, TypeIndex)
        };
        for(ULONG i = 0; i < ARRAYSIZE(OverlapOffsets); i++)
        {
            ULONG NewActualLength = 0;
            Status = NtQO(nullptr,
                          ObjectTypesInformation,
                          Buffer,
                          BufferSize,
                          &NewActualLength);
            if(!NT_SUCCESS(Status))
            {
                printf("ObjectTypesInformation overlap reset failed: %08X\n", Status);
                Detected = true;
                break;
            }

            PULONG Overlap = (PULONG)(Buffer + OverlapOffsets[i]);
            Status = NtQO(nullptr, ObjectTypesInformation, Buffer, BufferSize, Overlap);
            if(!NT_SUCCESS(Status) || *Overlap != NewActualLength)
            {
                printf("ObjectTypesInformation overlap %u mismatch: %08X\n", i, Status);
                Detected = true;
            }
        }
    }

    // Bytes after the native object-type list are caller-owned even when the
    // supplied allocation is larger than ReturnLength. A filter must not scan
    // or modify a crafted entry in that tail.
    ULONG TailActualLength = 0;
    Status = NtQO(nullptr,
                  ObjectTypesInformation,
                  Buffer,
                  BufferSize,
                  &TailActualLength);
    if(NT_SUCCESS(Status))
    {
        All = (OBJECT_ALL_INFORMATION*)Buffer;
        Location = (unsigned char*)All->ObjectTypeInformation;
        for(ULONG i = 0; i < All->NumberOfObjects; i++)
        {
            OBJECT_TYPE_INFORMATION* Type = (OBJECT_TYPE_INFORMATION*)Location;
            Location = (unsigned char*)Type->TypeName.Buffer +
                       Type->TypeName.MaximumLength;
            Location = (unsigned char*)(((ULONG_PTR)Location + sizeof(void*) - 1) &
                                        -(LONG_PTR)sizeof(void*));
        }

        const SIZE_T FakeSize = sizeof(OBJECT_TYPE_INFORMATION) + sizeof(DebugObject);
        if(Location >= Buffer + TailActualLength &&
                Location + FakeSize <= Buffer + BufferSize)
        {
            OBJECT_TYPE_INFORMATION* Fake =
                (OBJECT_TYPE_INFORMATION*)Location;
            memset(Fake, 0, FakeSize);
            Fake->TypeName.Buffer = (PWSTR)(Fake + 1);
            Fake->TypeName.Length = DebugObjectLength;
            Fake->TypeName.MaximumLength = sizeof(DebugObject);
            Fake->TotalNumberOfObjects = 0xA1B2C3D4;
            Fake->TotalNumberOfHandles = 0xB1C2D3E4;
            memcpy(Fake->TypeName.Buffer, DebugObject, sizeof(DebugObject));

            unsigned char Expected[sizeof(OBJECT_TYPE_INFORMATION) + sizeof(DebugObject)];
            memcpy(Expected, Fake, sizeof(Expected));
            Status = NtQO(nullptr,
                          ObjectTypesInformation,
                          Buffer,
                          BufferSize,
                          &TailActualLength);
            if(!NT_SUCCESS(Status) ||
                    memcmp(Fake, Expected, sizeof(Expected)) != 0)
            {
                printf("ObjectTypesInformation tail contract mismatch: %08X\n", Status);
                Detected = true;
            }
        }
    }
    else
    {
        printf("ObjectTypesInformation tail setup failed: %08X\n", Status);
        Detected = true;
    }

    HeapFree(GetProcessHeap(), 0, Buffer);
    return Detected;
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
    typedef NTSTATUS(NTAPI * NTSETINFORMATIONPROCESS)
    (
        IN HANDLE ProcessHandle,
        IN PROCESSINFOCLASS ProcessInformationClass,
        IN PVOID ProcessInformation,
        IN ULONG ProcessInformationLength
    );
    static NTSETINFORMATIONPROCESS NtSIP = 0;
    if(!NtSIP)
    {
        NtSIP = (NTSETINFORMATIONPROCESS)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
        if(!NtSIP)
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
    if(ZwQuerySystemInformation && NT_SUCCESS(ZwQuerySystemInformation(SystemKernelDebuggerInformation, &Info, sizeof(Info), NULL)))
    {
        if(Info.DebuggerEnabled || !Info.DebuggerNotPresent)
        {
            return true;
        }
    }
    return false;
}

bool CheckSystemDebugControl()
{
    enum SYSDBG_COMMAND { SysDbgQueryModuleInformation = 0 };
    typedef NTSTATUS(__stdcall * ZW_SYSTEM_DEBUG_CONTROL)(IN SYSDBG_COMMAND Command, IN PVOID InputBuffer OPTIONAL, IN ULONG InputBufferLength, OUT PVOID OutputBuffer OPTIONAL, IN ULONG OutputBufferLength, OUT PULONG ReturnLength OPTIONAL);
    static const NTSTATUS STATUS_DEBUGGER_INACTIVE = (NTSTATUS)0xC0000354L;
    ZW_SYSTEM_DEBUG_CONTROL ZwSystemDebugControl = (ZW_SYSTEM_DEBUG_CONTROL)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwSystemDebugControl");
    if(ZwSystemDebugControl == NULL)
    {
        return false;
    }
    return ZwSystemDebugControl(SysDbgQueryModuleInformation, NULL, 0, NULL, 0, NULL) != STATUS_DEBUGGER_INACTIVE;
}

bool CheckNtClose()
{
    __try
    {
        CloseHandle((HANDLE)0x1234);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return true;
    }
    return false;
}

int main(int argc, char* argv[])
{
    if(argc == 2 && strcmp(argv[1], "--native-contracts") == 0)
    {
        const bool ProcessDebugObject = CheckProcessDebugObjectHandle();
        const bool ThreadHide = CheckThreadHideFromDebuggerContract();
        const bool GetContextFailure = CheckGetContextFailureContract();
        const bool ObjectTypesOverlap = CheckObjectTypesInformationOverlapContract();
        printf("Native contracts: ProcessDebugObject=%d ThreadHide=%d GetContextFailure=%d ObjectTypesOverlap=%d\n",
               ProcessDebugObject, ThreadHide, GetContextFailure, ObjectTypesOverlap);
        return ProcessDebugObject || ThreadHide || GetContextFailure || ObjectTypesOverlap ? 1 : 0;
    }

    char title[256] = "";
    sprintf_s(title, "pid: %d", (int)GetCurrentProcessId());
    SetConsoleTitleA(title);

    BOOL IsWow64 = FALSE;
#ifndef _WIN64
    IsWow64Process(GetCurrentProcess(), &IsWow64);
#endif

    while(1)
    {
        printf("ProcessDebugFlags: %d\n", CheckProcessDebugFlags());
        printf("ProcessDebugPort: %d\n", CheckProcessDebugPort());
        printf("ProcessDebugObjectHandle: %d\n", CheckProcessDebugObjectHandle());
        printf("NtQueryObject: %d\n", CheckObjectList());
        printf("NtQueryObjectType: %d\n", CheckObjectTypeInformation());
        printf("CheckSystemDebugger: %d\n", CheckSystemDebugger());
        if(!IsWow64)  // This syscall is not implemented in wow64.dll
            printf("SystemDebugControl: %d\n", CheckSystemDebugControl());
        printf("CheckNtClose: %d\n", CheckNtClose());
        //printf("ThreadHideFromDebugger: %d\n", HideFromDebugger());
        puts("");
        if(argc > 1)
            break;
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

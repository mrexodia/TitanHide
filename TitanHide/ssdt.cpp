#include "ssdt.h"
#include "undocumented.h"
#include "hooklib.h"
#include "misc.h"

static int osMajorVersion=0;
static int osMinorVersion=0;
static int osServicePack=0;
static int osProductType=0;

static int SSDTgetOffset(const wchar_t* apiname)
{
    int ma=osMajorVersion;
    int mi=osMinorVersion;
    int sp=osServicePack;
    int pt=osProductType;

    static bool initDone=false;

    //hard-coded offsets
    static int offsetNtQueryObject=0;

    if(!initDone)
    {
        initDone=true;
        //Offset list from: http://j00ru.vexillium.org/ntapi_64/
        if(ma==5 && (mi==1 || (mi==2 && pt==VER_NT_WORKSTATION))) //Windows XP (x86/x64)
        {
            DbgPrint("[TITANHIDE] Windows XP ");
#ifdef _WIN64
            offsetNtQueryObject=0x000d;
#else
            offsetNtQueryObject=0x00a3;
#endif
            switch(osServicePack)
            {
            case 0:
            {
                DbgPrint("SP0 ");
            }
            break;
            case 1:
            {
                DbgPrint("SP1 ");
            }
            break;
            case 2:
            {
                DbgPrint("SP2 ");
            }
            break;
            case 3:
            {
                DbgPrint("SP3 ");
            }
            break;
            }
            DbgPrint("detected!\n");
        }
        else if(ma==5 && mi==1) //Windows Server 2003
        {
            DbgPrint("[TITANHIDE] Windows Server 2003 ");
#ifdef _WIN64
            offsetNtQueryObject=0x000d;
#else
            offsetNtQueryObject=0x00aa;
#endif
            switch(osServicePack)
            {
            case 0:
            {
                DbgPrint("SP0 ");
            }
            break;
            case 1:
            {
                DbgPrint("SP1 ");
            }
            break;
            case 2:
            {
                DbgPrint("SP2 ");
            }
            break;
            }
            DbgPrint("detected!\n");
        }
        else if(ma==6 && mi==0 && pt==VER_NT_WORKSTATION) //Windows Vista
        {
            DbgPrint("[TITANHIDE] Windows Vista ");
#ifdef _WIN64
            offsetNtQueryObject=0x000d;
#else
            offsetNtQueryObject=0x00ed;
#endif
            switch(osServicePack)
            {
            case 0:
            {
                DbgPrint("SP0 ");
            }
            break;
            case 1:
            {
                DbgPrint("SP1 ");
            }
            break;
            case 2:
            {
                DbgPrint("SP2 ");
            }
            break;
            }
            DbgPrint("detected!\n");
        }
        else if(ma==6 && mi==0 && pt!=VER_NT_WORKSTATION) //Windows Server 2008
        {
            DbgPrint("[TITANHIDE] Windows Server 2008 ");
#ifdef _WIN64
            offsetNtQueryObject=0x000d;
#else
            offsetNtQueryObject=0x00ed;
#endif
            switch(osServicePack)
            {
            case 0:
            {
                DbgPrint("SP0 ");
            }
            break;
            case 1:
            {
                DbgPrint("SP1 ");
            }
            break;
            case 2:
            {
                DbgPrint("SP2 ");
            }
            break;
            }
            DbgPrint("detected!\n");
        }
        else if(ma==6 && mi==1 && pt==VER_NT_WORKSTATION) //Windows 7
        {
            DbgPrint("[TITANHIDE] Windows 7 ");
#ifdef _WIN64
            offsetNtQueryObject=0x000d;
#else
            offsetNtQueryObject=0x00f8;
#endif
            switch(osServicePack)
            {
            case 0:
            {
                DbgPrint("SP0 ");
            }
            break;
            case 1:
            {
                DbgPrint("SP1 ");
            }
            break;
            }
            DbgPrint("detected!\n");
        }
        else if(ma==6 && mi==2 && pt!=VER_NT_WORKSTATION) //Windows Server 2012
        {
            DbgPrint("[TITANHIDE] Windows Server 2012 ");
            offsetNtQueryObject=0x000e;
            switch(osServicePack)
            {
            case 0:
            {
                DbgPrint("SP0 ");
            }
            break;
            }
            DbgPrint("detected!\n");
        }
        else if(ma==6 && mi==2 && pt==VER_NT_WORKSTATION) //Windows 8
        {
            DbgPrint("[TITANHIDE] Windows 8 ");
#ifdef _WIN64
            offsetNtQueryObject=0x000e;
#else
            offsetNtQueryObject=0x00a2;
#endif
            switch(osServicePack)
            {
            case 0:
            {
                DbgPrint("SP0 ");
            }
            break;
            }
            DbgPrint("detected!\n");
        }
        else if(ma==6 && mi==3 && pt==VER_NT_WORKSTATION) //Windows 8.1
        {
            DbgPrint("[TITANHIDE] Windows 8.1 ");
#ifdef _WIN64
            offsetNtQueryObject=0x000f;
#else
            offsetNtQueryObject=0x00a5;
#endif
            switch(osServicePack)
            {
            case 0:
            {
                DbgPrint("SP0 ");
            }
            break;
            }
            DbgPrint("detected!\n");
        }
        else
        {
            DbgPrint("[TITANHIDE] OS Unsupported...\n");
            return 0;
        }
    }

    //get read offset
    int readOffset=-1;
    if(!_wcsicmp(apiname, L"NtQueryObject")) //NtQueryObject
    {
        readOffset=offsetNtQueryObject;
    }
    if(readOffset==-1)
    {
        DbgPrint("[TITANHIDE] Unknown function...\n");
    }
    return readOffset;
}

bool SSDTinit()
{
    static bool initDone=false;
    if(initDone)
        return true;

    RTL_OSVERSIONINFOEXW OS;
    RtlZeroMemory(&OS, sizeof(OS));
    OS.dwOSVersionInfoSize=sizeof(OS);
    if(!NT_SUCCESS(RtlGetVersion((PRTL_OSVERSIONINFOW)&OS)))
        return false;
    osMajorVersion=OS.dwMajorVersion;
    osMinorVersion=OS.dwMinorVersion;
    osServicePack=OS.wServicePackMajor;
    osProductType=OS.wProductType;
    DbgPrint("[TITANHIDE] RtlGetVersion: %d.%d SP%d\n", osMajorVersion, osMinorVersion, osServicePack);

    SSDTStruct* SSDT=(SSDTStruct*)SSDTfind();
    if(!SSDT)
    {
        DbgPrint("[TITANHIDE] SSDT not found...\n");
        return false;
    }
    unsigned long long SSDTbase=(unsigned long long)SSDT->pServiceTable;
    if(!SSDTbase)
    {
        DbgPrint("[TITANHIDE] ServiceTable not found...\n");
        return false;
    }
    initDone=true;
    return true;
}

//Based on: https://code.google.com/p/volatility/issues/detail?id=189#c2
PVOID SSDTfind()
{
    static PVOID SSDT=0;
    if(!SSDT)
    {
        UNICODE_STRING routineName;
#ifndef _WIN64
        //x86 code
        RtlInitUnicodeString(&routineName, L"KeServiceDescriptorTable");
        SSDT=MmGetSystemRoutineAddress(&routineName);
#endif
        //x64 code
        RtlInitUnicodeString(&routineName, L"KeAddSystemServiceTable");
        PVOID KeASST=MmGetSystemRoutineAddress(&routineName);
        if(!KeASST)
            return 0;
        unsigned char function[1024];
        unsigned int function_size=0;
        RtlCopyMemory(function, KeASST, sizeof(function));
        for(unsigned int i=0; i<sizeof(function); i++)
        {
            if(function[i]==0xC3)
            {
                function_size=i+1;
                break;
            }
        }
        if(!function_size)
            return 0;
        unsigned int rvaSSDT=0;
        for(unsigned int i=0; i<function_size; i++)
        {
            if(((*(unsigned int*)(function+i))&0xFFFFF0)==0xBC8340 && !*(unsigned char*)(function+i+8)) //4?83bc?? ???????? 00 cmp qword ptr [r?+r?+????????h],0
            {
                rvaSSDT=*(unsigned int*)(function+i+4);
                break;
            }
        }
        if(!rvaSSDT)
            return 0;
        DbgPrint("[TITANHIDE] SSDT RVA: 0x%X\n", rvaSSDT);
        static PVOID base=KernelGetModuleBase("ntoskrnl");
        if(!base)
            return 0;
        DbgPrint("[TITANHIDE] KernelGetModuleBase(ntoskrnl)->0x%p\n", base);
        SSDT=(PVOID)((unsigned char*)base+rvaSSDT);
    }
    return SSDT;
}

PVOID SSDTgpa(const wchar_t* apiname)
{
    //read address from SSDT
    static SSDTStruct* SSDT=(SSDTStruct*)SSDTfind();
    if(!SSDT)
    {
        DbgPrint("[TITANHIDE] SSDT not found...\n");
        return 0;
    }
    unsigned long long SSDTbase=(unsigned long long)SSDT->pServiceTable;
    if(!SSDTbase)
    {
        DbgPrint("[TITANHIDE] ServiceTable not found...\n");
        return 0;
    }
    int readOffset=SSDTgetOffset(apiname);
    if(readOffset==-1)
        return 0;
    if(readOffset>=SSDT->NumberOfServices)
    {
        DbgPrint("[TITANHIDE] Invalid read offset...\n");
        return 0;
    }
#ifdef _WIN64
    return (PVOID)((((LONG*)SSDT->pServiceTable)[readOffset]>>4)+SSDTbase);
#else
    return (PVOID)((LONG*)SSDT->pServiceTable)[readOffset];
#endif
}

static NTSTATUS InterlockedSet(LONG* Destination, LONG Source)
{
    /*
    //Change memory properties.
    PMDL g_pmdl=IoAllocateMdl(Destination, sizeof(opcode), 0, 0, NULL);
    if(!g_pmdl)
        return STATUS_UNSUCCESSFUL;
    MmBuildMdlForNonPagedPool(g_pmdl);
    LONG* Mapped=(LONG*)MmMapLockedPages(g_pmdl, KernelMode);
    if(!Mapped)
    {
        IoFreeMdl(g_pmdl);
        return STATUS_UNSUCCESSFUL;
    }
    InterlockedExchange(Mapped, Source);
    //Restore memory properties.
    MmUnmapLockedPages((PVOID)Mapped, g_pmdl);
    IoFreeMdl(g_pmdl);
    return STATUS_SUCCESS;
    */
    unlockCR0();
    InterlockedExchange(Destination, Source);
    lockCR0();
    return STATUS_SUCCESS;
}

PVOID SSDThook(const wchar_t* apiname, void* newfunc)
{
    static SSDTStruct* SSDT=(SSDTStruct*)SSDTfind();
    if(!SSDT)
    {
        DbgPrint("[TITANHIDE] SSDT not found...\n");
        return 0;
    }
    duint SSDTbase=(unsigned long long)SSDT->pServiceTable;
    if(!SSDTbase)
    {
        DbgPrint("[TITANHIDE] ServiceTable not found...\n");
        return 0;
    }
    int readOffset=SSDTgetOffset(apiname);
    if(readOffset==-1)
        return 0;
    if(readOffset>=SSDT->NumberOfServices)
    {
        DbgPrint("[TITANHIDE] Invalid read offset...\n");
        return 0;
    }

    duint Lowest=(duint)SSDT;
    duint Highest=Lowest+0x0FFFFFFF;

    DbgPrint("[TITANHIDE] Range: 0x%p-0x%p\n", Lowest, Highest);

    if((duint)newfunc<(Highest-12) && (duint)newfunc>Lowest)
        DbgPrint("[TITANHIDE] Cave OK!\n");
    else
        return 0;

    ULONG originalRva=(((LONG*)SSDT->pServiceTable)[readOffset]);

    PVOID original=(PVOID)((originalRva<<4)+SSDTbase);

    ULONG newRva=(duint)newfunc-SSDTbase;
    newRva=(newRva<<4)|(originalRva&0xF);

    DbgPrint("[TITANHIDE] New RVA: 0x%X\n", newRva);

    DbgPrint("[TITANHIDE] Old RVA: 0x%X\n", originalRva);

    //DbgBreakPoint();

    LONG* SSDT_Table=(LONG*)SSDT->pServiceTable;

    DbgPrint("[TITANHIDE] SSDT_Table[readOffset]: 0x%p\n", &SSDT_Table[readOffset]);

    /*unlockCR0();
    lockCR0();*/

    InterlockedSet(&SSDT_Table[readOffset], originalRva);

    //((LONG*)SSDT->pServiceTable)[readOffset]=newRva<<4;
    
    return original;
}
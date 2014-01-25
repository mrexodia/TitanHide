#include "ssdt.h"
#include "undocumented.h"

static int osMajorVersion=0;
static int osMinorVersion=0;
static int osServicePack=0;
static int osProductType=0;

bool SSDTinit()
{
    RTL_OSVERSIONINFOEXW OS;
    RtlZeroMemory(&OS, sizeof(OS));
    OS.dwOSVersionInfoSize=sizeof(OS);
    if(!NT_SUCCESS(RtlGetVersion((PRTL_OSVERSIONINFOW)&OS)))
        return false;
    osMajorVersion=OS.dwMajorVersion;
    osMinorVersion=OS.dwMinorVersion;
    osServicePack=OS.wServicePackMajor;
    osProductType=OS.wProductType;
    return true;
}

//Based on: https://code.google.com/p/volatility/issues/detail?id=189#c2
PVOID SSDTfind()
{
    UNICODE_STRING routineName;
#ifndef _WIN64
    //x86 code
    RtlInitUnicodeString(&routineName, L"KeServiceDescriptorTable");
    return MmGetSystemRoutineAddress(&routineName);
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
        if(*(unsigned int*)(function+i)==0x1ABC834B) //4b83bc1a????????00 cmp qword ptr [r10+r11+????????h],0
        {
            rvaSSDT=*(unsigned int*)(function+i+sizeof(unsigned int));
            break;
        }
    }
    PVOID base=KernelGetModuleBase("ntoskrnl");
    if(!base)
        return 0;
    DbgPrint("[TITANHIDE] KernelGetModuleBase(ntoskrnl)->0x%llX\n", base);
    return (PVOID)((unsigned char*)base+rvaSSDT);
}

PVOID SSDTgpa(const char* apiname)
{
#ifndef _WIN64
    DbgPrint("[TITANHIDE] x86 Unsupported...\n");
    return 0;
#endif

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
        if(ma==5 && mi==1 && pt==VER_NT_WORKSTATION) //Windows XP
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
    if(!_stricmp(apiname, "NtQueryObject")) //NtQueryObject
    {
        readOffset=offsetNtQueryObject;
    }
    if(readOffset==-1)
    {
        DbgPrint("[TITANHIDE] Unknown function...\n");
        return 0;
    }

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
    if(readOffset>=SSDT->NumberOfServices)
    {
        DbgPrint("[TITANHIDE] Invalid read offset...\n");
        return 0;
    }
    return (PVOID)((((LONG*)SSDT->pServiceTable)[readOffset]>>4)+SSDTbase);
}

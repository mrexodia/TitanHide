#include "ssdt.h"
#include "undocumented.h"
#include "misc.h"
#include "pe.h"

static int SSDTgetOffset(const wchar_t* apiname)
{
    RTL_OSVERSIONINFOEXW OS;
    RtlZeroMemory(&OS, sizeof(OS));
    OS.dwOSVersionInfoSize=sizeof(OS);
    if(!NT_SUCCESS(RtlGetVersion((PRTL_OSVERSIONINFOW)&OS)))
        return 0;
    int osMajorVersion=OS.dwMajorVersion;
    int osMinorVersion=OS.dwMinorVersion;
    int osServicePack=OS.wServicePackMajor;
    int osProductType=OS.wProductType;

    DbgPrint("[TITANHIDE] RtlGetVersion: %d.%d SP%d\n", osMajorVersion, osMinorVersion, osServicePack);

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

static void InterlockedSet(LONG* Destination, LONG Source)
{
    unlockCR0();
    InterlockedExchange(Destination, Source);
    lockCR0();
}

static PVOID FindCaveAddress(PVOID CodeStart, ULONG CodeSize, int CaveSize)
{
    unsigned char* Code=(unsigned char*)CodeStart;

    for(unsigned int i=0,j=0; i<CodeSize; i++)
    {
        if(Code[i]==0x90 || Code[i]==0xCC)
            j++;
        else
            j=0;
        if(j==CaveSize)
            return (PVOID)((duint)CodeStart+i-CaveSize+1);
    }
    return 0;
}

HOOK SSDThook(const wchar_t* apiname, void* newfunc)
{
    static SSDTStruct* SSDT=(SSDTStruct*)SSDTfind();
    if(!SSDT)
    {
        DbgPrint("[TITANHIDE] SSDT not found...\n");
        return 0;
    }
    duint SSDTbase=(duint)SSDT->pServiceTable;
    if(!SSDTbase)
    {
        DbgPrint("[TITANHIDE] ServiceTable not found...\n");
        return 0;
    }
    int apiOffset=SSDTgetOffset(apiname);
    if(apiOffset==-1)
        return 0;
    if(apiOffset>=SSDT->NumberOfServices)
    {
        DbgPrint("[TITANHIDE] Invalid API offset...\n");
        return 0;
    }
    HOOK hHook=0;
    LONG* SSDT_Table=(LONG*)SSDTbase;
    ULONG oldValue=SSDT_Table[apiOffset];
    ULONG newValue;    
    PVOID original;
#ifdef _WIN64
    /*
    x64 SSDT Hook;
    1) find API addr
    2) get code page+size
    3) find cave address
    4) hook cave address (using hooklib)
    5) change SSDT value
    */
    newValue=oldValue; //for testing
    
    original=(PVOID)((oldValue>>4)+SSDTbase);

    static ULONG CodeSize=0;
    static PVOID CodeStart=0;
    if(!CodeStart)
    {
        duint Lowest=SSDTbase;
        duint Highest=Lowest+0x0FFFFFFF;
        DbgPrint("[TITANHIDE] Range: 0x%p-0x%p\n", Lowest, Highest);
        CodeSize=0;
        CodeStart=PeGetPageBase(KernelGetModuleBase("ntoskrnl"), &CodeSize, original);
        if(!CodeStart || !CodeSize)
        {
            DbgPrint("[TITANHIDE] PeGetPageBase failed...\n");
            return 0;
        }
        DbgPrint("[TITANHIDE] CodeStart: 0x%p, CodeSize: 0x%X\n", CodeStart, CodeSize);
        if((duint)CodeStart<Lowest) //start of the page is out of range (impossible, but whatever)
        {
            CodeSize-=Lowest-(duint)CodeStart;
            CodeStart=(PVOID)Lowest;
            DbgPrint("[TITANHIDE] CodeStart: 0x%p, CodeSize: 0x%X\n", CodeStart, CodeSize);
        }
        DbgPrint("[TITANHIDE] Range: 0x%p-0x%p\n", CodeStart, (duint)CodeStart+CodeSize);
    }

    PVOID CaveAddress=FindCaveAddress(CodeStart, CodeSize, sizeof(opcode));
    if(!CaveAddress)
    {
        DbgPrint("[TITANHIDE] FindCaveAddress failed...\n");
        return 0;
    }
    DbgPrint("[TITANHIDE] CaveAddress: 0x%p\n", CaveAddress);

    hHook=hook(CaveAddress, (void*)newfunc);
    if(!hHook)
        return 0;
    hHook->SSDTold=original;
    hHook->SSDToffset=apiOffset;

    newValue=(duint)CaveAddress-SSDTbase;
    newValue=(newValue<<4)|oldValue&0xF;

#else
    /*
    x86 SSDT Hook:
    1) change SSDT value
    */
    newValue=(ULONG)newfunc;
    original=(PVOID)oldValue;
    hHook=(HOOK)RtlAllocateMemory(true, sizeof(hookstruct));
#endif
    
    InterlockedSet(&SSDT_Table[apiOffset], newValue);
    
    return hHook;
}

void SSDTunhook(HOOK hHook)
{
    DbgBreakPoint();
    if(!hHook)
        return;
    static SSDTStruct* SSDT=(SSDTStruct*)SSDTfind();
    if(!SSDT)
    {
        DbgPrint("[TITANHIDE] SSDT not found...\n");
        return;
    }
    duint SSDTbase=(duint)SSDT->pServiceTable;
    if(!SSDTbase)
    {
        DbgPrint("[TITANHIDE] ServiceTable not found...\n");
        return;
    }
    int apiOffset=hHook->SSDToffset;
    LONG* SSDT_Table=(LONG*)SSDTbase;
    ULONG oldValue=SSDT_Table[apiOffset];
    ULONG newValue;
    
#ifdef _WIN64
    newValue=(duint)hHook->SSDTold-SSDTbase;
    newValue=(newValue<<4)|oldValue&0xF;
#else
    newValue=(ULONG)hHook->SSDTold;
#endif

    InterlockedSet(&SSDT_Table[apiOffset], newValue);
    
#ifdef _WIN64
    unhook(hHook, true);
#endif

}
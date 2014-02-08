#include "eprocess.h"
#include "log.h"
#include <windef.h>

static int GetDebugPortOffset()
{
    static int DebugPortOffset=-1;
    if(DebugPortOffset==-1)
    {
        RTL_OSVERSIONINFOEXW OS;
        RtlZeroMemory(&OS, sizeof(OS));
        OS.dwOSVersionInfoSize=sizeof(OS);
        if(!NT_SUCCESS(RtlGetVersion((PRTL_OSVERSIONINFOW)&OS)))
            return -1;
        int ma=OS.dwMajorVersion;
        int mi=OS.dwMinorVersion;
        int pt=OS.wProductType;

        if(ma==5 && (mi==1 || (mi==2 && pt==VER_NT_WORKSTATION))) //Windows XP (x86/x64)
        {
#ifdef _WIN64
            DebugPortOffset=0x148;
#else
            DebugPortOffset=0x0bc;
#endif
        }
        else if(ma==5 && mi==1) //Windows Server 2003
        {
            //TODO: Verify these offsets
#ifdef _WIN64
            DebugPortOffset=0x148;
#else
            DebugPortOffset=0x0bc;
#endif
        }
        else if(ma==6 && mi==0 && pt==VER_NT_WORKSTATION) //Windows Vista
        {
#ifdef _WIN64
            DebugPortOffset=0x150;
#else
            DebugPortOffset=0x0d4;
#endif
        }
        else if(ma==6 && mi==0 && pt!=VER_NT_WORKSTATION) //Windows Server 2008
        {
            //TODO: Verify these offsets
#ifdef _WIN64
            DebugPortOffset=0x150;
#else
            DebugPortOffset=0x0d4;
#endif
        }
        else if(ma==6 && mi==1 && pt==VER_NT_WORKSTATION) //Windows 7
        {
#ifdef _WIN64
            DebugPortOffset=0x1f0;
#else
            DebugPortOffset=0x0ec;
#endif
        }
        else if(ma==6 && mi==2 && pt!=VER_NT_WORKSTATION) //Windows Server 2012
        {   
        }
        else if(ma==6 && mi==2 && pt==VER_NT_WORKSTATION) //Windows 8
        {
        }
        else if(ma==6 && mi==3 && pt==VER_NT_WORKSTATION) //Windows 8.1
        {
        }
    }
    return DebugPortOffset;
}

PVOID SetDebugPort(PEPROCESS Process, PVOID DebugPort)
{
    int DebugPortOffset=GetDebugPortOffset();
    if(DebugPortOffset==-1)
        return 0;
    PVOID* _DebugPort=(PVOID*)((unsigned char*)Process+DebugPortOffset);
    PVOID OldDebugPort=*_DebugPort;
    *_DebugPort=DebugPort;
    return OldDebugPort;
}

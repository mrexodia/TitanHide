#include <windows.h>
#include <stdio.h>
#include "../TitanHide/TitanHide.h"
#include "pebhider.h"

//OllyDbg definitions
#define PLUGIN_VERSION1 110
#define PLUGIN_VERSION2 0x2010001
#define PP_MAIN 3
#define PP_TERMINATED 2

//global variables
static DWORD ProcessId;

static void TitanHideCall(DWORD ProcessId, HIDE_COMMAND Command)
{
    HANDLE hDevice = CreateFileA("\\\\.\\TitanHide", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    if(hDevice == INVALID_HANDLE_VALUE)
        return;
    HIDE_INFO HideInfo;
    HideInfo.Command = Command;
    HideInfo.Pid = ProcessId;
    HideInfo.Type = 0xFFFFFFFF; //every possible option
    DWORD written = 0;
    WriteFile(hDevice, &HideInfo, sizeof(HIDE_INFO), &written, 0);
    CloseHandle(hDevice);
}

//OllyDbg1 exports
extern "C" __declspec(dllexport) int _ODBG_Plugindata(char name[32])
{
    strcpy_s(name, 32, "TitanHide");
    return PLUGIN_VERSION1;
}

extern "C" __declspec(dllexport) int _ODBG_Plugininit(int ollyVersion, HWND hwndDlg, unsigned long* features)
{
    if(ollyVersion < PLUGIN_VERSION1)
        return -1;
    return 0;
}

extern "C" __declspec(dllexport) void _ODBG_Pluginmainloop(DEBUG_EVENT* DebugEvent)
{
    static bool PEBHidden = false;
    static HANDLE hProcess;
    if(!DebugEvent)
        return;
    switch(DebugEvent->dwDebugEventCode)
    {
    case CREATE_PROCESS_DEBUG_EVENT:
    {
        hProcess = DebugEvent->u.CreateProcessInfo.hProcess;
        ProcessId = DebugEvent->dwProcessId;
        TitanHideCall(ProcessId, HidePid);
        PEBHidden = false;
    }
    break;

    case EXCEPTION_DEBUG_EVENT:
    {
        switch(DebugEvent->u.Exception.ExceptionRecord.ExceptionCode)
        {
        case STATUS_BREAKPOINT:
        {
            if(!PEBHidden)
            {
                HidePEB(hProcess, true);
                PEBHidden = true;
            }
        }
        break;
        }
    }
    break;

    case EXIT_PROCESS_DEBUG_EVENT:
    {
        if(DebugEvent->dwProcessId == ProcessId) //main process terminates
            TitanHideCall(ProcessId, UnhidePid);
    }
    break;
    }
}

extern "C" __declspec(dllexport) int _ODBG_Pausedex(int reason, int extdata, void* reg, DEBUG_EVENT* DebugEvent)
{
    if((reason & PP_MAIN) == PP_TERMINATED)
        TitanHideCall(ProcessId, UnhidePid);
    return 0;
}

//OllyDbg2 exports
extern "C" __declspec(dllexport) void _ODBG2_Pluginmainloop(DEBUG_EVENT* DebugEvent)
{
    _ODBG_Pluginmainloop(DebugEvent);
}

extern "C" __declspec(dllexport) int _ODBG2_Pluginquery(int ollyVersion, unsigned long* features, wchar_t pluginname[32], wchar_t pluginversion[32])
{
    wcscpy_s(pluginname, 32, L"TitanHide");
    return PLUGIN_VERSION2;
}

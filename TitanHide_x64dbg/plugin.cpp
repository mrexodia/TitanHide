#include "plugin.h"
#include <windows.h>
#include <stdio.h>
#include "../TitanHide/TitanHide.h"

static DWORD pid = 0;
static bool hidden = false;

static void TitanHideCall(HIDE_COMMAND Command)
{
    HANDLE hDevice = CreateFileA("\\\\.\\TitanHide", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    if(hDevice == INVALID_HANDLE_VALUE)
    {
        _plugin_logputs("[" PLUGIN_NAME "] Could not open TitanHide handle...");
        return;
    }
    HIDE_INFO HideInfo;
    HideInfo.Command = Command;
    HideInfo.Pid = pid;
    HideInfo.Type = 0xFFFFFFFF;
    DWORD written = 0;
    if(WriteFile(hDevice, &HideInfo, sizeof(HIDE_INFO), &written, 0))
    {
        _plugin_logputs("[" PLUGIN_NAME "] Process hidden!");
        hidden = true;
    }
    else
        _plugin_logputs("[" PLUGIN_NAME "] WriteFile error...");
    CloseHandle(hDevice);
}

PLUG_EXPORT void CBCREATEPROCESS(CBTYPE cbType, PLUG_CB_CREATEPROCESS* info)
{
    pid = info->fdProcessInfo->dwProcessId;
}

PLUG_EXPORT void CBATTACH(CBTYPE cbType, PLUG_CB_ATTACH* info)
{
    pid = info->dwProcessId;
}

PLUG_EXPORT void CBSYSTEMBREAKPOINT(CBTYPE cbType, PLUG_CB_SYSTEMBREAKPOINT* info)
{
    DbgCmdExec("TitanHide");
}

PLUG_EXPORT void CBSTOPDEBUG(CBTYPE cbType, PLUG_CB_STOPDEBUG* info)
{
    if(hidden)
    {
        hidden = false;
        _plugin_logprintf("[" PLUGIN_NAME "] Unhiding PID %X (%ud)\n", pid, pid);
        TitanHideCall(UnhidePid);
    }
}

static bool cbTitanHide(int argc, char* argv[])
{
    if(!hidden)
    {
        _plugin_logprintf("[" PLUGIN_NAME "] Hiding PID %X (%ud)\n", pid, pid);
        TitanHideCall(HidePid);
        DbgCmdExec("hide");
    }
    else
    {
        _plugin_logprintf("[" PLUGIN_NAME "] Unhiding PID %X (%ud)\n", pid, pid);
        TitanHideCall(UnhidePid);
    }
    return true;
}

void TitanHideInit(PLUG_INITSTRUCT* initStruct)
{
    if(!_plugin_registercommand(pluginHandle, "TitanHide", cbTitanHide, false))
        puts("[" PLUGIN_NAME "] Error registering command!");
}

void TitanHideStop()
{
    _plugin_unregistercommand(pluginHandle, "TitanHide");
}

#include "plugin.h"
#include <windows.h>
#include <stdio.h>
#include "../TitanHide/TitanHide.h"

static DWORD pid = 0;
static bool hidden = false;

static ULONG GetTitanHideOptions()
{
    duint options = 0;
    if (!BridgeSettingGetUint("TitanHide", "Options", &options))
        options = 0xffffffff;
    return (ULONG)options;
}

static bool TitanHideCall(HIDE_COMMAND Command)
{
    HANDLE hDevice = CreateFileA("\\\\.\\TitanHide", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    if(hDevice == INVALID_HANDLE_VALUE)
    {
        _plugin_logputs("[" PLUGIN_NAME "] Could not open TitanHide handle...");
        return false;
    }
    HIDE_INFO HideInfo;
    HideInfo.Command = Command;
    HideInfo.Pid = pid;
    HideInfo.Type = GetTitanHideOptions();
    DWORD written = 0;
    auto result = false;
    if(WriteFile(hDevice, &HideInfo, sizeof(HIDE_INFO), &written, 0))
    {
        _plugin_logprintf("[" PLUGIN_NAME "] Process %shidden!\n", Command == UnhidePid ? "un" : "");
        result = true;
    }
    else
    {
        _plugin_logputs("[" PLUGIN_NAME "] WriteFile error...");
    }
    CloseHandle(hDevice);
    return result;
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
    DbgCmdExecDirect("TitanHide");
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
        if (TitanHideCall(HidePid))
        {
            DbgCmdExecDirect("hide");
            hidden = true;
        }
    }
    else
    {
        _plugin_logprintf("[" PLUGIN_NAME "] Unhiding PID %X (%ud)\n", pid, pid);
        TitanHideCall(UnhidePid);
    }
    return true;
}

static bool cbTitanHideOptions(int argc, char* argv[])
{
    if (argc < 2)
    {
        _plugin_logprintf("[" PLUGIN_NAME "] Options: 0x%08X\n", GetTitanHideOptions());
    }
    else
    {
        duint options = DbgValFromString(argv[1]);
        BridgeSettingSetUint("TitanHide", "Options", options & 0xffffffff);
        if (hidden)
            TitanHideCall(HidePid);
        _plugin_logprintf("[" PLUGIN_NAME "] New options: 0x%08X\n", GetTitanHideOptions());
    }
    return true;
}

void TitanHideInit(PLUG_INITSTRUCT* initStruct)
{
    if(!_plugin_registercommand(pluginHandle, "TitanHide", cbTitanHide, false))
        puts("[" PLUGIN_NAME "] Error registering command 'TitanHide'!");
    if (!_plugin_registercommand(pluginHandle, "TitanHideOptions", cbTitanHideOptions, false))
        puts("[" PLUGIN_NAME "] Error registering command 'TitanHideOptions'!");
}

void TitanHideStop()
{
    _plugin_unregistercommand(pluginHandle, "TitanHideOptions");
    _plugin_unregistercommand(pluginHandle, "TitanHide");
}

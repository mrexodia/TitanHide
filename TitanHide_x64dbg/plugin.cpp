#include "plugin.h"
#include <windows.h>
#include <stdio.h>
#include "../TitanHide/TitanHide.h"

static DWORD pid = 0;
static bool hidden = false;

static ULONG GetTitanHideOptions()
{
    duint options = 0;
    if(!BridgeSettingGetUint("TitanHide", "Options", &options))
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

static bool cbTitanHide(int argc, char* argv[])
{
    if(!hidden)
    {
        _plugin_logprintf("[" PLUGIN_NAME "] Hiding PID %X (%ud)\n", pid, pid);
        if(TitanHideCall(HidePid))
        {
            DbgCmdExecDirect("hide");
            hidden = true;
        }
    }
    return hidden;
}

static bool cbTitanUnhide(int argc, char* argv[])
{
    if(hidden)
    {
        _plugin_logprintf("[" PLUGIN_NAME "] Unhiding PID %X (%ud)\n", pid, pid);
        if(TitanHideCall(UnhidePid))
            hidden = false;
    }
    return !hidden;
}

static bool cbTitanHideOptions(int argc, char* argv[])
{
    if(argc < 2)
    {
        _plugin_logprintf("[" PLUGIN_NAME "] Options: 0x%08X\n", GetTitanHideOptions());
    }
    else
    {
        duint options = DbgValFromString(argv[1]);
        BridgeSettingSetUint("TitanHide", "Options", options & 0xffffffff);
        if(hidden)
            TitanHideCall(HidePid);
        _plugin_logprintf("[" PLUGIN_NAME "] New options: 0x%08X\n", GetTitanHideOptions());
    }
    return true;
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
    char* argv = "TitanHide";
    cbTitanHide(1, &argv);
}

PLUG_EXPORT void CBSTOPDEBUG(CBTYPE cbType, PLUG_CB_STOPDEBUG* info)
{
    char* argv = "TitanUnhide";
    cbTitanUnhide(1, &argv);
}

void TitanHideInit(PLUG_INITSTRUCT* initStruct)
{
    _plugin_registercommand(pluginHandle, "TitanHide", cbTitanHide, true);
    _plugin_registercommand(pluginHandle, "TitanUnhide", cbTitanUnhide, true);
    _plugin_registercommand(pluginHandle, "TitanHideOptions", cbTitanHideOptions, false);
}

void TitanHideStop()
{
    _plugin_unregistercommand(pluginHandle, "TitanHideOptions");
    _plugin_unregistercommand(pluginHandle, "TitanUnhide");
    _plugin_unregistercommand(pluginHandle, "TitanHide");
}

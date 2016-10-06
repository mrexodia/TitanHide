#include <windows.h>
#include "TitanEngine/TitanEngine.h"
#include "../TitanHide/TitanHide.h"

#ifdef _WIN64
#pragma comment(lib, "TitanEngine/TitanEngine_x64.lib")
#else
#pragma comment(lib, "TitanEngine/TitanEngine_x86.lib")
#endif //_WIN64

static void TitanHideCall(DWORD ProcessId, HIDE_COMMAND Command)
{
    HANDLE hDevice = CreateFileA("\\\\.\\TitanHide", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    if(hDevice == INVALID_HANDLE_VALUE)
    {
        return;
    }
    HIDE_INFO HideInfo;
    HideInfo.Command = Command;
    HideInfo.Pid = ProcessId;
    HideInfo.Type = 0xFFFFFFFF; //every possible option
    DWORD written = 0;
    if(!WriteFile(hDevice, &HideInfo, sizeof(HIDE_INFO), &written, 0))
        MessageBoxA(0, "WriteFile error...", "Unknown cause", MB_ICONINFORMATION | MB_SYSTEMMODAL);
    CloseHandle(hDevice);
}

extern "C" __declspec(dllexport) bool TitanRegisterPlugin(char* szPluginName, LPDWORD titanPluginMajorVersion, LPDWORD titanPluginMinorVersion)
{
    strcpy_s(szPluginName, 64, "TitanHide");
    *titanPluginMajorVersion = 1;
    *titanPluginMinorVersion = 0;
    return true;
}

extern "C" __declspec(dllexport) void TitanDebuggingCallBack(LPDEBUG_EVENT debugEvent, int CallReason)
{
    static bool PEBHidden = false;
    static DWORD ProcessId;
    static HANDLE hProcess;
    switch(CallReason)
    {
    case UE_PLUGIN_CALL_REASON_EXCEPTION:
    {
        switch(debugEvent->dwDebugEventCode)
        {
        case CREATE_PROCESS_DEBUG_EVENT:
        {
            hProcess = debugEvent->u.CreateProcessInfo.hProcess;
            ProcessId = debugEvent->dwProcessId;
            TitanHideCall(ProcessId, HidePid);
            PEBHidden = false;
        }
        break;

        case EXCEPTION_DEBUG_EVENT:
        {
            switch(debugEvent->u.Exception.ExceptionRecord.ExceptionCode)
            {
            case STATUS_BREAKPOINT:
            {
                if(!PEBHidden)
                {
                    HideDebugger(hProcess, UE_HIDE_PEBONLY);
                    PEBHidden = true;
                }
            }
            break;
            }
        }
        break;
        }
    }
    break;

    case UE_PLUGIN_CALL_REASON_POSTDEBUG:
    {
        TitanHideCall(ProcessId, UnhidePid);
    }
    break;
    }
}
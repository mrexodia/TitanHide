#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <utility>
#include "resource.h"
#include "..\TitanHide\TitanHide.h"

static HINSTANCE hInst;
static char iniPath[MAX_PATH];

static std::pair<int, HIDE_TYPE> gOptions[] =
{
    { IDC_CHK_PROCESSDEBUGFLAGS, HideProcessDebugFlags },
    { IDC_CHK_PROCESSDEBUGPORT, HideProcessDebugPort },
    { IDC_CHK_PROCESSDEBUGOBJECTHANDLE, HideProcessDebugObjectHandle },
    { IDC_CHK_DEBUGOBJECT, HideDebugObject },
    { IDC_CHK_SYSTEMDEBUGGERINFORMATION, HideSystemDebuggerInformation },
    { IDC_CHK_NTCLOSE, HideNtClose },
    { IDC_CHK_THREADHIDEFROMDEBUGGER, HideThreadHideFromDebugger },
    { IDC_CHK_NTGETCONTEXTTHREAD, HideNtGetContextThread },
    { IDC_CHK_NTSETCONTEXTTHREAD, HideNtSetContextThread },
    { IDC_CHK_NTSYSTEMDEBUGCONTROL, HideNtSystemDebugControl },
};

static ULONG GetTypeDword(HWND hwndDlg)
{
    ULONG Option = 0;
    for (const auto& option : gOptions)
    {
        if (IsDlgButtonChecked(hwndDlg, option.first))
            Option |= (ULONG)option.second;
    }
    return Option;
}

static void TitanHideCall(HWND hwndDlg, HIDE_COMMAND Command)
{
    char driverName[256] = "\\\\.\\";
    GetWindowTextA(GetDlgItem(hwndDlg, IDC_EDT_DRIVER), driverName + 4, sizeof(driverName) - 4);
    WritePrivateProfileStringA("TitanHide", "DriverName", driverName + 4, iniPath);
    HANDLE hDevice = CreateFileA(driverName, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    if(hDevice == INVALID_HANDLE_VALUE)
    {
        MessageBoxA(hwndDlg, "Could not open TitanHide handle...", "Driver loaded?", MB_ICONERROR);
        return;
    }
    HIDE_INFO HideInfo;
    HideInfo.Command = Command;
    HideInfo.Pid = GetDlgItemInt(hwndDlg, IDC_EDT_PID, 0, FALSE);
    HideInfo.Type = GetTypeDword(hwndDlg);
    DWORD written = 0;
    if(WriteFile(hDevice, &HideInfo, sizeof(HIDE_INFO), &written, 0))
        MessageBoxA(hwndDlg, "Data written!", "Done", MB_ICONINFORMATION);
    else
        MessageBoxA(hwndDlg, "WriteFile error...", "Unknown cause", MB_ICONINFORMATION);
    CloseHandle(hDevice);
}

static BOOL CALLBACK DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
        SetWindowTextA(GetDlgItem(hwndDlg, IDC_EDT_DRIVER), "TitanHide");
        for (const auto& option : gOptions)
        {
            CheckDlgButton(hwndDlg, option.first, BST_CHECKED);
        }
        char driverName[256] = "";
        GetPrivateProfileStringA("TitanHide", "DriverName", "TitanHide", driverName, sizeof(driverName), iniPath);
        SetWindowTextA(GetDlgItem(hwndDlg, IDC_EDT_DRIVER), driverName);
    }
    return TRUE;

    case WM_CLOSE:
    {
        EndDialog(hwndDlg, 0);
    }
    return TRUE;

    case WM_COMMAND:
    {
        switch(LOWORD(wParam))
        {
        case IDC_BTN_HIDE:
        {
            TitanHideCall(hwndDlg, HidePid);
        }
        return TRUE;

        case IDC_BTN_UNHIDE:
        {
            TitanHideCall(hwndDlg, UnhidePid);
        }
        return TRUE;

        case IDC_BTN_UNHIDEALL:
        {
            TitanHideCall(hwndDlg, UnhideAll);
        }
        return TRUE;
        }
    }
    return TRUE;
    }
    return FALSE;
}


int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    hInst = hInstance;
    InitCommonControls();
    GetModuleFileNameA(hInstance, iniPath, sizeof(iniPath));
    auto ext = strrchr(iniPath, '.');
    if (ext != nullptr)
    {
        *ext = '\0'; // remove the extension
    }
    strncat_s(iniPath, ".ini", _TRUNCATE); // append .ini
    return (int)DialogBox(hInst, MAKEINTRESOURCE(DLG_MAIN), NULL, (DLGPROC)DlgMain);
}

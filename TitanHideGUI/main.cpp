#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include "resource.h"
#include "..\TitanHide\TitanHide.h"

HINSTANCE hInst;

static ULONG GetTypeDword(HWND hwndDlg)
{
	ULONG Option = 0;
	if (IsDlgButtonChecked(hwndDlg, IDC_CHK_PROCESSDEBUGFLAGS))
		Option |= (ULONG)HideProcessDebugFlags;
	if (IsDlgButtonChecked(hwndDlg, IDC_CHK_PROCESSDEBUGPORT))
		Option |= (ULONG)HideProcessDebugPort;
	if (IsDlgButtonChecked(hwndDlg, IDC_CHK_PROCESSDEBUGOBJECTHANDLE))
		Option |= (ULONG)HideProcessDebugObjectHandle;
	if (IsDlgButtonChecked(hwndDlg, IDC_CHK_DEBUGOBJECT))
		Option |= (ULONG)HideDebugObject;
	if (IsDlgButtonChecked(hwndDlg, IDC_CHK_SYSTEMDEBUGGERINFORMATION))
		Option |= (ULONG)HideSystemDebuggerInformation;
	if (IsDlgButtonChecked(hwndDlg, IDC_CHK_NTCLOSE))
		Option |= (ULONG)HideNtClose;
	if (IsDlgButtonChecked(hwndDlg, IDC_CHK_THREADHIDEFROMDEBUGGER))
		Option |= (ULONG)HideThreadHideFromDebugger;
	if (IsDlgButtonChecked(hwndDlg, IDC_CHK_NTSETCONTEXTTHREAD))
		Option |= (ULONG)HideNtSetContextThread;
	return Option;
}

static void TitanHideCall(HWND hwndDlg, HIDE_COMMAND Command)
{
	HANDLE hDevice = CreateFileA("\\\\.\\TitanHide", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		MessageBoxA(hwndDlg, "Could not open TitanHide handle...", "Driver loaded?", MB_ICONERROR);
		return;
	}
	HIDE_INFO HideInfo;
	HideInfo.Command = Command;
	HideInfo.Pid = GetDlgItemInt(hwndDlg, IDC_EDT_PID, 0, FALSE);
	HideInfo.Type = GetTypeDword(hwndDlg);
	DWORD written = 0;
	if (WriteFile(hDevice, &HideInfo, sizeof(HIDE_INFO), &written, 0))
		MessageBoxA(hwndDlg, "Data written!", "Done", MB_ICONINFORMATION);
	else
		MessageBoxA(hwndDlg, "WriteFile error...", "Unknown cause", MB_ICONINFORMATION);
	CloseHandle(hDevice);
}

static BOOL CALLBACK DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
	{
	}
		return TRUE;

	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
	}
		return TRUE;

	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
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
	return (int)DialogBox(hInst, MAKEINTRESOURCE(DLG_MAIN), NULL, (DLGPROC)DlgMain);
}

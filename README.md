#Overview

TitanHide is a driver intended to hide debuggers from certain processes. The driver hooks various Nt* kernel functions (using SSDT table hooks) and modifies the return values of the original functions. To hide a process, you must pass a simple structure with a ProcessID and the hiding option(s) to enable, to the driver. The internal API is designed to add hooks with little effort, which means adding features is really easy.

#Features

- ProcessDebugFlags (NtQueryInformationProcess)
- ProcessDebugPort (NtQueryInformationProcess)
- ProcessDebugObjectHandle (NtQueryInformationProcess)
- DebugObject (NtQueryObject)
- SystemKernelDebuggerInformation (NtQuerySystemInformation)
- NtClose (STATUS_INVALID_HANDLE exception)
- ThreadHideFromDebugger (NtSetInformationThread)
- Protect DRx (HW BPs) (NtSetContextThread)

#Test environments

- Windows 7 x64 & x86 (SP1)
- Windows XP x86 (SP3)
- Windows XP x64 (SP1)

#Compiling

1. Install Visual Studio 2013 (Express Edition untested).
2. Install the [WDK](http://www.microsoft.com/en-us/download/details.aspx?id=42273).
3. Open `TitanHide.sln` and hit compile!

#Installation Method 1

1. Copy `TitanHide.sys` to `%systemroot%\system32\drivers`.
2. Run the command `sc create TitanHide binPath= %systemroot%\system32\drivers\TitanHide.sys type= kernel` to create the TitanHide service.
3. Run the command `sc start TitanHide` to start the TitanHide service.
4. Run the command `sc query TitanHide` to check if TitanHide is running.

#Installation Method 2

1. Copy `TitanHide.sys` to `%systemroot%\system32\drivers`.
2. Start `ServiceManager.exe` (available on the download page).
3. Delete the old service (when present).
4. Install a new service (specify the full path to `TitanHide.sys`).
5. Start the service you just created.
6. Use `TitanHideGUI.exe` to set hide options for a PID.

#Testsigning & PatchGuard

To enable testsigning run the following command:

```
bcdedit /set testsigning on
```

To disable PatchGuard, find a tool like KPP Destroyer to disable it (Google is your friend). To check if TitanHide is working correctly, use DebugPrint or check `C:\TitanHide.log`

#Remarks

- When using x64_dbg, you can use the TitanHide plugin (available on the download page).
- When using EsetNod32 AV, disable "Realtime File Protection", to prevent a BSOD when starting TitanHide. You can re-enable it right afterwards
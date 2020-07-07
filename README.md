**Do not come here and open issues about problems with installation, crashes with bug check 0x109: CRITICAL_STRUCTURE_CORRUPTION or questions on how to disable PatchGuard. I will permanently ban you from the issue tracker. If you don't know how to properly install the tool you don't know enough to use it responsibly and you should use something else like [ScyllaHide](https://github.com/x64dbg/ScyllaHide). To disable PatchGuard, try [EfiGuard](https://github.com/Mattiwatti/EfiGuard), [UPGDSED](https://github.com/hfiref0x/UPGDSED) or [Shark](https://github.com/9176324/Shark).**

## Latest build: [![Build status](https://ci.appveyor.com/api/projects/status/cb17ic9sxmccc74d?svg=true)](https://ci.appveyor.com/project/mrexodia/titanhide/build/artifacts)

# Overview

TitanHide is a driver intended to hide debuggers from certain processes. The driver hooks various Nt* kernel functions (using SSDT table hooks) and modifies the return values of the original functions. To hide a process, you must pass a simple structure with a ProcessID and the hiding option(s) to enable, to the driver. The internal API is designed to add hooks with little effort, which means adding features is really easy.

The idea for this project was thought of together with cypher, shoutout man!

# Features

- ProcessDebugFlags (NtQueryInformationProcess)
- ProcessDebugPort (NtQueryInformationProcess)
- ProcessDebugObjectHandle (NtQueryInformationProcess)
- DebugObject (NtQueryObject)
- SystemKernelDebuggerInformation (NtQuerySystemInformation)
- SystemDebugControl (NtSystemDebugControl)
- NtClose (STATUS_INVALID_HANDLE/STATUS_HANDLE_NOT_CLOSABLE exceptions)
- ThreadHideFromDebugger (NtSetInformationThread)
- Protect DRx (HW BPs) (NtGetContextThread/NtSetContextThread)

# Test environments

- Windows 10 x64 & x86
- Windows 8.1 x64 & x86
- Windows 7 x64 & x86 (SP1)
- Windows XP x86 (SP3)
- Windows XP x64 (SP1)

# Compiling

1. Install Visual Studio 2013 (Express Edition untested).
2. Install the [WDK8](http://www.microsoft.com/en-us/download/details.aspx?id=42273)/[WDK7](https://www.microsoft.com/en-us/download/details.aspx?id=11800).
3. Open `TitanHide.sln` and hit compile!

# Installation Method 1

1. Copy `TitanHide.sys` to `%systemroot%\system32\drivers`.
2. Run the command `sc create TitanHide binPath= %systemroot%\system32\drivers\TitanHide.sys type= kernel` to create the TitanHide service.
3. Run the command `sc start TitanHide` to start the TitanHide service.
4. Run the command `sc query TitanHide` to check if TitanHide is running.

# Installation Method 2

1. Copy `TitanHide.sys` to `%systemroot%\system32\drivers`.
2. Start `ServiceManager.exe` (available on the download page).
3. Delete the old service (when present).
4. Install a new service (specify the full path to `TitanHide.sys`).
5. Start the service you just created.
6. Use `TitanHideGUI.exe` to set hide options for a PID.

# Testsigning & PatchGuard

To enable testsigning run the following command:

```
bcdedit /set testsigning on
```

To disable PatchGuard, find a tool like KPP Destroyer to disable it (Google is your friend). To check if TitanHide is working correctly, use [DebugView](https://technet.microsoft.com/en-us/sysinternals/debugview.aspx) or check `C:\TitanHide.log`. You can also try [EfiGuard](https://github.com/Mattiwatti/EfiGuard), [UPGDSED](https://github.com/hfiref0x/UPGDSED) or [Shark](https://github.com/9176324/Shark).

# Remarks

- When using x64dbg, you can use the TitanHide plugin (available on the download page).
- **NEVER RUN THIS DRIVER ON A PRODUCTION SYSTEM, ALWAYS USE A VM!**

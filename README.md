**Do not come here and open issues about problems with installation, crashes with bug check 0x109: CRITICAL_STRUCTURE_CORRUPTION or questions on how to disable PatchGuard. I will permanently ban you from the issue tracker. If you don't know how to properly install the tool you don't know enough to use it responsibly and you should use something else like [ScyllaHide](https://github.com/x64dbg/ScyllaHide).

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

1. Install Visual Studio 2022.
2. Install the [WDK10](https://go.microsoft.com/fwlink/?linkid=2128854)/[WDK8](https://go.microsoft.com/fwlink/p/?LinkID=324284)/[WDK7](https://www.microsoft.com/download/confirmation.aspx?id=11800).
3. Open `TitanHide.sln` and hit compile!

# Requirements

**You need to disable PatchGuard and driver signing enforcement (DSE) before using this driver.**

To disable PatchGuard you can try one of the following projects:

- [EfiGuard](https://github.com/Mattiwatti/EfiGuard)
- [SandboxBootkit](https://github.com/thesecretclub/SandboxBootkit)
- [Shark](https://github.com/9176324/Shark)
- [UPGDSED](https://github.com/hfiref0x/UPGDSED) (archived in 2019)

To load the driver you can enable test signing:

```sh
bcdedit /set testsigning on
```

# Installation

1. Copy `TitanHide.sys` to `%systemroot%\system32\drivers`.
2. Run the command `sc create TitanHide binPath= %systemroot%\system32\drivers\TitanHide.sys type= kernel` to create the TitanHide service.
3. Run the command `sc start TitanHide` to start the TitanHide service.
4. Run the command `sc query TitanHide` to check if TitanHide is running.

To check if TitanHide is working correctly, use [DebugView](https://technet.microsoft.com/en-us/sysinternals/debugview.aspx) or check `C:\TitanHide.log`.

**Note**: For VMProtect 3.9.4 and above you need to change the service name to something else. For example `sc create NotTitanHide`, which will bypass their latest 'detection'.

# Remarks

- When using x64dbg, you can use the TitanHide plugin (available on the download page).
- **NEVER RUN THIS DRIVER ON A PRODUCTION SYSTEM, ALWAYS USE A VM!**

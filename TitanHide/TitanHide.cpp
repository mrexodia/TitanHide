#include "hooks.h"
#include "undocumented.h"
#include "ssdt.h"
#include "hider.h"
#include "log.h"
#include "ntdll.h"
#include "threadhidefromdbg.h"

static UNICODE_STRING DeviceName;
static wchar_t DeviceNameBuffer[256];
static UNICODE_STRING Win32Device;
static wchar_t Win32DeviceBuffer[256];

static void DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
    IoDeleteSymbolicLink(&Win32Device);
    IoDeleteDevice(DriverObject->DeviceObject);
    Hooks::Deinitialize();
    NTDLL::Deinitialize();
}

static NTSTATUS DriverCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DriverDefaultHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS DriverWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    NTSTATUS RetStatus = STATUS_SUCCESS;
    PIO_STACK_LOCATION pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
    if(pIoStackIrp)
    {
        PVOID pInBuffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
        if(pInBuffer)
        {
            if(Hider::ProcessData(pInBuffer, pIoStackIrp->Parameters.Write.Length))
                Log("[TITANHIDE] HiderProcessData OK!\r\n");
            else
            {
                Log("[TITANHIDE] HiderProcessData failed...\r\n");
                RetStatus = STATUS_UNSUCCESSFUL;
            }
        }
    }
    else
    {
        Log("[TITANHIDE] Invalid IRP stack pointer...\r\n");
        RetStatus = STATUS_UNSUCCESSFUL;
    }
    Irp->IoStatus.Status = RetStatus;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return RetStatus;
}

extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    // Initialize name buffers
    RtlInitEmptyUnicodeString(&DeviceName, DeviceNameBuffer, sizeof(DeviceNameBuffer));
    RtlAppendUnicodeToString(&DeviceName, L"\\Device\\");
    RtlInitEmptyUnicodeString(&Win32Device, Win32DeviceBuffer, sizeof(Win32DeviceBuffer));
    RtlAppendUnicodeToString(&Win32Device, L"\\DosDevices\\");

    // Derive the device name and symbolic link from the registry path
    UNICODE_STRING DriverName = {};
    if (RegistryPath != NULL && RegistryPath->Buffer != NULL)
    {
        for (int i = 0; i < RegistryPath->Length / sizeof(WCHAR); i++)
        {
            auto index = RegistryPath->Length / sizeof(WCHAR) - i - 1;
            if (RegistryPath->Buffer[index] == L'\\')
            {
                index++; // skip the backslash
                DriverName.Buffer = RegistryPath->Buffer + index;
                DriverName.Length = (USHORT)(RegistryPath->Length - index * sizeof(WCHAR));
                DriverName.MaximumLength = DriverName.Length;
                break;
            }
        }
    }

    // Fall back to default driver name
    if (DriverName.Length == 0)
    {
        RtlInitUnicodeString(&DriverName, L"TitanHide");
    }

    // Use the driver name
    RtlAppendUnicodeStringToString(&DeviceName, &DriverName);
    RtlAppendUnicodeStringToString(&Win32Device, &DriverName);
    InitLog(&DriverName);
    Log("[TITANHIDE] DriverName: %.*ws\r\n", DriverName.Length / sizeof(WCHAR), DriverName.Buffer);

    PDEVICE_OBJECT DeviceObject = NULL;
    NTSTATUS status;

    //set callback functions
    DriverObject->DriverUnload = DriverUnload;
    for(unsigned int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = DriverDefaultHandler;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = DriverWrite;

    //read ntdll.dll from disk so we can use it for exports
    if(!NT_SUCCESS(NTDLL::Initialize()))
    {
        Log("[TITANHIDE] Ntdll::Initialize() failed...\r\n");
        return STATUS_UNSUCCESSFUL;
    }

    //initialize undocumented APIs
    if(!Undocumented::UndocumentedInit())
    {
        Log("[TITANHIDE] UndocumentedInit() failed...\r\n");
        return STATUS_UNSUCCESSFUL;
    }
    Log("[TITANHIDE] UndocumentedInit() was successful!\r\n");

    //find the offset of CrossThreadFlags in ETHREAD
    status = FindCrossThreadFlagsOffset(&CrossThreadFlagsOffset);
    if(!NT_SUCCESS(status))
    {
        Log("[TITANHIDE] FindCrossThreadFlagsOffset() failed: 0x%lX\r\n", status);
        return status;
    }

    //create io device
    status = IoCreateDevice(DriverObject,
                            0,
                            &DeviceName,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &DeviceObject);
    if(!NT_SUCCESS(status))
    {
        Log("[TITANHIDE] IoCreateDevice Error...\r\n");
        return status;
    }
    if(!DeviceObject)
    {
        Log("[TITANHIDE] Unexpected I/O Error...\r\n");
        return STATUS_UNEXPECTED_IO_ERROR;
    }
    Log("[TITANHIDE] Device %.*ws created successfully!\r\n", DeviceName.Length / sizeof(WCHAR), DeviceName.Buffer);

    //create symbolic link
    DeviceObject->Flags |= DO_BUFFERED_IO;
    DeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
    status = IoCreateSymbolicLink(&Win32Device, &DeviceName);
    if(!NT_SUCCESS(status))
    {
        Log("[TITANHIDE] IoCreateSymbolicLink Error...\r\n");
        return status;
    }
    Log("[TITANHIDE] Symbolic link %.*ws->%.*ws created!\r\n", Win32Device.Length / sizeof(WCHAR), Win32Device.Buffer, DeviceName.Length / sizeof(WCHAR), DeviceName.Buffer);

    //initialize hooking
    Log("[TITANHIDE] Hooks::Initialize() hooked %d functions\r\n", Hooks::Initialize());

    return STATUS_SUCCESS;
}

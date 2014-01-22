#include "stdafx.h"
#include "hooks.h"
#include <windef.h>
#include "undocumented.h"
#include "ssdt.h"
#include "hider.h"

void DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING Win32Device;
    RtlInitUnicodeString(&Win32Device,L"\\DosDevices\\TitanHide");
    IoDeleteSymbolicLink(&Win32Device);
    IoDeleteDevice(DriverObject->DeviceObject);
    HooksFree();
}

NTSTATUS DriverCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DriverDefaultHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}

NTSTATUS DriverWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS NtStatus = STATUS_SUCCESS;
    PIO_STACK_LOCATION pIoStackIrp = NULL;
    PVOID pInBuffer = NULL;

    pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);

    if(pIoStackIrp)
    {
        pInBuffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
        if(pInBuffer)
        {
            if(HiderProcessData(pInBuffer, pIoStackIrp->Parameters.Write.Length))
                DbgPrint("[TITANHIDE] HiderProcessData OK!\n");
            else
                DbgPrint("[TITANHIDE] HiderProcessData failed...\n");
        }
    }
    else
    {
        DbgPrint("[TITANHIDE] Invalid IRP stack pointer...\n");
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}

extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath)
{
    UNICODE_STRING DeviceName, Win32Device;
    PDEVICE_OBJECT DeviceObject = NULL;
    NTSTATUS status;

    //set callback functions
    DriverObject->DriverUnload = DriverUnload;

    for (unsigned int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = DriverDefaultHandler;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = DriverWrite;

    //create io device
    RtlInitUnicodeString(&DeviceName, L"\\Device\\TitanHide");
    RtlInitUnicodeString(&Win32Device, L"\\DosDevices\\TitanHide");

    status=IoCreateDevice(DriverObject,
                          0,
                          &DeviceName,
                          FILE_DEVICE_UNKNOWN,
                          FILE_DEVICE_SECURE_OPEN,
                          FALSE,
                          &DeviceObject);

    if(!NT_SUCCESS(status))
    {
        DbgPrint("[TITANHIDE] IoCreateDevice Error...\n");
        return status;
    }

    if(!DeviceObject)
    {
        DbgPrint("[TITANHIDE] Unexpected I/O Error...\n");
        return STATUS_UNEXPECTED_IO_ERROR;
    }

    DbgPrint("[TITANHIDE] Device %ws created successfully!\n", DeviceName.Buffer);

    //create symbolic link
    DeviceObject->Flags |= DO_BUFFERED_IO;
    DeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);

    status = IoCreateSymbolicLink(&Win32Device, &DeviceName);

    if(!NT_SUCCESS(status))
    {
        DbgPrint("[TITANHIDE] IoCreateSymbolicLink Error...\n");
        return status;
    }

    DbgPrint("[TITANHIDE] Symbolic link %ws, %ws created!\n", Win32Device.Buffer, DeviceName.Buffer);
    DbgPrint("[TITANHIDE] SSDTinit() returned %d\n", SSDTinit());
    DbgPrint("[TITANHIDE] HooksInit() returned %d\n", HooksInit());

    return STATUS_SUCCESS;
}

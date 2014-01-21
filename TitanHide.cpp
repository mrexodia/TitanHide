#include "stdafx.h"
#include "stringTools.h"
#include "hooks.h"
#include <windef.h>
#include "undocumented.h"
#include "ssdt.h"

void DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING Win32Device;
    RtlInitUnicodeString(&Win32Device,L"\\DosDevices\\testDriver0");
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
    PCHAR pInBuffer = NULL;

    pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);

    if(pIoStackIrp)
    {
        pInBuffer = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
        if(pInBuffer)
        {
            forceNullTermination(pInBuffer, pIoStackIrp->Parameters.Write.Length);
            DbgPrint("[TITANHIDE] Command: \"%s\"[%u]\n", pInBuffer, pIoStackIrp->Parameters.Write.Length);
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

    /*UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"KeAddSystemServiceTable");
    DbgPrint("[TITANHIDE] KeAddSystemServiceTable->0x%llX\n", MmGetSystemRoutineAddress(&routineName));

    SSDTStruct* SSDT=(SSDTStruct*)SSDTfind();
    DbgPrint("[TITANHIDE] FindSSDT: 0x%llX\n", SSDT);
    if(SSDT)
    {
        DbgPrint("[TITANHIDE] SSDT->pServiceTable: 0x%llX\n", SSDT->pServiceTable);
        DbgPrint("[TITANHIDE] SSDT->pCounterTable: 0x%llX\n", SSDT->pCounterTable);
        DbgPrint("[TITANHIDE] SSDT->NumberOfServices: 0x%llX\n", SSDT->NumberOfServices);
        DbgPrint("[TITANHIDE] SSDT->pArgumentTable: 0x%llX\n", SSDT->pArgumentTable);
#ifdef _WIN64
        unsigned long long SSDTbase=(unsigned long long)SSDT->pServiceTable;
#else
        unsigned long SSDTbase=0;
#endif
        LONG* pServiceTable=(LONG*)SSDT->pServiceTable;
        LONG offsetNtQueryObject=pServiceTable[0x000d]>>4;
        DbgPrint("[TITANHIDE] NtQueryObject offset: 0x%X\n", offsetNtQueryObject);
        DbgPrint("[TITANHIDE] NtQueryObject: 0x%llX\n", offsetNtQueryObject+SSDTbase);
    }
    
    DbgPrint("[TITANHIDE] NtQueryObject: 0x%llX\n", SSDTgpa("NtQueryObject"));*/

    return STATUS_SUCCESS;
}

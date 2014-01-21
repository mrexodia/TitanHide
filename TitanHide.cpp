#include "stdafx.h"
#include "stringTools.h"
#include "hooks.h"
#include <windef.h>
#include "undocumented.h"
#include "ssdt.h"

void testDriverUnload(IN PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING Win32Device;
    DbgPrint("[TESTDRIVER] testDriverUnload\n");
    RtlInitUnicodeString(&Win32Device,L"\\DosDevices\\testDriver0");
    IoDeleteSymbolicLink(&Win32Device);
    IoDeleteDevice(DriverObject->DeviceObject);
    HooksFree();
}

NTSTATUS testDriverCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    DbgPrint("[TESTDRIVER] testDriverCreateClose\n");
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS testDriverDefaultHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    DbgPrint("[TESTDRIVER] testDriverDefaultHandler\n");
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}

NTSTATUS testDriverWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS NtStatus = STATUS_SUCCESS;
    PIO_STACK_LOCATION pIoStackIrp = NULL;
    PCHAR pInBuffer = NULL;

    DbgPrint("[TESTDRIVER] testDriverWrite\n");

    pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);

    if(pIoStackIrp)
    {
        pInBuffer = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
        if(pInBuffer)
        {
            forceNullTermination(pInBuffer, pIoStackIrp->Parameters.Write.Length);
            DbgPrint("[TESTDRIVER] Command: \"%s\"[%u]\n", pInBuffer, pIoStackIrp->Parameters.Write.Length);
        }
    }
    else
    {
        DbgPrint("[TESTDRIVER] Invalid IRP stack pointer...\n");
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
    DriverObject->DriverUnload = testDriverUnload;

    for (unsigned int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = testDriverDefaultHandler;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = testDriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = testDriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = testDriverWrite;

    //create io device
    RtlInitUnicodeString(&DeviceName, L"\\Device\\testDriver0");
    RtlInitUnicodeString(&Win32Device, L"\\DosDevices\\testDriver0");

    status=IoCreateDevice(DriverObject,
                          0,
                          &DeviceName,
                          FILE_DEVICE_UNKNOWN,
                          FILE_DEVICE_SECURE_OPEN,
                          FALSE,
                          &DeviceObject);

    if(!NT_SUCCESS(status))
    {
        DbgPrint("[TESTDRIVER] IoCreateDevice Error...\n");
        return status;
    }

    if(!DeviceObject)
    {
        DbgPrint("[TESTDRIVER] Unexpected I/O Error...\n");
        return STATUS_UNEXPECTED_IO_ERROR;
    }

    DbgPrint("[TESTDRIVER] Device %ws created successfully!\n", DeviceName.Buffer);

    //create symbolic link
    DeviceObject->Flags |= DO_BUFFERED_IO;
    DeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);

    status = IoCreateSymbolicLink(&Win32Device, &DeviceName);

    if(!NT_SUCCESS(status))
    {
        DbgPrint("[TESTDRIVER] IoCreateSymbolicLink Error...\n");
        return status;
    }

    DbgPrint("[TESTDRIVER] Symbolic link %ws, %ws created!\n", Win32Device.Buffer, DeviceName.Buffer);
    
    DbgPrint("[TESTDRIVER] SSDTinit() returned %d\n", SSDTinit());
    DbgPrint("[TESTDRIVER] HooksInit() returned %d\n", HooksInit());

    /*UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"KeAddSystemServiceTable");
    DbgPrint("[TESTDRIVER] KeAddSystemServiceTable->0x%llX\n", MmGetSystemRoutineAddress(&routineName));

    SSDTStruct* SSDT=(SSDTStruct*)SSDTfind();
    DbgPrint("[TESTDRIVER] FindSSDT: 0x%llX\n", SSDT);
    if(SSDT)
    {
        DbgPrint("[TESTDRIVER] SSDT->pServiceTable: 0x%llX\n", SSDT->pServiceTable);
        DbgPrint("[TESTDRIVER] SSDT->pCounterTable: 0x%llX\n", SSDT->pCounterTable);
        DbgPrint("[TESTDRIVER] SSDT->NumberOfServices: 0x%llX\n", SSDT->NumberOfServices);
        DbgPrint("[TESTDRIVER] SSDT->pArgumentTable: 0x%llX\n", SSDT->pArgumentTable);
#ifdef _WIN64
        unsigned long long SSDTbase=(unsigned long long)SSDT->pServiceTable;
#else
        unsigned long SSDTbase=0;
#endif
        LONG* pServiceTable=(LONG*)SSDT->pServiceTable;
        LONG offsetNtQueryObject=pServiceTable[0x000d]>>4;
        DbgPrint("[TESTDRIVER] NtQueryObject offset: 0x%X\n", offsetNtQueryObject);
        DbgPrint("[TESTDRIVER] NtQueryObject: 0x%llX\n", offsetNtQueryObject+SSDTbase);
    }
    
    DbgPrint("[TESTDRIVER] NtQueryObject: 0x%llX\n", SSDTgpa("NtQueryObject"));*/

    return STATUS_SUCCESS;
}

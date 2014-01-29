#include "hooks.h"
#include "undocumented.h"
#include "ssdt.h"
#include "hider.h"

static UNICODE_STRING DeviceName;
static UNICODE_STRING Win32Device;

static void DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
    IoDeleteSymbolicLink(&Win32Device);
    IoDeleteDevice(DriverObject->DeviceObject);
    HooksFree();
}

static NTSTATUS DriverCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    Irp->IoStatus.Status=STATUS_SUCCESS;
    Irp->IoStatus.Information=0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DriverDefaultHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    Irp->IoStatus.Status=STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information=0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}

static NTSTATUS DriverWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS RetStatus=STATUS_SUCCESS;
    PIO_STACK_LOCATION pIoStackIrp=IoGetCurrentIrpStackLocation(Irp);
    if(pIoStackIrp)
    {
        PVOID pInBuffer=(PVOID)Irp->AssociatedIrp.SystemBuffer;
        if(pInBuffer)
        {
            if(HiderProcessData(pInBuffer, pIoStackIrp->Parameters.Write.Length))
                DbgPrint("[TITANHIDE] HiderProcessData OK!\n");
            else
            {
                DbgPrint("[TITANHIDE] HiderProcessData failed...\n");
                RetStatus=STATUS_UNSUCCESSFUL;
            }
        }
    }
    else
    {
        DbgPrint("[TITANHIDE] Invalid IRP stack pointer...\n");
        RetStatus=STATUS_UNSUCCESSFUL;
    }
    Irp->IoStatus.Status=RetStatus;
    Irp->IoStatus.Information=0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}

extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath)
{
    PDEVICE_OBJECT DeviceObject=NULL;
    NTSTATUS status;

    //set callback functions
    DriverObject->DriverUnload=DriverUnload;
    for (unsigned int i=0; i<=IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i]=DriverDefaultHandler;
    DriverObject->MajorFunction[IRP_MJ_CREATE]=DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]=DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_WRITE]=DriverWrite;

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
    DbgPrint("[TITANHIDE] Device %wZ created successfully!\n", DeviceName);

    //create symbolic link
    DeviceObject->Flags|=DO_BUFFERED_IO;
    DeviceObject->Flags&=(~DO_DEVICE_INITIALIZING);
    status=IoCreateSymbolicLink(&Win32Device, &DeviceName);
    if(!NT_SUCCESS(status))
    {
        DbgPrint("[TITANHIDE] IoCreateSymbolicLink Error...\n");
        return status;
    }
    DbgPrint("[TITANHIDE] Symbolic link %wZ->%wZ created!\n", Win32Device, DeviceName);

    //initialize hooking
    DbgPrint("[TITANHIDE] UndocumentedInit() returned %d\n", UndocumentedInit());
    DbgPrint("[TITANHIDE] HooksInit() returned %d\n", HooksInit());

    //test code
    /*UNICODE_STRING usfn;
    RtlInitUnicodeString(&usfn, L"NtSetInformationThread");
    DbgPrint("[TITANHIDE] NtSetInformationThread: 0x%p\n", MmGetSystemRoutineAddress(&usfn));*/

    return STATUS_SUCCESS;
}

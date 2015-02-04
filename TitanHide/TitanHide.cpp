#include "hooks.h"
#include "undocumented.h"
#include "ssdt.h"
#include "hider.h"
#include "log.h"
#include "ntdll.h"

static UNICODE_STRING DeviceName;
static UNICODE_STRING Win32Device;

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
	return Irp->IoStatus.Status;
}

static NTSTATUS DriverWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS RetStatus = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
	if (pIoStackIrp)
	{
		PVOID pInBuffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
		if (pInBuffer)
		{
			if (Hider::ProcessData(pInBuffer, pIoStackIrp->Parameters.Write.Length))
				Log("[TITANHIDE] HiderProcessData OK!\n");
			else
			{
				Log("[TITANHIDE] HiderProcessData failed...\n");
				RetStatus = STATUS_UNSUCCESSFUL;
			}
		}
	}
	else
	{
		Log("[TITANHIDE] Invalid IRP stack pointer...\n");
		RetStatus = STATUS_UNSUCCESSFUL;
	}
	Irp->IoStatus.Status = RetStatus;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	PDEVICE_OBJECT DeviceObject = NULL;
	NTSTATUS status;

	//set callback functions
	DriverObject->DriverUnload = DriverUnload;
	for (unsigned int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = DriverDefaultHandler;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = DriverWrite;

	//read ntdll.dll from disk so we can use it for exports
	if (!NT_SUCCESS(NTDLL::Initialize()))
	{
		Log("[TITANHIDE] Ntdll::Initialize() failed...\n");
		return STATUS_UNSUCCESSFUL;
	}

	//initialize undocumented APIs
	if (!Undocumented::UndocumentedInit())
	{
		Log("[TITANHIDE] UndocumentedInit() failed...\n");
		return STATUS_UNSUCCESSFUL;
	}
	Log("[TITANHIDE] UndocumentedInit() was successful!\n");

	//create io device
	RtlInitUnicodeString(&DeviceName, L"\\Device\\TitanHide");
	RtlInitUnicodeString(&Win32Device, L"\\DosDevices\\TitanHide");
	status = IoCreateDevice(DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DeviceObject);
	if (!NT_SUCCESS(status))
	{
		Log("[TITANHIDE] IoCreateDevice Error...\n");
		return status;
	}
	if (!DeviceObject)
	{
		Log("[TITANHIDE] Unexpected I/O Error...\n");
		return STATUS_UNEXPECTED_IO_ERROR;
	}
	Log("[TITANHIDE] Device %.*ws created successfully!\n", DeviceName.Length / sizeof(WCHAR), DeviceName.Buffer);

	//create symbolic link
	DeviceObject->Flags |= DO_BUFFERED_IO;
	DeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
	status = IoCreateSymbolicLink(&Win32Device, &DeviceName);
	if (!NT_SUCCESS(status))
	{
		Log("[TITANHIDE] IoCreateSymbolicLink Error...\n");
		return status;
	}
	Log("[TITANHIDE] Symbolic link %.*ws->%.*ws created!\n", Win32Device.Length / sizeof(WCHAR), Win32Device.Buffer, DeviceName.Length / sizeof(WCHAR), DeviceName.Buffer);

	//initialize hooking
	Log("[TITANHIDE] Hooks::Initialize() returned %d\n", Hooks::Initialize());

	return STATUS_SUCCESS;
}

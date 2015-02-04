#include "log.h"

void Log(const char* format, ...)
{
	char msg[1024] = "";
	va_list vl;
	va_start(vl, format);
	_vsnprintf(msg, sizeof(msg) / sizeof(char), format, vl);
#ifdef _DEBUG
	DbgPrint(msg);
#endif
	va_end(format);
	UNICODE_STRING FileName;
	OBJECT_ATTRIBUTES objAttr;
	RtlInitUnicodeString(&FileName, L"\\DosDevices\\C:\\TitanHide.log");
	InitializeObjectAttributes(&objAttr, &FileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
#ifdef _DEBUG
		DbgPrint("[TITANHIDE] KeGetCurrentIrql != PASSIVE_LEVEL!\n");
#endif
		return;
	}
	HANDLE handle;
	IO_STATUS_BLOCK ioStatusBlock;
	NTSTATUS ntstatus = ZwCreateFile(&handle,
		FILE_APPEND_DATA,
		&objAttr, &ioStatusBlock, NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);
	if (NT_SUCCESS(ntstatus))
	{
		size_t cb;
		ntstatus = RtlStringCbLengthA(msg, sizeof(msg), &cb);
		if (NT_SUCCESS(ntstatus))
			ZwWriteFile(handle, NULL, NULL, NULL, &ioStatusBlock, msg, (ULONG)cb, NULL, NULL);
		ZwClose(handle);
	}
}

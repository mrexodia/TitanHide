#include "log.h"
#include <ntddk.h>
#include <ntstrsafe.h>

void Log(const char* format, ...)
{
    char msg[1024]="";
    va_list vl;
    va_start(vl, format);
    if(_vsnprintf(msg, sizeof(msg)/sizeof(char), format, vl))
        DbgPrint(msg);
    va_end(format);

    UNICODE_STRING     uniName;
    OBJECT_ATTRIBUTES  objAttr;

    RtlInitUnicodeString(&uniName, L"\\DosDevices\\C:\\TitanHide.log");
    InitializeObjectAttributes(&objAttr, &uniName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    HANDLE   handle;
    NTSTATUS ntstatus;
    IO_STATUS_BLOCK    ioStatusBlock;

    // Do not try to perform any file operations at higher IRQL levels.
    // Instead, you may use a work item or a system worker thread to perform file operations.

    if(KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;

    ntstatus = ZwCreateFile(&handle,
                            FILE_APPEND_DATA,
                            &objAttr, &ioStatusBlock, NULL,
                            FILE_ATTRIBUTE_NORMAL,
                            FILE_SHARE_WRITE | FILE_SHARE_READ,
                            FILE_OPEN_IF,
                            FILE_SYNCHRONOUS_IO_NONALERT,
                            NULL, 0);
    size_t  cb;

    if(NT_SUCCESS(ntstatus))
    {
        ntstatus = RtlStringCbLengthA(msg, sizeof(msg), &cb);
        if(NT_SUCCESS(ntstatus))
        {
            ntstatus = ZwWriteFile(handle, NULL, NULL, NULL, &ioStatusBlock,
                                   msg, cb, NULL, NULL);
        }
        ZwClose(handle);
    }


}

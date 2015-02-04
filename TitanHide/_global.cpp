#include "_global.h"

void* RtlAllocateMemory(bool InZeroMemory, SIZE_T InSize)
{
	void* Result = ExAllocatePoolWithTag(NonPagedPool, InSize, 'HIDE');
	if (InZeroMemory && (Result != NULL))
		RtlZeroMemory(Result, InSize);
	return Result;
}

void RtlFreeMemory(void* InPointer)
{
	ExFreePool(InPointer);
}

//Based on: http://leguanyuan.blogspot.nl/2013/09/x64-inline-hook-zwcreatesection.html
NTSTATUS RtlSuperCopyMemory(IN VOID UNALIGNED* Destination, IN CONST VOID UNALIGNED* Source, IN ULONG Length)
{
	//Change memory properties.
	PMDL g_pmdl = IoAllocateMdl(Destination, Length, 0, 0, NULL);
	if (!g_pmdl)
		return STATUS_UNSUCCESSFUL;
	MmBuildMdlForNonPagedPool(g_pmdl);
	unsigned int* Mapped = (unsigned int*)MmMapLockedPages(g_pmdl, KernelMode);
	if (!Mapped)
	{
		IoFreeMdl(g_pmdl);
		return STATUS_UNSUCCESSFUL;
	}
	KIRQL kirql = KeRaiseIrqlToDpcLevel();
	RtlCopyMemory(Mapped, Source, Length);
	KeLowerIrql(kirql);
	//Restore memory properties.
	MmUnmapLockedPages((PVOID)Mapped, g_pmdl);
	IoFreeMdl(g_pmdl);
	return STATUS_SUCCESS;
}
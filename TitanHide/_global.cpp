#include "_global.h"

void* RtlAllocateMemory(bool InZeroMemory, SIZE_T InSize)
{
    void* Result = ExAllocatePoolWithTag(NonPagedPool, InSize, 'HIDE');
    if(InZeroMemory && (Result != NULL))
        RtlZeroMemory(Result, InSize);
    return Result;
}

void RtlFreeMemory(void* InPointer)
{
    ExFreePool(InPointer);
}

NTSTATUS RtlSuperCopyMemory(IN VOID UNALIGNED* Destination, IN CONST VOID UNALIGNED* Source, IN ULONG Length)
{
    const KIRQL Irql = KeRaiseIrqlToDpcLevel();

    PMDL Mdl = IoAllocateMdl(Destination, Length, 0, 0, nullptr);
    if(Mdl == nullptr)
    {
        KeLowerIrql(Irql);
        return STATUS_NO_MEMORY;
    }

    MmBuildMdlForNonPagedPool(Mdl);

    // Hack: prevent bugcheck from Driver Verifier and possible future versions of Windows
#pragma prefast(push)
#pragma prefast(disable:__WARNING_MODIFYING_MDL, "Trust me I'm a scientist")
    const CSHORT OriginalMdlFlags = Mdl->MdlFlags;
    Mdl->MdlFlags |= MDL_PAGES_LOCKED;
    Mdl->MdlFlags &= ~MDL_SOURCE_IS_NONPAGED_POOL;

    // Map pages and do the copy
    const PVOID Mapped = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, nullptr, FALSE, HighPagePriority);
    if(Mapped == nullptr)
    {
        Mdl->MdlFlags = OriginalMdlFlags;
        IoFreeMdl(Mdl);
        KeLowerIrql(Irql);
        return STATUS_NONE_MAPPED;
    }

    RtlCopyMemory(Mapped, Source, Length);

    MmUnmapLockedPages(Mapped, Mdl);
    Mdl->MdlFlags = OriginalMdlFlags;
#pragma prefast(pop)
    IoFreeMdl(Mdl);
    KeLowerIrql(Irql);

    return STATUS_SUCCESS;
}

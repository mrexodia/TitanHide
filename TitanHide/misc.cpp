#include "misc.h"
#include "undocumented.h"

ULONG Misc::GetProcessIDFromProcessHandle(HANDLE ProcessHandle)
{
    // FIXME: this causes a Driver Verifier violation when non-kernel handles are passed to ObReferenceObjectByHandle inside ZwQIP
    PROCESS_BASIC_INFORMATION PBI;
    if(NT_SUCCESS(Undocumented::ZwQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &PBI, sizeof(PBI), NULL)))
        return (ULONG)PBI.UniqueProcessId;

    return 0;
}

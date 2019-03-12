#include "misc.h"
#include "undocumented.h"

ULONG Misc::GetProcessIDFromProcessHandle(HANDLE ProcessHandle)
{
    PROCESS_BASIC_INFORMATION PBI;
    if(NT_SUCCESS(Undocumented::NtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &PBI, sizeof(PBI), NULL)))
        return (ULONG)PBI.UniqueProcessId;

    return 0;
}

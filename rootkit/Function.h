

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenProcess( 
	OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL
);

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenThread(
	OUT PHANDLE phThread,
	IN ACCESS_MASK AccessMask,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID pClientId
);

NTSYSAPI
NTSTATUS
NTAPI 
ZwQuerySystemInformation(
            IN ULONG SystemInformationClass,
			IN PVOID SystemInformation,
			IN ULONG SystemInformationLength,
			OUT PULONG ReturnLength
);

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(
			HANDLE ProcessHandle,
			PROCESSINFOCLASS ProcessInformationClass,
			PVOID ProcessInformation,
			ULONG ProcessInformationLength,
			PULONG ReturnLength
);


NTSYSAPI 
NTSTATUS
NTAPI 
ZwAllocateVirtualMemory(
			HANDLE ProcessHandle,
			PVOID *BaseAddress,
			ULONG ZeroBits,
			PULONG AllocationSize,
			ULONG AllocationType,
			ULONG Protect
);

NTSYSAPI 
NTSTATUS
NTAPI 
ZwFreeVirtualMemory(
			HANDLE ProcessHandle,
			PVOID *BaseAddress,
			PULONG FreeSize,
			ULONG FreeType
);





typedef NTSTATUS (NTAPI *ZWOPENPROCESS)(
	OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL
);
ZWOPENPROCESS	OldZwOpenProcess;

typedef NTSTATUS (NTAPI *ZWOPENTHREAD)(
	OUT PHANDLE phThread,
	IN ACCESS_MASK AccessMask,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID pClientId
);
ZWOPENTHREAD	OldZwOpenThread;

typedef NTSTATUS (NTAPI *ZWWRITEVIRTUALMEMORY)(
	IN HANDLE hProcess,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN ULONG BytesToWrite,
	OUT PULONG BytesWritten
);
ZWWRITEVIRTUALMEMORY	OldZwWriteVirtualMemory;

typedef NTSTATUS (NTAPI *ZWREADVIRTUALMEMORY)(
	IN HANDLE hProcess,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN ULONG BytesToWrite,
	OUT PULONG BytesWritten
);
ZWREADVIRTUALMEMORY	OldZwReadVirtualMemory;

typedef NTSTATUS (NTAPI *ZWPROTECTVIRTUALMEMORY)(
	IN HANDLE hProcess,
	IN OUT PVOID *BaseAddress,
	IN OUT PULONG RegionSize,
	IN ULONG Protect,
	OUT PULONG OldProtect
);
ZWPROTECTVIRTUALMEMORY	OldZwProtectVirtualMemory;

typedef NTSTATUS (NTAPI *ZWQUERYSYSTEMINFORMATION)(
            ULONG SystemInformationCLass,
			PVOID SystemInformation,
			ULONG SystemInformationLength,
			PULONG ReturnLength
);
ZWQUERYSYSTEMINFORMATION OldZwQuerySystemInformation;

typedef NTSTATUS (NTAPI *ZWQUERYINFORMATIONPROCESS)(
			HANDLE ProcessHandle,
			PROCESSINFOCLASS ProcessInformationClass,
			PVOID ProcessInformation,
			ULONG ProcessInformationLength,
			PULONG ReturnLength
);
ZWQUERYINFORMATIONPROCESS OldZwQueryInformationProcess;


typedef NTSTATUS (NTAPI *ZWCREATEPROCESSEX) (
			OUT PHANDLE ProcessHandle,
			IN ACCESS_MASK DesiredAccess,
			IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
			IN HANDLE ParentProcessHandle,
			IN BOOLEAN InheritObjectTable,
			IN HANDLE SectionHandle,
			IN HANDLE DebugPort,
			IN HANDLE ExceptionPort, 
			IN HANDLE Unknown
);
ZWCREATEPROCESSEX OldZwCreateProcessEx;

typedef NTSTATUS (NTAPI *ZWGETCONTEXTTHREAD) (
					HANDLE hThread, 
					PCONTEXT pContext
);
ZWGETCONTEXTTHREAD OldZwGetContextThread;

typedef NTSTATUS (NTAPI *ZWSETCONTEXTTHREAD) (
					HANDLE hThread, 
					PCONTEXT pContext
);
ZWSETCONTEXTTHREAD OldZwSetContextThread;


NTSTATUS NewZwOpenProcess( 
	OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL
);

NTSTATUS NewZwOpenThread(
	OUT PHANDLE phThread,
	IN ACCESS_MASK AccessMask,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID pClientId
);



NTSTATUS NewZwWriteVirtualMemory(
	IN HANDLE hProcess,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN ULONG BytesToWrite,
	OUT PULONG BytesWritten
);

NTSTATUS NewZwReadVirtualMemory(
	IN HANDLE hProcess,
	IN PVOID BaseAddress,
	OUT PVOID Buffer,
	IN ULONG BytesToRead,
	OUT PULONG BytesRead
);

NTSTATUS NewZwQuerySystemInformation(
            IN ULONG SystemInformationClass,
			IN PVOID SystemInformation,
			IN ULONG SystemInformationLength,
			OUT PULONG ReturnLength
);

NTSTATUS NewZwQueryInformationProcess(
			HANDLE ProcessHandle,
			PROCESSINFOCLASS ProcessInformationClass,
			PVOID ProcessInformation,
			ULONG ProcessInformationLength,
			PULONG ReturnLength
);


NTSTATUS NewZwGetContextThread(
		HANDLE hThread, 
		PCONTEXT pContext
);

NTSTATUS NewZwSetContextThread(
		HANDLE hThread, 
		PCONTEXT pContext
);
/*
NTSTATUS NewZwProtectVirtualMemory(
	IN HANDLE hProcess,
	IN OUT PVOID *BaseAddress,
	IN OUT PULONG RegionSize,
	IN ULONG Protect,
	OUT PULONG OldProtect
);


NTSTATUS NewZwCreateProcessEx(
		OUT PHANDLE ProcessHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
		IN HANDLE ParentProcessHandle,
		IN BOOLEAN InheritObjectTable,
		IN HANDLE SectionHandle,
		IN HANDLE DebugPort,
		IN HANDLE ExceptionPort, 
		IN HANDLE Unknown
);
*/
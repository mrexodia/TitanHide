#include "Driver.h"
#include "Function.h"


NTSTATUS NewZwOpenThread(
	OUT PHANDLE phThread,
	IN ACCESS_MASK AccessMask,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID pClientId
)
{
	NTSTATUS rc;
	CHAR Attack_Process_Name[PROCNAMELEN]; 
	HANDLE Pid;
	HANDLE ThreadId;
	PETHREAD Thread;
	UNICODE_STRING y;
	PVOID *PsThreadType;
	HANDLE pHandle;

	InterlockedIncrement( &G_nLockUseCounter);
	//DbgPrint("OpenThread called");
	GetProcessName(Attack_Process_Name);
	if(!strncmp(Attack_Process_Name,MYPROCESS,NT_PROCNAMELEN))
	{
		_try
		{
			Pid = pClientId->UniqueProcess;
			if(Pid == 0)
				Pid = (HANDLE)EnemyProcessID;
			ThreadId = pClientId->UniqueThread;
			if(PsLookupThreadByThreadId(ThreadId,&Thread) == STATUS_SUCCESS)
			{
				RtlInitUnicodeString(&y, L"PsThreadType");
				PsThreadType=MmGetSystemRoutineAddress(&y);
				if(PsThreadType)
				{
					rc = ObOpenObjectByPointer(
						Thread,
						0,
						NULL,
						PROCESS_ALL_ACCESS,
						(PVOID)*PsThreadType,
						KernelMode,
						&pHandle);
					//DbgPrint("ThreadntStatus=%x",NT_SUCCESS(rc));
					ObDereferenceObject(Thread);
					InterlockedDecrement( &G_nLockUseCounter );
					*phThread = pHandle;
					return rc;

				}
				else DbgPrint("PsProcessType not found\n");
			}
		}
		__except(1)
		{
			InterlockedDecrement( &G_nLockUseCounter );
			rc = STATUS_UNSUCCESSFUL;
			return rc;
		}
	}
	rc = ((ZWOPENTHREAD)(OldZwOpenThread)) ( 
			phThread,
			AccessMask,
			ObjectAttributes,
			pClientId);  
	InterlockedDecrement( &G_nLockUseCounter );
	return rc;
}
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
/*/////////////////////////ZwOpenProcess Hook//////////////////*/
NTSTATUS NewZwOpenProcess( 
	OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL
) 
{ 
    NTSTATUS rc; 
	NTSTATUS rc2;
    CHAR Attack_Process_Name[PROCNAMELEN]; 
	CHAR Target_Process_Name[PROCNAMELEN]; 
	PEPROCESS Process;
	char *nameptr;
	HANDLE Pid;
	UNICODE_STRING y;
	PVOID *PsProcessType;
	HANDLE pHandle;

	InterlockedIncrement( &G_nLockUseCounter );
    GetProcessName( Attack_Process_Name );    //GetProcessName

	if(!strncmp(Attack_Process_Name,MYPROCESS,NT_PROCNAMELEN))
	{
		_try
		{	
			Pid = ClientId->UniqueProcess;
			if(Pid > (HANDLE)0x200000)
			{
				Pid = (HANDLE)EnemyProcessID;
				//DbgPrint("You`re looser bitch!");
			}
			if(PsLookupProcessByProcessId(Pid,&Process) == STATUS_SUCCESS)
			{
				RtlInitUnicodeString(&y, L"PsProcessType");
				PsProcessType=MmGetSystemRoutineAddress(&y);
				if(PsProcessType)
				{				
					rc = ObOpenObjectByPointer(
										Process,
										0,
										NULL,
										PROCESS_ALL_ACCESS,
										(PVOID)*PsProcessType,
										KernelMode,
										&pHandle);
					InterlockedDecrement( &G_nLockUseCounter );
					//DbgPrint("Opend handle : %X",pHandle);
					*ProcessHandle = pHandle;
					return rc;
				}
				else DbgPrint("PsProcessType not found\n");
			}
		}
		__except(1)
		{
			rc = STATUS_UNSUCCESSFUL;
			return rc;
		}
	}

	rc = ((ZWOPENPROCESS)(OldZwOpenProcess)) ( //Original ZwOpenProcess()
				ProcessHandle,
				DesiredAccess,
				ObjectAttributes,
				ClientId OPTIONAL);  
	
	if(DesiredAccess == PROCESS_ALL_ACCESS || DesiredAccess == 0x410)
	{

		if(NT_SUCCESS(rc))					
		{									//SUCCESS?
			
			rc2 = ObReferenceObjectByHandle( //Get EPROCESS FROM HANDLE
						*ProcessHandle,
						PROCESS_ALL_ACCESS,
						NULL,
						KernelMode,
						(void *)&Process,
						NULL);

			if(NT_SUCCESS(rc2))				
			{
				nameptr = (PCHAR)Process + gProcessNameOffset;
				strncpy(Target_Process_Name, nameptr, NT_PROCNAMELEN); 
				Target_Process_Name[NT_PROCNAMELEN] = 0;	
				if(!strncmp(Target_Process_Name,MYPROCESS,NT_PROCNAMELEN) && 
					strncmp(Attack_Process_Name,MYPROCESS,NT_PROCNAMELEN))
				{
					ZwClose(ProcessHandle);	//Close Handle
					//DbgPrint("[Alarm] OpenProcess Detected\n");
					//DbgPrint("Called by %s\n",Attack_Process_Name);
					rc = STATUS_UNSUCCESSFUL;	//Return invalid handle
					ProcessHandle = 0;	//Handle = 0;
				}
			}
		}
	}
	InterlockedDecrement( &G_nLockUseCounter );
    return rc;	//return
} 
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
/*//////////////////ZwWriteVirtualMemory Hook//////////////////*/
NTSTATUS NTAPI NewZwWriteVirtualMemory(
	IN HANDLE hProcess,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN ULONG BytesToWrite,
	OUT PULONG BytesWritten
)
{
	NTSTATUS rc;
	NTSTATUS rc2;
    CHAR Attack_Process_Name[PROCNAMELEN]; 
	CHAR Target_Process_Name[PROCNAMELEN]; 
	PEPROCESS Process;
	char *nameptr;

	InterlockedIncrement( &G_nLockUseCounter );
	GetProcessName( Attack_Process_Name );    //Get name 
	rc2 = ObReferenceObjectByHandle(
					hProcess,
					PROCESS_ALL_ACCESS,
					NULL,
					KernelMode,
					(void *)&Process,
					NULL);
	if(NT_SUCCESS(rc2))
	{
		nameptr = (PCHAR)Process + gProcessNameOffset;
		strncpy(Target_Process_Name, nameptr, NT_PROCNAMELEN);
		Target_Process_Name[NT_PROCNAMELEN] = 0;
		if(!strncmp(Target_Process_Name,MYPROCESS,NT_PROCNAMELEN) && 
			strncmp(Attack_Process_Name,MYPROCESS,NT_PROCNAMELEN))
		{
			//DbgPrint("[Alarm] WriteMemoey Detected\n");
			//DbgPrint("Called by %s\n",Attack_Process_Name);
			hProcess = (HANDLE)-1;	//Trick for you
		}
		ObDereferenceObject(Process);
	}

	rc = ((ZWWRITEVIRTUALMEMORY)(OldZwWriteVirtualMemory)) ( 
		hProcess,
		BaseAddress,
		Buffer,
		BytesToWrite,
		BytesWritten); 

	InterlockedDecrement( &G_nLockUseCounter );
	return rc;
}
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
/*//////////////////ZwReadVirtualMemory Hook//////////////////*/
NTSTATUS NTAPI NewZwReadVirtualMemory(
	IN HANDLE hProcess,
	IN PVOID BaseAddress,
	OUT PVOID Buffer,
	IN ULONG BytesToRead,
	OUT PULONG BytesRead
)
{
	NTSTATUS rc;
	NTSTATUS rc2;
    CHAR Attack_Process_Name[PROCNAMELEN]; 
	CHAR Target_Process_Name[PROCNAMELEN]; 
	PEPROCESS Process;
	char *nameptr;
	
	InterlockedIncrement( &G_nLockUseCounter );
	GetProcessName( Attack_Process_Name );    //Get name

	rc2 = ObReferenceObjectByHandle(
					hProcess,
					PROCESS_ALL_ACCESS,
					NULL,
					KernelMode,
					(void *)&Process,
					NULL);
	if(NT_SUCCESS(rc2))
	{
		nameptr = (PCHAR)Process + gProcessNameOffset;
		strncpy(Target_Process_Name, nameptr, NT_PROCNAMELEN);
		Target_Process_Name[NT_PROCNAMELEN] = 0;
		if(!strncmp(Target_Process_Name,MYPROCESS,NT_PROCNAMELEN) && 
			strncmp(Attack_Process_Name,MYPROCESS,NT_PROCNAMELEN))
		{
			if((BytesToRead != 0x50))
			{
				//DbgPrint("[Alarm] ReadMemoey Detected\n");
				//DbgPrint("Called by %s\n",Attack_Process_Name);
				//Hey Bitch~! I already know about Ur trick.
				// 'ㅠ'~
				//hProcess = (HANDLE)-1;
								
			}
			ObDereferenceObject(Process);
			InterlockedDecrement( &G_nLockUseCounter );
			rc = ((ZWWRITEVIRTUALMEMORY)(SYSTEMSERVICEIDX(SERVICEID_WM))) ( 
			hProcess,
			BaseAddress,
			Buffer,
			BytesToRead,
			BytesRead); 
			return rc;
		}
		ObDereferenceObject(Process);
	}
	
	rc = ((ZWREADVIRTUALMEMORY)(OldZwReadVirtualMemory)) ( 
			hProcess,
			BaseAddress,
			Buffer,
			BytesToRead,
			BytesRead); 

	InterlockedDecrement( &G_nLockUseCounter );
	return rc;
}
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
NTSTATUS NTAPI NewZwQuerySystemInformation(
            IN ULONG SystemInformationClass,
			IN PVOID SystemInformation,
			IN ULONG SystemInformationLength,
			OUT PULONG ReturnLength
)
{
	NTSTATUS rc;
	CHAR Attack_Process_Name[PROCNAMELEN];
	PEPROCESS eproc,currproc;
	PLIST_ENTRY start_plist,plist_hTable = NULL;
	DWORD *d_pid;
	extern PsOffset_HandleTable,PsOffset_HandleList,PsOffset_hPID;
	extern SE_Proc;	
	extern PsOffset_ListEntry;
	char *nameptr;
	CHAR Hided_Process_Name[PROCNAMELEN]; 
	PLIST_ENTRY pCurrProc,pHideProc;
	ANSI_STRING a_ProcessName;


	InterlockedIncrement( &G_nLockUseCounter );
	GetProcessName( Attack_Process_Name );

	eproc = (PEPROCESS)SE_Proc;
	plist_hTable = (PLIST_ENTRY)((*(DWORD*)((DWORD)eproc +
		PsOffset_HandleTable)) + PsOffset_HandleList);
	start_plist = plist_hTable;

	rc = ((ZWQUERYSYSTEMINFORMATION)(OldZwQuerySystemInformation)) (
			SystemInformationClass,
			SystemInformation,
			SystemInformationLength,
			ReturnLength );

	if( NT_SUCCESS( rc ) ) 
	{

		if(5 == SystemInformationClass)
		{
			struct _SYSTEM_PROCESSES *curr = (struct _SYSTEM_PROCESSES *)SystemInformation;
			struct _SYSTEM_PROCESSES *prev = NULL;
			struct _SYSTEM_PROCESSES user;

			memcpy(&user,curr,sizeof(struct _SYSTEM_PROCESSES));
			RtlInitAnsiString(&a_ProcessName,ProcessNameBuffer);
			RtlAnsiStringToUnicodeString(&user.ProcessName,&a_ProcessName,TRUE);
			user.NextEntryDelta = 0;
			
			while(curr)
			{				
				ANSI_STRING process_name;
				RtlUnicodeStringToAnsiString( &process_name, &(curr->ProcessName), TRUE);
				if( (255 > process_name.Length) && (0 < process_name.Length) )
				{
					d_pid = (DWORD*)(((DWORD)plist_hTable + PsOffset_hPID)
						- PsOffset_HandleList);
				//	//DbgPrint("Pid : %d",*d_pid);
					PsLookupProcessByProcessId((HANDLE)*d_pid,&eproc);
				//	//DbgPrint("%X",eproc);
					plist_hTable = plist_hTable->Flink;
				//	//DbgPrint("%d",curr->ProcessId);
					if(curr->ProcessId != *d_pid)
					{
						//DbgPrint("---Hided process---");
						nameptr = (PCHAR)eproc + gProcessNameOffset;
						strncpy(Hided_Process_Name, nameptr, NT_PROCNAMELEN);
						Hided_Process_Name[NT_PROCNAMELEN] = 0;
						//DbgPrint("ProcessName:%s",Hided_Process_Name);
						//DbgPrint("ProcessId:0x%X",*d_pid);
						//DbgPrint("EPROCESS:0x%X",eproc);
						//DbgPrint("-------------------");

						if(!strncmp(ProcessNameBuffer,Hided_Process_Name,NT_PROCNAMELEN))
						{
							//DbgPrint("Target is in the stealth Mode");	
						}
					}
					
					if(0 == strncmp( process_name.Buffer, MYPROCESS, NT_PROCNAMELEN))
					{
						//DbgPrint("[Alarm] ProcessScan Detected\n");
						//DbgPrint("Called by %s\n",Attack_Process_Name);

						if(prev)
						{
							if(curr->NextEntryDelta)
							{
								prev->NextEntryDelta += curr->NextEntryDelta;
							}
							else
							{
								prev->NextEntryDelta = 0;
							}
						}
						else
						{
							if(curr->NextEntryDelta)
							{
								(char *)SystemInformation += curr->NextEntryDelta;
							}
							else
							{
								SystemInformation = NULL;
							}
						}
					}
				}
				RtlFreeAnsiString(&process_name);
				prev = curr;
				if(curr->NextEntryDelta) ((char *)curr += curr->NextEntryDelta);
				else 
				{
					if(start_plist != plist_hTable)
					{
						do
						{
							d_pid = (DWORD*)(((DWORD)plist_hTable + PsOffset_hPID)
							- PsOffset_HandleList);
							if(*d_pid == 0) 
							{
								plist_hTable = plist_hTable->Flink;
								break;
							}
							PsLookupProcessByProcessId((HANDLE)*d_pid,&eproc);
							nameptr = (PCHAR)eproc + gProcessNameOffset;
							strncpy(Hided_Process_Name, nameptr, NT_PROCNAMELEN);
							Hided_Process_Name[NT_PROCNAMELEN] = 0;
							//DbgPrint("---Hided process---");
							//DbgPrint("ProcessName:%s",Hided_Process_Name);
							//DbgPrint("ProcessId:0x%X",*d_pid);
							//DbgPrint("EPROCESS:0x%X",eproc);
							//DbgPrint("-------------------");
							
							plist_hTable = plist_hTable->Flink;

						}while(start_plist != plist_hTable);
					}
					curr = NULL;
				}
			}
		}
	}
	InterlockedDecrement( &G_nLockUseCounter );
	return rc;
}
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴

NTSTATUS NTAPI NewZwQueryInformationProcess(HANDLE ProcessHandle,
											PROCESSINFOCLASS ProcessInformationClass,
											PVOID ProcessInformation,
											ULONG ProcessInformationLength,
											PULONG ReturnLength
)
{
	NTSTATUS rc;
	NTSTATUS rc2;
	CHAR Attack_Process_Name[PROCNAMELEN];
	CHAR Target_Process_Name[PROCNAMELEN]; 
	PEPROCESS Process;
	char *nameptr;

	InterlockedIncrement( &G_nLockUseCounter );
	GetProcessName( Attack_Process_Name );
	rc = ((ZWQUERYINFORMATIONPROCESS)(OldZwQueryInformationProcess))
							(ProcessHandle,
							ProcessInformationClass,
							ProcessInformation,
							ProcessInformationLength,
							ReturnLength);
	
	if(NT_SUCCESS(rc))
	{
		rc2 = ObReferenceObjectByHandle(
					ProcessHandle,
					PROCESS_ALL_ACCESS,
					NULL,
					KernelMode,
					(void *)&Process,
					NULL);
		if(NT_SUCCESS(rc2))
		{
			nameptr = (PCHAR)Process + gProcessNameOffset;
			strncpy(Target_Process_Name, nameptr, NT_PROCNAMELEN);
			Target_Process_Name[NT_PROCNAMELEN] = 0;
			if(strncmp(Attack_Process_Name,MYPROCESS,NT_PROCNAMELEN))
			{
				if(ProcessInformationClass == ProcessDebugPort)
				{
					//DbgPrint("[Alarm] DebugPort Check Detected\n");
					//DbgPrint("Called by %s\n",Attack_Process_Name);
					if(!strncmp(Target_Process_Name,MYPROCESS,NT_PROCNAMELEN))
					{
						rc = STATUS_INVALID_HANDLE;
						ProcessInformation = 0;
						ProcessInformationLength = 0;
						ReturnLength = 0;
					}
					else if(!strncmp(Target_Process_Name,ProcessNameBuffer,NT_PROCNAMELEN))
					{
						rc = STATUS_INVALID_HANDLE;
						ProcessInformation = 0;
						ProcessInformationLength = 0;
						ReturnLength = 0;
					}
					else if(!strncmp(Attack_Process_Name,ProcessNameBuffer,NT_PROCNAMELEN))
					{
						rc = STATUS_INVALID_HANDLE;
						ProcessInformation = 0;
						ProcessInformationLength = 0;
						ReturnLength = 0;
					}
				}
		/*		else if(ProcessInformationClass == ProcessBasicInformation)
				{
					if(!strncmp(Target_Process_Name,MYPROCESS,NT_PROCNAMELEN))
					{
						rc = STATUS_SUCCESS;
						ProcessInformation = 0;
						ProcessInformationLength = 0;
						ReturnLength = 0;		
					}
				}*/
				else if(ProcessInformationClass == 0x24)
				{
					if(!strncmp(Attack_Process_Name,ProcessNameBuffer,NT_PROCNAMELEN))
					{
						rc = STATUS_INVALID_HANDLE;
						ProcessInformation = 0;
						ProcessInformationLength = 0;
						ReturnLength = 0;
					}
					if(!strncmp(Target_Process_Name,MYPROCESS,NT_PROCNAMELEN))
					{
						rc = STATUS_INVALID_HANDLE;
						ProcessInformation = 0;
						ProcessInformationLength = 0;
						ReturnLength = 0;
					}
					else if(!strncmp(Target_Process_Name,ProcessNameBuffer,NT_PROCNAMELEN))
					{
						rc = STATUS_INVALID_HANDLE;
						ProcessInformation = 0;
						ProcessInformationLength = 0;
						ReturnLength = 0;
					}
				}
			}
		}
	}
	InterlockedDecrement( &G_nLockUseCounter );
	return rc;

}
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
/*
NTSTATUS NTAPI NewZwProtectVirtualMemory(
	IN HANDLE hProcess,
	IN OUT PVOID *BaseAddress,
	IN OUT PULONG RegionSize,
	IN ULONG Protect,
	OUT PULONG OldProtect
)
{
	NTSTATUS rc;
	NTSTATUS rc2;
    CHAR Attack_Process_Name[PROCNAMELEN]; 
	CHAR Target_Process_Name[PROCNAMELEN]; 
	PEPROCESS Process;
	char *nameptr;

	GetProcessName( Attack_Process_Name );    //호출한 프로세스 이름을 구해옴 

	rc2 = ObReferenceObjectByHandle(
					hProcess,
					PROCESS_ALL_ACCESS,
					NULL,
					KernelMode,
					(void *)&Process,
					NULL);
	if(NT_SUCCESS(rc2))
	{
		nameptr = (PCHAR)Process + gProcessNameOffset;
		strncpy(Target_Process_Name, nameptr, NT_PROCNAMELEN);
		Target_Process_Name[NT_PROCNAMELEN] = 0;
		if(!strncmp(Target_Process_Name,MYPROCESS,strlen(MYPROCESS))
			&& strncmp(Attack_Process_Name,MYPROCESS,strlen(MYPROCESS)))
		{
			////DbgPrint("%s\n",Attack_Process_Name);
			////DbgPrint("Notedpad Attack was Detected-ProtectMemoey\n");
			return STATUS_SUCCESS;
		}
	}

	rc = ((ZWPROTECTVIRTUALMEMORY)(OldZwProtectVirtualMemory)) ( 
				hProcess,
				*BaseAddress,
				RegionSize,
				Protect,
				OldProtect); 
	return rc;
}



NTSTATUS NTAPI NewZwCreateProcessEx (OUT PHANDLE ProcessHandle,
									 IN ACCESS_MASK DesiredAccess,
									 IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
									 IN HANDLE ParentProcessHandle,
									 IN BOOLEAN InheritObjectTable,
									 IN HANDLE SectionHandle,
									 IN HANDLE DebugPort,
									 IN HANDLE ExceptionPort,
									 IN HANDLE Unknown)
{
	NTSTATUS rc;

	////DbgPrint("ZwCreateProcessEx - Entry\n");

	rc = OldZwCreateProcessEx(
			ProcessHandle, 
			DesiredAccess,
			ObjectAttributes,
			ParentProcessHandle,
			InheritObjectTable,
			SectionHandle,DebugPort,
			ExceptionPort,Unknown);

	if(NT_SUCCESS(rc))
	{
		NTSTATUS intstatus;

		PROCESS_BASIC_INFORMATION PBI;
		PVOID pDebug = NULL;
		ULONG ulSize = 1;

		memset(&PBI,0,sizeof(PBI));

		intstatus = ZwQueryInformationProcess(*ProcessHandle,ProcessBasicInformation,&PBI,sizeof(PBI),NULL);
		if(NT_SUCCESS(intstatus))
		{
			////DbgPrint("ZwCreateProcessEx - New process created with PEB address of 0x%08X\n",PBI.PebBaseAddress);
			
			intstatus = ZwAllocateVirtualMemory((HANDLE)-1,&pDebug,0,&ulSize,MEM_COMMIT,PAGE_READWRITE);

			if(NT_SUCCESS(intstatus))
			{
				if(pDebug != NULL)
				{
					*(unsigned char*)pDebug = FALSE;

					////DbgPrint ("ZwCreateProcessEx - Allocated memory for PEB modification, 0x%08X\n",pDebug);
					
					intstatus = OldZwWriteVirtualMemory(*ProcessHandle,(unsigned char*)PBI.PebBaseAddress+2,pDebug,1,NULL);

					if(!NT_SUCCESS(intstatus))
					{
						////DbgPrint("ZwCreateProcessEx - Failed to write to PEB in remote process 0x%08X\n",intstatus);
					}

				}
			}
			else
			{
				////DbgPrint("ZwCreateProcessEx - Failed to allocate process memory with status 0x%08X\n",intstatus);
			}

		}
		else
		{
			////DbgPrint("ZwCreateProcessEx - Failed to Query process information with error 0x%08X\n",intstatus);
		}
	}
	else
	{
		////DbgPrint("ZwCreateProcessEx - Failed to create process with error 0x%08X\n",rc);
	}

	return rc;

}
*/
#include "Driver.h"	
#include "Function.h"

/////////////////////////////////////////////
//Coded by Sammuel Dual(Dual5651@hotmail.com)
//If you want more about this Source
//Visit my bl0g. - http://dualpage.muz.ro 
/////////////////////////////////////////////

//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
/*//////////////////////Global Var////////////////////////*/
ULONG	G_nWinMajorVersion = -1;	//윈도우 버젼 확인을 위한것
ULONG	G_nWinMinorVersion = -1;	//For Windows Version Check
 
ULONG	SERVICEID_WM;				//ZwWriteVirtualMemory
ULONG   SERVICEID_RM;				//ZwReadVirtualMemory
ULONG	SERVICEID_GC;				//ZwGetThreadContext
ULONG	SERVICEID_SC;

						//EPROCESS내의 상대적 offset
ULONG	PsOffset_ListEntry;			//ListEntry offset
ULONG	PsOffset_UniqueProcessId;	//PID offset
ULONG	PsOffset_ThreadListHead;	//ThreadListHead offset
ULONG	PsOffset_HandleTable;
ULONG	PsOffset_HandleList;
ULONG	PsOffset_hPID;

ULONG	ThrdOffset_ListEntry;		//ListEntry offset
ULONG	ThrdOffset_UniqueThreadId;	//TID offset
//ULONG   ThrdOffset_ServiceTable;	//SDT pointer

PServiceDescriptorTableEntry_t SDT;			//KeServiceDescriptorTable
ULONG *NewServiceTable,*OrdServiceTable;				

PLIST_ENTRY BeforePPTR,PPTR,AfterPPTR;
PLIST_ENTRY TargetPTR,AfterTargetPTR,BeforeTargetPTR;
PLIST_ENTRY OriginalBeforePTR,OriginalAfterPTR;

								//for Communcation with APP
HANDLE LogFileHandle,LogFileHandle2;	//data file handle
CCHAR logNameFile[] = "\\DosDevices\\c:\\GR.ini";
CCHAR logNameFile2[] = "\\DosDevices\\c:\\GR2.ini";

char ProcessNameBuffer[PROCNAMELEN];	//Target process name
char OutProcessName[PROCNAMELEN];		//User`s process name

ULONG MyProcessPID;						//User process PID
ULONG EnemyProcessID;					//Target process PID 
//PLIST_ENTRY MyProcessThreadListHead;	

BOOL Hooked = FALSE;		//Native API Hooking Check
BOOL Terminated = TRUE;		//User process was terminated?
BOOL EnemyTerminated = TRUE;	//Target process was terminated?

PEPROCESS SE_Proc;

//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
/*//////////////////////Driver Entry////////////////////////*/
NTSTATUS DriverEntry ( 
            IN PDRIVER_OBJECT pDriverObject, 
            IN PUNICODE_STRING pRegistryPath    ) { 

    NTSTATUS status; 
    int i; 
	PDEVICE_OBJECT Device_Object = NULL;
	UNICODE_STRING Device_Name;
	UNICODE_STRING	Win32NameString;
	UNICODE_STRING uFileName,uFileName2;
	ANSI_STRING logNameString,logNameString2;
	OBJECT_ATTRIBUTES obj_attrib,obj_attrib2;
	IO_STATUS_BLOCK file_status,file_status2;
	IO_STATUS_BLOCK io_status,io_status2;
	LARGE_INTEGER timeout;
	
	RtlInitUnicodeString(&Device_Name,WIN_DEVICE_NAME);
	status = IoCreateDevice(pDriverObject,		//Create Device
							0,
							&Device_Name,
							FILE_DEVICE_UNKNOWN,
							0,
							FALSE,
							&Device_Object);
	if(!NT_SUCCESS(status))
	{
		//DbgPrint("CreateDevice Faild\n");
		return status;
	}
	PrintStartInfo();	//Start Logo
  	for(i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) { 
      	  pDriverObject->MajorFunction[i] = DispatchPassThru; //(2)PassThru
    	} 

        pDriverObject->DriverUnload = DriverUnload;    //(3)Driver Unload
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverControl;//IOCONTROL
	
	RtlInitUnicodeString(&Win32NameString,DOS_DEVICE_NAME);	
	status = IoCreateSymbolicLink(&Win32NameString,&Device_Name);
	//Create SymbolicLink

	if(!NT_SUCCESS(status))	//Fail?
	{
		//DbgPrint("CreateSymbolicLink Faild\n");
		IoDeleteDevice(pDriverObject->DeviceObject);	//Delete Device
		return status;

	}
	Device_Object->Flags &= ~DO_DEVICE_INITIALIZING;

    GetProcessNameOffset();    //FROM EPROCESS

	BEGINE_WIN_VER(WIN_VER_2K)//Win 2k
		//DbgPrint("[ALARM] Windows 2000\n");
		SERVICEID_WM = 0x0F0; //ZwWriteVirtualMemory	
		SERVICEID_RM = 0x0A4; //ZwReadVirtualMemory
		SERVICEID_GC = 0x049;
		SERVICEID_SC = 0x0BA;
		PsOffset_ListEntry = 0xA0;
		PsOffset_UniqueProcessId = 0x9C;
		PsOffset_ThreadListHead = 0x50;
		PsOffset_HandleTable = 0x128;
		PsOffset_HandleList = 0x54;
		PsOffset_hPID = 0x10;
		ThrdOffset_ListEntry = 0x1a4;
		ThrdOffset_UniqueThreadId = 0x1e4;
		//ThrdOffset_ServiceTable = 0xDC;
	ELSE_IF_WIN_VER(WIN_VER_XP) //Win XP
		//DbgPrint("[ALARM] Windows XP\n");
		SERVICEID_WM = 0x115;
		SERVICEID_RM = 0x0BA;
		SERVICEID_GC = 0x055;
		SERVICEID_SC = 0x0D5;
		PsOffset_ListEntry = 0x88;
		PsOffset_ThreadListHead = 0x50;
		PsOffset_UniqueProcessId = 0x84;
		PsOffset_HandleTable = 0xc4;
		PsOffset_HandleList = 0x1c;
		PsOffset_hPID = 0x08;
		ThrdOffset_ListEntry = 0x1b0;
		ThrdOffset_UniqueThreadId = 0x1f0;
	//	ThrdOffset_ServiceTable = 0x38;
	ELSE_WIN_VER()
		//DbgPrint("[ALARM]No Support OS Version\n");
		IoDeleteDevice(pDriverObject->DeviceObject);
		IoDeleteSymbolicLink ( &Win32NameString );	
		return status;
	END_WIN_VER()

	RtlInitAnsiString(&logNameString,logNameFile);

	RtlAnsiStringToUnicodeString(&uFileName,&logNameString,TRUE);
	InitializeObjectAttributes(&obj_attrib,&uFileName,
								OBJ_CASE_INSENSITIVE,
								NULL,
								NULL);

	status = ZwCreateFile(&LogFileHandle,
				GENERIC_READ,
				&obj_attrib,
				&file_status,
				NULL,
				FILE_ATTRIBUTE_NORMAL,
				0,
				FILE_OPEN_IF,
				FILE_SYNCHRONOUS_IO_NONALERT,
				NULL,
				0);

	RtlFreeUnicodeString(&uFileName);

	if(NT_SUCCESS(status))
	{
		//DbgPrint("ini Open Success");
	}
	else
	{
		//DbgPrint("ini Open Faild");
		IoDeleteDevice(pDriverObject->DeviceObject);
		IoDeleteSymbolicLink ( &Win32NameString );	
		return status;
	}

	status = ZwReadFile(LogFileHandle,	
						NULL,
						NULL,
						NULL,
						&io_status,
						ProcessNameBuffer,
						PROCNAMELEN,
						NULL,
						NULL);
	if(NT_SUCCESS(status))
	{
		//DbgPrint("Enemy Process : %s",ProcessNameBuffer);
	}
	else
	{
		//DbgPrint("Read Faild");
		IoDeleteDevice(pDriverObject->DeviceObject);
		IoDeleteSymbolicLink ( &Win32NameString );
		ZwClose(LogFileHandle);
		return status;
	}

	RtlInitAnsiString(&logNameString2,logNameFile2);

	RtlAnsiStringToUnicodeString(&uFileName2,&logNameString2,TRUE);
	InitializeObjectAttributes(&obj_attrib2,&uFileName2,
								OBJ_CASE_INSENSITIVE,
								NULL,
								NULL);

	status = ZwCreateFile(&LogFileHandle2,
				GENERIC_READ,
				&obj_attrib2,
				&file_status2,
				NULL,
				FILE_ATTRIBUTE_NORMAL,
				0,
				FILE_OPEN_IF,
				FILE_SYNCHRONOUS_IO_NONALERT,
				NULL,
				0);

	RtlFreeUnicodeString(&uFileName2);

	if(NT_SUCCESS(status))
	{
		//DbgPrint("ini2 Open Success");
	}
	else
	{
		//DbgPrint("ini2 Open Faild");
		IoDeleteDevice(pDriverObject->DeviceObject);
		IoDeleteSymbolicLink ( &Win32NameString );	
		return status;
	}

	status = ZwReadFile(LogFileHandle2,	
						NULL,
						NULL,
						NULL,
						&io_status2,
						OutProcessName,
						PROCNAMELEN,
						NULL,
						NULL);
	if(NT_SUCCESS(status))
	{
		//DbgPrint("Protect Process : %s",OutProcessName);
	}
	else
	{
		//DbgPrint("Read Faild");
		IoDeleteDevice(pDriverObject->DeviceObject);
		IoDeleteSymbolicLink ( &Win32NameString );
		ZwClose(LogFileHandle2);
		return status;
	}
	HideMyProcess();	//Hide user process
	SE_Proc = PsGetCurrentProcess();
	PsSetCreateProcessNotifyRoutine(PsNoify, FALSE); //Process Create/Terminate Notify
	SetupSTBHook();    //Set SDT Hooking
	SilenceSDT();	   //Magic Code
    status = STATUS_SUCCESS;    //return 
    return status;    
} 
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
/*//////////////////////Set Hook////////////////////////*/
VOID SetupSTBHook( void ) {
	Hooked = TRUE;
	//DbgPrint("[Alarm] HookSetup\n");	
	SetHook_ZwOpenProcess();
	SetHook_ZwOpenThread();
	SetHook_ZwWriteVirtualMemory();
	//SetHook_ZwReadVirtualMemory();	//I will do not hook this for U,bitch
	SetHook_ZwQuerySystemInformation();
	SetHook_ZwQueryInformationProcess();
}
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
/*//////////////////////Unset Hook////////////////////////*/
VOID UnSetupSTBHook( void )
{
	//DbgPrint("[Alarm] HookUnsetup\n");
	SetHook_ZwOpenProcess();
	SetHook_ZwOpenThread();
	SetHook_ZwWriteVirtualMemory();
	//SetHook_ZwReadVirtualMemory();
	SetHook_ZwQuerySystemInformation();
	SetHook_ZwQueryInformationProcess();
}
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
/*///////////////////////ServiceTable 생성////////////////////////*/
void SilenceSDT()
{
	//DbgPrint("Original KerServiceDescriptorTable : 0x%X",&KeServiceDescriptorTable);
	SDT = &KeServiceDescriptorTable;
	OrdServiceTable = SDT->ServiceTableBase;
	//DbgPrint("Original Service Table : 0x%X",OrdServiceTable);
	//DbgPrint("Number of Services : 0x%X",SDT->NumberOfServices);
	NewServiceTable = ExAllocatePool(NonPagedPool,(SDT->NumberOfServices) * 4);
	memcpy(NewServiceTable,SDT->ServiceTableBase,(SDT->NumberOfServices) * 4);
	InterSet();
	SDT->ServiceTableBase = NewServiceTable;
	InterUnset();
	//DbgPrint("New Service Table : 0x%X",KeServiceDescriptorTable.ServiceTableBase);
}

//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
/*//////////////////////Hide Enemy Process////////////////////////*/

void HideProcess()
{
	PLIST_ENTRY pProcessListPtr, pPsListHead;
	unsigned char *pProcess;
	char *nameptr;
	char theName[PROCNAMELEN];
	PLIST_ENTRY _BeforeEnemy,_Enemy,_AfterEnemy;
//	ULONG *eProcess;

	pProcessListPtr = pPsListHead = (PLIST_ENTRY)(((unsigned char *)
	PsInitialSystemProcess) + PsOffset_ListEntry);
	while(pProcessListPtr->Flink != pPsListHead)
	{
		pProcess = (((unsigned char *)pProcessListPtr) - PsOffset_ListEntry);
		if( gProcessNameOffset ) 
		{
			nameptr   = (PCHAR)pProcess + gProcessNameOffset;
			strncpy( theName, nameptr, NT_PROCNAMELEN );
			theName[NT_PROCNAMELEN] = 0; 
			//DbgPrint("%s",theName);
			if(!strncmp(ProcessNameBuffer,theName,NT_PROCNAMELEN))
			{
				_Enemy = pProcessListPtr;
				_BeforeEnemy = pProcessListPtr->Blink;
				_AfterEnemy = pProcessListPtr->Flink;
				_BeforeEnemy->Flink = _Enemy->Flink;
				_AfterEnemy->Blink = _Enemy->Blink;
				//DbgPrint("%s(Enemy) was Hided",theName);
			}
		} 
		pProcessListPtr = pProcessListPtr ->Flink;
	}
}
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
/*//////////////////////Hide User Process////////////////////////*/
void HideMyProcess()
{
	PLIST_ENTRY pProcessListPtr, pPsListHead;
	unsigned char *pProcess;
	char *nameptr;
	char theName[PROCNAMELEN];

	pProcessListPtr = pPsListHead = (PLIST_ENTRY)(((unsigned char *)
	PsInitialSystemProcess) + PsOffset_ListEntry);
	
	while(pProcessListPtr->Flink != pPsListHead)
	{
		pProcess = (((unsigned char *)pProcessListPtr) - PsOffset_ListEntry);
		nameptr   = (PCHAR)pProcess + gProcessNameOffset;
		strncpy( theName, nameptr, NT_PROCNAMELEN );
		theName[NT_PROCNAMELEN] = 0; 

		if(!strncmp(OutProcessName,theName,NT_PROCNAMELEN))
		{	

			MyProcessPID = *((DWORD *)(pProcess + PsOffset_UniqueProcessId));
			//DbgPrint("User process PID : 0x%X",MyProcessPID);
			PPTR = pProcessListPtr;
			BeforePPTR = pProcessListPtr->Blink;
			AfterPPTR = pProcessListPtr->Flink;
			BeforePPTR->Flink = PPTR->Flink;
			AfterPPTR->Blink = PPTR->Blink;
			//DbgPrint("%s(User process) was Hided",theName);
			Terminated = FALSE;
		}
		pProcessListPtr = pProcessListPtr ->Flink;
	}
}
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
/*//////////////////////Process Notify////////////////////////*/
VOID PsNoify(HANDLE ParentID, HANDLE ProcessID, BOOLEAN bCreate)
{
  //PEPROCESS MyTH;
  PEPROCESS       curproc;
  char            *nameptr;
  char theName[PROCNAMELEN];
  PLIST_ENTRY  pPsListHead;

  pPsListHead = (PLIST_ENTRY)(((unsigned char *)
	PsInitialSystemProcess) + PsOffset_ListEntry);

  PsLookupProcessByProcessId(ProcessID,&curproc);
  nameptr   = (PCHAR) curproc + gProcessNameOffset;
  strncpy( theName, nameptr, NT_PROCNAMELEN);
  theName[NT_PROCNAMELEN] = 0; /* NULL at end */
  if(bCreate)
  {
	  if( gProcessNameOffset ) 
	  {
		//DbgPrint("%s",theName);
		if(!strncmp(theName,ProcessNameBuffer,NT_PROCNAMELEN))
		{	//theName == Target Process?
			//DbgPrint("I find enemy process");
			EnemyTerminated = FALSE;
			//DbgPrint("PID : %d, Parent ID : %d", ProcessID, ParentID);
			TargetPTR = (PLIST_ENTRY)(((unsigned char *)
	        curproc) + PsOffset_ListEntry);
			EnemyProcessID = (ULONG)ProcessID; //Save enemy PID
		//	HideProcess();	//Hide Enemy Process
		}		
	  } 
  }
  else
  {
	if(!strncmp(theName,OutProcessName,NT_PROCNAMELEN))	//User Process?
	{
		//DbgPrint("Out Process was terminated");
		//DbgPrint("PID : %d, Parent ID : %d", ProcessID, ParentID);
		Terminated = TRUE;
	}
	else if(!strncmp(theName,ProcessNameBuffer,NT_PROCNAMELEN))	//Enemy Process?
	{
		//DbgPrint("Enemy Process was terminated");
		//DbgPrint("PID : %d, Parent ID : %d", ProcessID, ParentID);
		EnemyTerminated = TRUE;
	}
  }
}

//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
/*///////////////////Get Process Name Offset/////////////////*/
VOID GetProcessNameOffset( void ) {
	
    PEPROCESS curproc;
    int i;

	curproc = PsGetCurrentProcess();
    for( i = 0; i < 3*PAGE_SIZE; i++ ) 
	{
        if( !strncmp( "System", (PCHAR)curproc + i, strlen("System") ))
		{
            gProcessNameOffset = i;
		}
    }STATUS_SUCCESS;
}
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
/*/////////////////////////// GetProcess Name //////////////////*/
BOOL GetProcessName( PCHAR theName )
{
    PEPROCESS       curproc;
    char            *nameptr;

    if( gProcessNameOffset ) 
	{
        curproc = PsGetCurrentProcess();
        nameptr   = (PCHAR) curproc + gProcessNameOffset;
        strncpy( theName, nameptr, NT_PROCNAMELEN );
        theName[NT_PROCNAMELEN] = 0; /* NULL at end */
		return TRUE;
    } 
	return FALSE;
}
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
/*///////////////////////////////// IO Control///////////////// */
NTSTATUS My_IoControl(PFILE_OBJECT pFileObject,
					  ULONG nIoCode, 
					  PCHAR pSystemBuffer,
					  ULONG nInput,
					  ULONG nOutput,
					  ULONG *nReturnOut)
{
//	PLIST_ENTRY  pPsListHead;

	switch(nIoCode)
	{
		case APP_MSG_LIVECHECK:
			break;
		default:
			return STATUS_INVALID_DEVICE_REQUEST;
	}
		
	return STATUS_SUCCESS;
}
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
/*////////////////////// Start Logo/////////////////////////// */
VOID PrintStartInfo( void )
{
	//DbgPrint(":::::::Game Resistance Driver:::::::\n");    
	//DbgPrint("\n");
	//DbgPrint("Coded by Dual†\n");
	//DbgPrint("\n");
	//DbgPrint("09/15/2006(M/D/Y)\n");
	//DbgPrint("\n");
}
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
/*//////////////////////Dispatch////////////////////////*/
NTSTATUS DispatchPassThru(
		IN PDEVICE_OBJECT DeviceObject,
		IN   PIRP Irp		) {

	PIO_STACK_LOCATION CurIrpStack = IoGetCurrentIrpStackLocation(Irp);	
    PFILE_OBJECT pFileObject;
	UCHAR MajorFunction = CurIrpStack->MajorFunction;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	if(MajorFunction == IRP_MJ_CLOSE)
	{
		pFileObject = CurIrpStack->FileObject;
	}
	IoCompleteRequest(Irp,IO_NO_INCREMENT);
	if(MajorFunction == IRP_MJ_CREATE)
	{
		pFileObject = CurIrpStack->FileObject;		
	}
	return Irp->IoStatus.Status;
}
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
NTSTATUS DriverControl (IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	ULONG ulIoControlCode;
	PIO_STACK_LOCATION pCurIrpStack;	    
	PCHAR pInputBuffer;
	ULONG ulInputBufferLength, ulOutputBufferLength;    
	NTSTATUS	nReturn = STATUS_SUCCESS;	
	ULONG 	nOutputBufferLength = 0;
	PFILE_OBJECT pFileObject;
	pCurIrpStack = IoGetCurrentIrpStackLocation( Irp );    
	ulIoControlCode = pCurIrpStack -> Parameters.DeviceIoControl.IoControlCode;
    pFileObject = pCurIrpStack->FileObject;
    
	pInputBuffer = (PCHAR) (Irp->AssociatedIrp.SystemBuffer);
	ulInputBufferLength = pCurIrpStack -> Parameters.DeviceIoControl.InputBufferLength;
	ulOutputBufferLength = pCurIrpStack -> Parameters.DeviceIoControl.OutputBufferLength;
	if( pInputBuffer == NULL )
	{
		Irp -> IoStatus.Information = 0;
		Irp -> IoStatus.Status = STATUS_INVALID_PARAMETER;
		return STATUS_SUCCESS;  
	}
	
	nReturn = My_IoControl(pFileObject, ulIoControlCode, pInputBuffer, ulInputBufferLength, ulOutputBufferLength, &nOutputBufferLength);

	if(nOutputBufferLength)
		Irp->IoStatus.Information = nOutputBufferLength;
	Irp -> IoStatus.Status = nReturn;
	
	IoCompleteRequest( Irp, IO_NO_INCREMENT );	
	return STATUS_SUCCESS;  
}
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
VOID DriverUnload (
		IN PDRIVER_OBJECT	pDriverObject	) {

	KTIMER timer;
	LARGE_INTEGER duetime = {0};
	UNICODE_STRING Win32NameString;
	
	KeInitializeTimerEx( &timer, SynchronizationTimer );
	KeSetTimerEx( &timer, duetime, 100, NULL );		
	while (G_nLockUseCounter > 0)
	{
		KeWaitForSingleObject(&timer, Executive, KernelMode, FALSE, NULL );
	}
	KeCancelTimer( &timer );
	
	RtlInitUnicodeString ( &Win32NameString , DOS_DEVICE_NAME );	
	IoDeleteSymbolicLink ( &Win32NameString );	

	IoDeleteDevice ( pDriverObject -> DeviceObject );
	PsSetCreateProcessNotifyRoutine(PsNoify, TRUE);
	
	if(NewServiceTable)
	{
		//DbgPrint("Release FakeServiceTabel");
		InterSet();
		SDT->ServiceTableBase = OrdServiceTable;
		InterUnset();
		ExFreePool(NewServiceTable);
	}

	if(PPTR && !Terminated)
	{
		//DbgPrint("UnStealth MyProgram");
		AfterPPTR = BeforePPTR->Flink;
		BeforePPTR->Flink = PPTR;
		PPTR->Blink = BeforePPTR;
		AfterPPTR->Blink = PPTR;
		PPTR->Flink = AfterPPTR;
	}
	else
	{
		//DbgPrint("Maybe user process was already terminated.");
	}
	
	if(Hooked)
		UnSetupSTBHook();

	if(LogFileHandle)
	{
		//DbgPrint("ini File Close");
		ZwClose(LogFileHandle);
	}
	if(LogFileHandle2)
	{
		//DbgPrint("ini2 File Close");
		ZwClose(LogFileHandle2);
	}

	//DbgPrint(":::::::Driver Unloaded:::::::\n");	//Driver Unload
	
}
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
/////////////////////////////////////////////
//Coded by Sammuel Dual(Dual5651@hotmail.com)
//If you want more about this Source
//Visit my bl0g. - http://dualpage.muz.ro 
/////////////////////////////////////////////




#include "Driver.h"
#include "Function.h"

//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
VOID InterSet( void )
{
	_asm
	{
		CLI
		MOV	EAX, CR0	
		AND EAX, NOT 10000H 
		MOV	CR0, EAX
	}
}
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
VOID InterUnset( void )
{
	_asm
	{
		MOV	EAX, CR0		
		OR	EAX, 10000H		
		MOV	CR0, EAX			
		STI	
	}
}

//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
VOID SetHook_ZwOpenProcess( void )
{
	static BOOL HookStatus = FALSE;
	
	InterSet();
	if(!HookStatus)
	{
		OldZwOpenProcess =
		(ZWOPENPROCESS)
		(SYSTEMSERVICE(ZwOpenProcess));
		DbgPrint("ZwOpenProcess Hook Setup");
		DbgPrint("0x%0X -> 0x%0X\n",
		OldZwOpenProcess,NewZwOpenProcess);
		
		(ZWOPENPROCESS)
		(SYSTEMSERVICE(ZwOpenProcess))
		= NewZwOpenProcess;

		HookStatus = TRUE;
	}
	else
	{
		(ZWOPENPROCESS)
		(SYSTEMSERVICE(ZwOpenProcess))
		= OldZwOpenProcess;

		HookStatus = FALSE;
		DbgPrint("ZwOpenProcess Hook Unsetup");
	}
	InterUnset();
}

VOID SetHook_ZwOpenThread( void )
{
	static BOOL HookStatus = FALSE;
	
	InterSet();
	if(!HookStatus)
	{
		OldZwOpenThread =
		(ZWOPENTHREAD)
		(SYSTEMSERVICE(ZwOpenThread));
		DbgPrint("ZwOpenThread Hook Setup");
		DbgPrint("0x%0X -> 0x%0X\n",
		OldZwOpenThread,NewZwOpenThread);
		
		(ZWOPENTHREAD)
		(SYSTEMSERVICE(ZwOpenThread))
		= NewZwOpenThread;

		HookStatus = TRUE;
	}
	else
	{
		(ZWOPENTHREAD)
		(SYSTEMSERVICE(ZwOpenThread))
		= OldZwOpenThread;

		HookStatus = FALSE;
		DbgPrint("ZwOpenThread Hook Unsetup");
	}
	InterUnset();
}
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
VOID SetHook_ZwWriteVirtualMemory( void )
{
	static BOOL HookStatus = FALSE;
	
	InterSet();
	if(!HookStatus)
	{
		OldZwWriteVirtualMemory = 
		(ZWWRITEVIRTUALMEMORY)
		(SYSTEMSERVICEIDX(SERVICEID_WM));
		DbgPrint("ZwWriteVirtualMemory Hook Setup");
		DbgPrint("0x%0X -> 0x%0X\n",
		OldZwWriteVirtualMemory,NewZwWriteVirtualMemory);

		(ZWWRITEVIRTUALMEMORY)
		(SYSTEMSERVICEIDX(SERVICEID_WM))
		= NewZwWriteVirtualMemory;

		HookStatus = TRUE;
	}
	else
	{
		(ZWWRITEVIRTUALMEMORY)
		(SYSTEMSERVICEIDX(SERVICEID_WM))
		= OldZwWriteVirtualMemory;
		
		HookStatus = FALSE;
		DbgPrint("ZwWriteVirtualMemory Hook Unsetup");
	}
	InterUnset();
}
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
VOID SetHook_ZwReadVirtualMemory( void )
{
	static BOOL HookStatus = FALSE;
	
	InterSet();
	if(!HookStatus)
	{
		OldZwReadVirtualMemory = 
		(ZWREADVIRTUALMEMORY)
		(SYSTEMSERVICEIDX(SERVICEID_RM));
		DbgPrint("ZwReadVirtualMemory Hook Setup");
		DbgPrint("0x%0X -> 0x%0X\n",
		OldZwReadVirtualMemory,NewZwReadVirtualMemory);

		(ZWREADVIRTUALMEMORY)
		(SYSTEMSERVICEIDX(SERVICEID_RM))
		= NewZwReadVirtualMemory;
		
		HookStatus = TRUE;
	}
	else
	{
		(ZWREADVIRTUALMEMORY)
		(SYSTEMSERVICEIDX(SERVICEID_RM))
		= OldZwReadVirtualMemory;
		
		HookStatus = FALSE;
		DbgPrint("ZwReadVirtualMemory Hook Unsetup");
	}
	InterUnset();
}
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
VOID SetHook_ZwQuerySystemInformation( void )
{
	static BOOL HookStatus = FALSE;
	
	InterSet();
	if(!HookStatus)
	{
		OldZwQuerySystemInformation =
		(ZWQUERYSYSTEMINFORMATION)
		(SYSTEMSERVICE(ZwQuerySystemInformation));
		DbgPrint("ZwQuerySystemInformation Hook Setup");
		DbgPrint("0x%0X -> 0x%0X\n",
		OldZwQuerySystemInformation,NewZwQuerySystemInformation);

		(ZWQUERYSYSTEMINFORMATION)
		(SYSTEMSERVICE(ZwQuerySystemInformation))
		= NewZwQuerySystemInformation; 
		
		HookStatus = TRUE;
	}
	else
	{
		(ZWQUERYSYSTEMINFORMATION)
		(SYSTEMSERVICE(ZwQuerySystemInformation))
		= OldZwQuerySystemInformation;
		
		HookStatus = FALSE;
		DbgPrint("ZwQuerySystemInformation Hook Unsetup");
	}
	InterUnset();
}
//컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
VOID SetHook_ZwQueryInformationProcess( void )
{
	static BOOL HookStatus = 0;
	
	InterSet();
	if(!HookStatus)
	{
		OldZwQueryInformationProcess =
		(ZWQUERYINFORMATIONPROCESS)
		(SYSTEMSERVICE(ZwQueryInformationProcess));
		DbgPrint("ZwQueryInformationProcess Hook Setup");
		DbgPrint("0x%0X -> 0x%0X\n",
		OldZwQueryInformationProcess,NewZwQueryInformationProcess);

		(ZWQUERYINFORMATIONPROCESS)
		(SYSTEMSERVICE(ZwQueryInformationProcess))
		= NewZwQueryInformationProcess;
		HookStatus = TRUE;
	}
	else
	{
		(ZWQUERYINFORMATIONPROCESS)
		(SYSTEMSERVICE(ZwQueryInformationProcess))
		= OldZwQueryInformationProcess;
		HookStatus = FALSE;
	}
	InterUnset();
}


/*
VOID SetHook_( void )
{
	static BOOL HookStatus = 0;
	
	InterSet();
	if(!HookStatus)
	{

	}
	else
	{

	}
	InterUnset();
}
*/

/*
	///////////////////////////////////////////////////
	OldZwProtectVirtualMemory = 
	(ZWPROTECTVIRTUALMEMORY)
	(SYSTEMSERVICEIDX(137));
	DbgPrint("ZwProtectVirtualMemory Hook Setup");
	DbgPrint("0x%0X -> 0x%0X\n",
	OldZwProtectVirtualMemory,NewZwProtectVirtualMemory);
	///////////////////////////////////////////////////
	OldZwQueryInformationProcess =
	(ZWQUERYINFORMATIONPROCESS)
	(SYSTEMSERVICE(ZwQueryInformationProcess));
	DbgPrint("ZwQueryInformationProcess Hook Setup");
	DbgPrint("0x%0X -> 0x%0X\n",
	OldZwQueryInformationProcess,NewZwQueryInformationProcess);
	///////////////////////////////////////////////////
	OldZwCreateProcessEx =
	(ZWCREATEPROCESSEX)
	(SYSTEMSERVICEIDX(48));
	DbgPrint("ZwCreateProcessEx Hook Setup");
	DbgPrint("0x%0X -> 0x%0X\n"
	OldZwCreateProcessEx,NewZwCreateProcessEx);
	///////////////////////////////////////////////////
	DbgPrint("[Alarm] HookSetup Ended\n");

//////////////////////////////////////////////////
아직은 사용되지 않는 함수들
	(ZWPROTECTVIRTUALMEMORY)
	(SYSTEMSERVICEIDX(137))
	= NewZwProtectVirtualMemory;
///////////////////////////////////////////////////
	(ZWQUERYINFORMATIONPROCESS)
	(SYSTEMSERVICE(ZwQueryInformationProcess))
	= NewZwQueryInformationProcess;
///////////////////////////////////////////////////
	(ZWCREATEPROCESSEX)
	(SYSTEMSERVICEIDX(48))
	= NewZwCreateProcessEx; */

/*	
	///////////////////////////////////////////////////
	(ZWPROTECTVIRTUALMEMORY)
	(SYSTEMSERVICEIDX(137))
	= OldZwProtectVirtualMemory;
	///////////////////////////////////////////////////
	(ZWQUERYINFORMATIONPROCESS)
	(SYSTEMSERVICE(ZwQueryInformationProcess))
	= OldZwQueryInformationProcess;
	///////////////////////////////////////////////////
	(ZWCREATEPROCESSEX)
	(SYSTEMSERVICEIDX(48))
	= OldZwCreateProcessEx;*/

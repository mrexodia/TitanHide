#pragma once

/*!	\file 
	\brief Contains definitions making handles and NTSTATUS variables recognizable by debugger
	This file contains definitions for special helper structures and enums, so NTSTATUS and HANDLE
	variables will not appear in debugger as "unsigned long" and "void *".
	
	Once the variable type is recognized correctly, VisualDDK can display additional information
	about this types, such as translated NTSTATUS code and object referenced by handle.
*/

#ifdef _DEBUG

#include <excpt.h>
#include <ntdef.h>

typedef enum NTSTATUS_VisualDDK_Helper {} NTSTATUS_VisualDDK_Helper_t;
C_ASSERT(sizeof(NTSTATUS_VisualDDK_Helper_t) == sizeof(NTSTATUS));

#define NTSTATUS NTSTATUS_VisualDDK_Helper_t

typedef struct HANDLE_VisualDDK_Helper *HANDLE_VisualDDK_Helper_t, **PHANDLE_VisualDDK_Helper_t;
C_ASSERT(sizeof(HANDLE_VisualDDK_Helper_t) == sizeof(HANDLE));
C_ASSERT(sizeof(PHANDLE_VisualDDK_Helper_t) == sizeof(PHANDLE));

#define HANDLE HANDLE_VisualDDK_Helper_t
#define PHANDLE PHANDLE_VisualDDK_Helper_t 

#endif
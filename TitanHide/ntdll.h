#ifndef _NTDLL_H
#define _NTDLL_H

#include "_global.h"

class Ntdll
{
public:
	static NTSTATUS Initialize();
	static void Deinitialize();
	static int GetSsdtOffset(const char* ExportName);

private:
	static unsigned char* FileData;
	static ULONG FileSize;
};

#endif //_NTDLL_H
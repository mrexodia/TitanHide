#ifndef _NTDLL_H
#define _NTDLL_H

#include "_global.h"

class NTDLL
{
public:
	static NTSTATUS Initialize();
	static void Deinitialize();
	static int GetExportSsdtIndex(const char* ExportName);

private:
	static unsigned char* FileData;
	static ULONG FileSize;
};

#endif //_NTDLL_H
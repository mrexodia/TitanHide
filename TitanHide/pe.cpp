#include "pe.h"
#include "log.h"

static ULONG RvaToSection(IMAGE_NT_HEADERS* pNtHdr, ULONG dwRVA)
{
	USHORT wSections;
	PIMAGE_SECTION_HEADER pSectionHdr;
	pSectionHdr = IMAGE_FIRST_SECTION(pNtHdr);
	wSections = pNtHdr->FileHeader.NumberOfSections;
	for (int i = 0; i < wSections; i++)
	{
		if (pSectionHdr[i].VirtualAddress <= dwRVA)
			if ((pSectionHdr[i].VirtualAddress + pSectionHdr[i].Misc.VirtualSize) > dwRVA)
			{
			return i;
			}
	}
	return (ULONG)-1;
}

static ULONG RvaToOffset(PIMAGE_NT_HEADERS pnth, ULONG Rva, ULONG FileSize)
{
	PIMAGE_SECTION_HEADER psh = IMAGE_FIRST_SECTION(pnth);
	USHORT NumberOfSections = pnth->FileHeader.NumberOfSections;
	for (int i = 0; i<NumberOfSections; i++)
	{
		if (psh->VirtualAddress <= Rva)
		{
			if ((psh->VirtualAddress + psh->Misc.VirtualSize) > Rva)
			{
				Rva -= psh->VirtualAddress;
				Rva += psh->PointerToRawData;
				return Rva < FileSize ? Rva : PE_ERROR_VALUE;
			}
		}
		psh++;
	}
	return PE_ERROR_VALUE;
}

ULONG PE::GetExportOffset(const unsigned char* FileData, ULONG FileSize, const char* ExportName)
{
	//Verify DOS Header
	PIMAGE_DOS_HEADER pdh = (PIMAGE_DOS_HEADER)FileData;
	if (pdh->e_magic != IMAGE_DOS_SIGNATURE)
	{
		Log("[TITANHIDE] Invalid IMAGE_DOS_SIGNATURE!\n");
		return PE_ERROR_VALUE;
	}

	//Verify PE Header
	PIMAGE_NT_HEADERS pnth = (PIMAGE_NT_HEADERS)(FileData + pdh->e_lfanew);
	if (pnth->Signature != IMAGE_NT_SIGNATURE)
	{
		Log("[TITANHIDE] Invalid IMAGE_NT_SIGNATURE!\n");
		return PE_ERROR_VALUE;
	}

	//Verify Export Directory
	PIMAGE_DATA_DIRECTORY pdd = pnth->OptionalHeader.DataDirectory;
	ULONG ExportDirRva = pdd[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	ULONG ExportDirSize = pdd[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	ULONG ExportDirOffset = RvaToOffset(pnth, ExportDirRva, FileSize);
	if (ExportDirOffset == PE_ERROR_VALUE)
	{
		Log("[TITANHIDE] Invalid Export Directory!\n");
		return PE_ERROR_VALUE;
	}

	//Read Export Directory
	PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)(FileData + ExportDirOffset);
	ULONG NumberOfNames = ExportDir->NumberOfNames;
	ULONG AddressOfFunctionsOffset = RvaToOffset(pnth, ExportDir->AddressOfFunctions, FileSize);
	ULONG AddressOfNameOrdinalsOffset = RvaToOffset(pnth, ExportDir->AddressOfNameOrdinals, FileSize);
	ULONG AddressOfNamesOffset = RvaToOffset(pnth, ExportDir->AddressOfNames, FileSize);
	if (AddressOfFunctionsOffset == PE_ERROR_VALUE ||
		AddressOfNameOrdinalsOffset == PE_ERROR_VALUE ||
		AddressOfNamesOffset == PE_ERROR_VALUE)
	{
		Log("[TITANHIDE] Invalid Export Directory Contents!\n");
		return PE_ERROR_VALUE;
	}
	ULONG* AddressOfFunctions = (ULONG*)(FileData + AddressOfFunctionsOffset);
	USHORT* AddressOfNameOrdinals = (USHORT*)(FileData + AddressOfNameOrdinalsOffset);
	ULONG* AddressOfNames = (ULONG*)(FileData + AddressOfNamesOffset);

	//Find Export
	ULONG ExportOffset = PE_ERROR_VALUE;
	for (ULONG i = 0; i < NumberOfNames; i++)
	{
		ULONG CurrentNameOffset = RvaToOffset(pnth, AddressOfNames[i], FileSize);
		if (CurrentNameOffset == PE_ERROR_VALUE)
			continue;
		const char* CurrentName = (const char*)(FileData + CurrentNameOffset);
		ULONG CurrentFunctionRva = AddressOfFunctions[AddressOfNameOrdinals[i]];
		if (CurrentFunctionRva >= ExportDirRva && CurrentFunctionRva < ExportDirRva + ExportDirSize)
			continue; //we ignore forwarded exports
		if (!strcmp(CurrentName, ExportName)) //compare the export name to the requested export
		{
			ExportOffset = RvaToOffset(pnth, CurrentFunctionRva, FileSize);
			break;
		}
	}

	if (ExportOffset == PE_ERROR_VALUE)
	{
		Log("[TITANHIDE] Export %s not found in export table!\n", ExportName);
	}

	return ExportOffset;
}

PVOID PE::GetPageBase(PVOID lpHeader, ULONG* Size, PVOID ptr)
{
	if ((unsigned char*)ptr < (unsigned char*)lpHeader)
		return 0;
	ULONG dwRva = (ULONG)((unsigned char*)ptr - (unsigned char*)lpHeader);
	IMAGE_DOS_HEADER* pdh = (IMAGE_DOS_HEADER*)lpHeader;
	if (pdh->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;
	IMAGE_NT_HEADERS* pnth = (IMAGE_NT_HEADERS*)((unsigned char*)lpHeader + pdh->e_lfanew);
	if (pnth->Signature != IMAGE_NT_SIGNATURE)
		return 0;
	IMAGE_SECTION_HEADER* psh = IMAGE_FIRST_SECTION(pnth);
	int section = RvaToSection(pnth, dwRva);
	if (section == -1)
		return 0;
	if (Size)
		*Size = psh[section].SizeOfRawData;
	return (PVOID)((unsigned char*)lpHeader + psh[section].VirtualAddress);
}
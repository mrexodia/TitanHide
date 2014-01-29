#include "pe.h"
#include <winnt.h>

static DWORD RvaToSection(IMAGE_NT_HEADERS* pNtHdr, DWORD dwRVA)
{
    WORD wSections;
    PIMAGE_SECTION_HEADER pSectionHdr;
    pSectionHdr=IMAGE_FIRST_SECTION(pNtHdr);
    wSections=pNtHdr->FileHeader.NumberOfSections;
    for(int i=0; i<wSections; i++)
    {
        if(pSectionHdr[i].VirtualAddress<=dwRVA)
            if((pSectionHdr[i].VirtualAddress+pSectionHdr[i].Misc.VirtualSize)>dwRVA)
            {
                return i;
            }
    }
    return -1;
}

PVOID PeGetPageBase(PVOID lpHeader, ULONG* Size, PVOID ptr)
{
    if((unsigned char*)ptr<(unsigned char*)lpHeader)
        return 0;
    ULONG dwRva=(unsigned char*)ptr-(unsigned char*)lpHeader;
    IMAGE_DOS_HEADER* pdh=(IMAGE_DOS_HEADER*)lpHeader;
    if(pdh->e_magic!=IMAGE_DOS_SIGNATURE)
        return 0;
    IMAGE_NT_HEADERS* pnth=(IMAGE_NT_HEADERS*)((unsigned char*)lpHeader+pdh->e_lfanew);
    if(pnth->Signature!=IMAGE_NT_SIGNATURE)
        return 0;
    IMAGE_SECTION_HEADER* psh=IMAGE_FIRST_SECTION(pnth);
    int section=RvaToSection(pnth, dwRva);
    if(section==-1)
        return 0;
    if(Size)
        *Size=psh[section].SizeOfRawData;
    return (PVOID)((unsigned char*)lpHeader+psh[section].VirtualAddress);
}
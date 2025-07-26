/*
 * From https://raw.githubusercontent.com/Cobalt-Strike/bof-vs/refs/heads/main/BOF-Template/beacon.h
 */

#ifndef _BEACON_H_
#define _BEACON_H_

#include <windows.h>

typedef struct {
   char* start; // The start address of the .rdata section
   DWORD length; // The length (Size of Raw Data) of the .rdata section
   DWORD offset; // The obfuscation start offset
} RDATA_SECTION, *PRDATA_SECTION;

typedef enum {
	PURPOSE_EMPTY,
	PURPOSE_GENERIC_BUFFER,
	PURPOSE_BEACON_MEMORY,
	PURPOSE_SLEEPMASK_MEMORY,
	PURPOSE_BOF_MEMORY,
	PURPOSE_USER_DEFINED_MEMORY = 1000
} ALLOCATED_MEMORY_PURPOSE;

typedef enum {
	LABEL_EMPTY,
	LABEL_BUFFER,
	LABEL_PEHEADER,
	LABEL_TEXT,
	LABEL_RDATA,
	LABEL_DATA,
	LABEL_PDATA,
	LABEL_RELOC,
	LABEL_USER_DEFINED = 1000
} ALLOCATED_MEMORY_LABEL;

typedef enum {
	METHOD_UNKNOWN,
	METHOD_VIRTUALALLOC,
	METHOD_HEAPALLOC,
	METHOD_MODULESTOMP,
	METHOD_NTMAPVIEW,
	METHOD_USER_DEFINED = 1000,
} ALLOCATED_MEMORY_ALLOCATION_METHOD;

typedef struct _HEAPALLOC_INFO {
	PVOID HeapHandle;
	BOOL  DestroyHeap;
} HEAPALLOC_INFO, *PHEAPALLOC_INFO;

typedef struct _MODULESTOMP_INFO {
	HMODULE ModuleHandle;
} MODULESTOMP_INFO, *PMODULESTOMP_INFO;

typedef union _ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION {
	HEAPALLOC_INFO HeapAllocInfo;
	MODULESTOMP_INFO ModuleStompInfo;
	PVOID Custom;
} ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION, *PALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION;

typedef struct _ALLOCATED_MEMORY_CLEANUP_INFORMATION {
	BOOL Cleanup;
	ALLOCATED_MEMORY_ALLOCATION_METHOD AllocationMethod;
	ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION AdditionalCleanupInformation;
} ALLOCATED_MEMORY_CLEANUP_INFORMATION, *PALLOCATED_MEMORY_CLEANUP_INFORMATION;

typedef struct _ALLOCATED_MEMORY_SECTION {
	ALLOCATED_MEMORY_LABEL Label; // A label to simplify Sleepmask development
	PVOID  BaseAddress;           // Pointer to virtual address of section
	SIZE_T VirtualSize;           // Virtual size of the section
	DWORD  CurrentProtect;        // Current memory protection of the section
	DWORD  PreviousProtect;       // The previous memory protection of the section (prior to masking/unmasking)
	BOOL   MaskSection;           // A boolean to indicate whether the section should be masked
} ALLOCATED_MEMORY_SECTION, *PALLOCATED_MEMORY_SECTION;

typedef struct _ALLOCATED_MEMORY_REGION {
	ALLOCATED_MEMORY_PURPOSE Purpose;      // A label to indicate the purpose of the allocated memory
	PVOID  AllocationBase;                 // The base address of the allocated memory block
	SIZE_T RegionSize;                     // The size of the allocated memory block
	DWORD Type;                            // The type of memory allocated
	ALLOCATED_MEMORY_SECTION Sections[8];  // An array of section information structures
	ALLOCATED_MEMORY_CLEANUP_INFORMATION CleanupInformation; // Information required to cleanup the allocation
} ALLOCATED_MEMORY_REGION, *PALLOCATED_MEMORY_REGION;

typedef struct {
	ALLOCATED_MEMORY_REGION AllocatedMemoryRegions[6];
} ALLOCATED_MEMORY, *PALLOCATED_MEMORY;

typedef struct
{
	PVOID fnAddr;
	PVOID jmpAddr;
	DWORD sysnum;
} SYSCALL_API_ENTRY, *PSYSCALL_API_ENTRY;

typedef struct
{
	SYSCALL_API_ENTRY ntAllocateVirtualMemory;
	SYSCALL_API_ENTRY ntProtectVirtualMemory;
	SYSCALL_API_ENTRY ntFreeVirtualMemory;
	SYSCALL_API_ENTRY ntGetContextThread;
	SYSCALL_API_ENTRY ntSetContextThread;
	SYSCALL_API_ENTRY ntResumeThread;
	SYSCALL_API_ENTRY ntCreateThreadEx;
	SYSCALL_API_ENTRY ntOpenProcess;
	SYSCALL_API_ENTRY ntOpenThread;
	SYSCALL_API_ENTRY ntClose;
	SYSCALL_API_ENTRY ntCreateSection;
	SYSCALL_API_ENTRY ntMapViewOfSection;
	SYSCALL_API_ENTRY ntUnmapViewOfSection;
	SYSCALL_API_ENTRY ntQueryVirtualMemory;
	SYSCALL_API_ENTRY ntDuplicateObject;
	SYSCALL_API_ENTRY ntReadVirtualMemory;
	SYSCALL_API_ENTRY ntWriteVirtualMemory;
	SYSCALL_API_ENTRY ntReadFile;
	SYSCALL_API_ENTRY ntWriteFile;
	SYSCALL_API_ENTRY ntCreateFile;
	SYSCALL_API_ENTRY ntQueueApcThread;
	SYSCALL_API_ENTRY ntCreateProcess;
	SYSCALL_API_ENTRY ntOpenProcessToken;
	SYSCALL_API_ENTRY ntTestAlert;
	SYSCALL_API_ENTRY ntSuspendProcess;
	SYSCALL_API_ENTRY ntResumeProcess;
	SYSCALL_API_ENTRY ntQuerySystemInformation;
	SYSCALL_API_ENTRY ntQueryDirectoryFile;
	SYSCALL_API_ENTRY ntSetInformationProcess;
	SYSCALL_API_ENTRY ntSetInformationThread;
	SYSCALL_API_ENTRY ntQueryInformationProcess;
	SYSCALL_API_ENTRY ntQueryInformationThread;
	SYSCALL_API_ENTRY ntOpenSection;
	SYSCALL_API_ENTRY ntAdjustPrivilegesToken;
	SYSCALL_API_ENTRY ntDeviceIoControlFile;
	SYSCALL_API_ENTRY ntWaitForMultipleObjects;
} SYSCALL_API, *PSYSCALL_API;

/* Additional Run Time Library (RTL) addresses used to support system calls.
 * If they are not set then system calls that require them will fall back
 * to the Standard Windows API.
 *
 * Required to support the following system calls:
 *    ntCreateFile
 */
typedef struct
{
	PVOID rtlDosPathNameToNtPathNameUWithStatusAddr;
	PVOID rtlFreeHeapAddr;
	PVOID rtlGetProcessHeapAddr;
} RTL_API, *PRTL_API;

typedef struct
{
	SYSCALL_API syscalls;
	RTL_API     rtls;
} BEACON_SYSCALLS, *PBEACON_SYSCALLS;

/* Beacon User Data
 *
 * version format: 0xMMmmPP, where MM = Major, mm = Minor, and PP = Patch
 * e.g. 0x040900 -> CS 4.9
 *      0x041000 -> CS 4.10
*/

#define COBALT_STRIKE_VERSION 0x041100
#define BOF_MEMORY_SIZE 0x10000
#define SLEEPMASK_MEMORY_SIZE 0x10000

#define DLL_BEACON_START     0x04
#define DLL_BEACON_USER_DATA 0x0d

#define BEACON_USER_DATA_CUSTOM_SIZE 32

typedef struct
{
	unsigned int version;
	PSYSCALL_API syscalls;
	char         custom[BEACON_USER_DATA_CUSTOM_SIZE];
	PRTL_API     rtls;
	PALLOCATED_MEMORY allocatedMemory;
} USER_DATA, * PUSER_DATA;

#endif // _BEACON_H_
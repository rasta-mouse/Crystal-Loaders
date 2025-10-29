#include <windows.h>

typedef struct {
    DWORD ssn;
    PVOID jmpAddr;
} SYSCALL_GATE;

BOOL GetSyscall     (PVOID ntdll, PVOID func, SYSCALL_GATE * gate);
void PrepareSyscall (DWORD ssn, PVOID addr);
void DoSyscall      ();
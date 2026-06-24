/*
 * User-mode controller for the Karnel educational memory-forensics driver.
 * Communicates by invoking NtUserUserHandleGrantAccess with a DRIVER_COMMAND
 * buffer disguised as the first HANDLE parameter.
 *
 * Build as a x64 console application and run only inside the isolated test VM.
 */

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <tlhelp32.h>

#include <cinttypes>
#include <cstdio>
#include <cstring>

#pragma warning(push)
#pragma warning(disable : 4201)

/* -------------------------------------------------------------------------- */
/* Shared command protocol (mirrored from driver.c)                           */
/* -------------------------------------------------------------------------- */

#define KARNEL_MAGIC_KEY 0xABCDEF1234567890ULL

#ifndef IoReadAccess
#define IoReadAccess 0
#endif

#ifndef IoModifyAccess
#define IoModifyAccess 1
#endif

typedef enum _KARNEL_COMMAND_TYPE {
    KarnelCommandLockMemory = 1,
    KarnelCommandUnlockMemory = 2,
    KarnelCommandReadLockedMemory = 3
} KARNEL_COMMAND_TYPE;

typedef struct _DRIVER_COMMAND {
    ULONG64 MagicKey;
    KARNEL_COMMAND_TYPE CommandType;
    HANDLE ProcessId;
    PVOID VirtualAddress;
    SIZE_T Length;
    ULONG AccessMode;
    PVOID OutBuffer;
    NTSTATUS ReturnStatus;
} DRIVER_COMMAND, *PDRIVER_COMMAND;

#pragma warning(pop)

typedef BOOL (WINAPI* PFN_NtUserUserHandleGrantAccess)(
    HANDLE hUserHandle,
    HANDLE hProcess,
    BOOL bGrantAccess);

static const char* NtStatusToString(_In_ NTSTATUS status)
{
    switch (status) {
    case 0x00000000L: return "STATUS_SUCCESS";
    case 0xC0000005L: return "STATUS_ACCESS_VIOLATION";
    case 0xC000000DL: return "STATUS_INVALID_PARAMETER";
    case 0xC0000022L: return "STATUS_ACCESS_DENIED";
    case 0xC000009AL: return "STATUS_INSUFFICIENT_RESOURCES";
    case 0xC00000BBL: return "STATUS_NOT_SUPPORTED";
    case 0xC000010AL: return "STATUS_INVALID_DEVICE_STATE";
    case 0xC0000010L: return "STATUS_INVALID_DEVICE_REQUEST";
    case 0xC0000225L: return "STATUS_NOT_FOUND";
    default: return "UNKNOWN_STATUS";
    }
}

static void PrintStatus(_In_z_ const char* label, _In_ NTSTATUS status)
{
    std::printf(
        "%s: 0x%08lX (%s)\n",
        label,
        static_cast<unsigned long>(status),
        NtStatusToString(status));
}

static BOOL InvokeDriverCommand(
    _Inout_ PDRIVER_COMMAND command,
    _In_ PFN_NtUserUserHandleGrantAccess routine
    )
{
    command->MagicKey = KARNEL_MAGIC_KEY;
    command->ReturnStatus = 0xC00000BBL; /* STATUS_NOT_SUPPORTED */

    const BOOL hookAccepted = routine(
        reinterpret_cast<HANDLE>(command),
        nullptr,
        FALSE);

    std::printf("HookAccepted: %s\n", hookAccepted ? "TRUE" : "FALSE");
    PrintStatus("ReturnStatus", command->ReturnStatus);

    return hookAccepted;
}

static BOOL IsRunningAsAdministrator()
{
    BOOL isAdmin = FALSE;
    PSID administratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (!AllocateAndInitializeSid(
            &ntAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0,
            0,
            0,
            0,
            0,
            0,
            &administratorsGroup)) {
        return FALSE;
    }

    if (!CheckTokenMembership(nullptr, administratorsGroup, &isAdmin)) {
        isAdmin = FALSE;
    }

    FreeSid(administratorsGroup);
    return isAdmin;
}

static DWORD LookupProcessIdByName(_In_ LPCWSTR processName)
{
    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        std::printf(
            "CreateToolhelp32Snapshot failed. GetLastError=0x%08lX\n",
            static_cast<unsigned long>(GetLastError()));
        return 0;
    }

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName) == 0) {
                processId = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    } else {
        std::printf(
            "Process32FirstW failed. GetLastError=0x%08lX\n",
            static_cast<unsigned long>(GetLastError()));
    }

    CloseHandle(snapshot);
    return processId;
}

static PFN_NtUserUserHandleGrantAccess ResolveNtUserUserHandleGrantAccess()
{
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32 == nullptr) {
        user32 = LoadLibraryW(L"user32.dll");
    }

    if (user32 == nullptr) {
        std::printf("Failed to load user32.dll. GetLastError=0x%08lX\n",
                    static_cast<unsigned long>(GetLastError()));
        return nullptr;
    }

    auto routine = reinterpret_cast<PFN_NtUserUserHandleGrantAccess>(
        GetProcAddress(user32, "NtUserUserHandleGrantAccess"));

    if (routine == nullptr) {
        std::printf(
            "NtUserUserHandleGrantAccess export not found. GetLastError=0x%08lX\n",
            static_cast<unsigned long>(GetLastError()));
    }

    return routine;
}

int main()
{
    if (!IsRunningAsAdministrator()) {
        std::printf("[!] Error: This application must be run as Administrator to invoke win32k system hooks natively.\n");
        return 1;
    }

    std::printf("Karnel user-mode controller (x64)\n");
    std::printf("=================================\n\n");

    const PFN_NtUserUserHandleGrantAccess routine = ResolveNtUserUserHandleGrantAccess();
    if (routine == nullptr) {
        return 1;
    }

    std::printf("Resolved NtUserUserHandleGrantAccess at %p\n\n", reinterpret_cast<void*>(routine));

    DWORD targetPid = LookupProcessIdByName(L"Overwatch.exe");
    if (targetPid == 0) {
        std::printf("[!] Warning: Overwatch.exe is not running. Falling back to current process PID for local testing.\n");
        targetPid = GetCurrentProcessId();
    } else {
        std::printf("Located Overwatch.exe with PID %lu\n", static_cast<unsigned long>(targetPid));
    }

    char sampleBuffer[] = "Karnel forensic snapshot sample payload.";
    const SIZE_T sampleLength = sizeof(sampleBuffer);

    std::printf("Sample buffer at %p (%zu bytes)\n", static_cast<void*>(sampleBuffer), sampleLength);
    std::printf("Target PID: %lu\n\n", static_cast<unsigned long>(targetPid));

    DRIVER_COMMAND lockCommand = {};
    lockCommand.CommandType = KarnelCommandLockMemory;
    lockCommand.ProcessId = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(targetPid));
    lockCommand.VirtualAddress = sampleBuffer;
    lockCommand.Length = sampleLength;
    lockCommand.AccessMode = IoReadAccess;

    std::printf("[1] LockMemory\n");
    if (!InvokeDriverCommand(&lockCommand, routine)) {
        std::printf("Driver hook did not accept the lock command.\n");
        return 1;
    }

    if (lockCommand.ReturnStatus != 0) {
        std::printf("Lock failed.\n");
        return 1;
    }

    char readback[128] = {};
    DRIVER_COMMAND readCommand = {};
    readCommand.CommandType = KarnelCommandReadLockedMemory;
    readCommand.OutBuffer = readback;
    readCommand.Length = sizeof(readback) - 1;

    std::printf("\n[2] ReadLockedMemory\n");
    if (!InvokeDriverCommand(&readCommand, routine)) {
        std::printf("Driver hook did not accept the read command.\n");
        return 1;
    }

    if (readCommand.ReturnStatus == 0) {
        readback[sizeof(readback) - 1] = '\0';
        std::printf("Readback: \"%s\"\n", readback);
    }

    DRIVER_COMMAND unlockCommand = {};
    unlockCommand.CommandType = KarnelCommandUnlockMemory;

    std::printf("\n[3] UnlockMemory\n");
    if (!InvokeDriverCommand(&unlockCommand, routine)) {
        std::printf("Driver hook did not accept the unlock command.\n");
        return 1;
    }

    std::printf("\nController run complete.\n");
    return unlockCommand.ReturnStatus == 0 ? 0 : 1;
}

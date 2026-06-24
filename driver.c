/*
 * Educational local memory-forensics kernel payload (x64).
 * Designed for manual mapping (kdmapper / similar loaders) — no DriverObject,
 * no WDF registration, and no standard device/IOCTL surface.
 *
 * Communicates via a hooked win32k routine. Test only in an isolated VM.
 */

#include <ntddk.h>
#include <ntifs.h>

#pragma warning(disable : 4201)

/* -------------------------------------------------------------------------- */
/* Shared command protocol (mirrored in user-mode main.cpp)                     */
/* -------------------------------------------------------------------------- */

#define KARNEL_MAGIC_KEY 0xABCDEF1234567890ULL

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

/* -------------------------------------------------------------------------- */
/* Payload / locked-memory state                                              */
/* -------------------------------------------------------------------------- */

typedef struct _KARNEL_LOCKED_MEMORY {
    PEPROCESS Process;
    PMDL Mdl;
    PVOID VirtualAddress;
    SIZE_T Length;
    BOOLEAN PagesLocked;
} KARNEL_LOCKED_MEMORY, *PKARNEL_LOCKED_MEMORY;

static KARNEL_LOCKED_MEMORY g_ActiveLock;
static FAST_MUTEX g_CommandMutex;
static volatile LONG g_PayloadInitialized = 0;
static PVOID g_PayloadMappingBase = NULL;
static SIZE_T g_PayloadMappingSize = 0;

/* -------------------------------------------------------------------------- */
/* Hook state                                                                 */
/* -------------------------------------------------------------------------- */

typedef BOOL (NTAPI *PFN_NtUserUserHandleGrantAccess)(
    _In_ HANDLE hUserHandle,
    _In_ HANDLE hProcess,
    _In_ BOOL bGrantAccess
    );

#define KARNEL_HOOK_PATCH_SIZE 12

static PVOID g_HookTarget = NULL;
static UCHAR g_OriginalBytes[KARNEL_HOOK_PATCH_SIZE];
static PUCHAR g_Trampoline = NULL;
static PFN_NtUserUserHandleGrantAccess g_OriginalRoutine = NULL;
static volatile LONG g_HookInstalled = 0;

/* -------------------------------------------------------------------------- */
/* CR0 write-protection override                                              */
/* -------------------------------------------------------------------------- */

#define KARNEL_CR0_WP_BIT (1ULL << 16)

static KIRQL
KarnelDisableWriteProtection(
    VOID
    )
{
    KIRQL irql;
    ULONG_PTR cr0;

    irql = KeRaiseIrqlToDpcLevel();
    cr0 = __readcr0();
    __writecr0(cr0 & ~KARNEL_CR0_WP_BIT);
    _disable();
    return irql;
}

static VOID
KarnelEnableWriteProtection(
    _In_ KIRQL Irql
    )
{
    ULONG_PTR cr0;

    cr0 = __readcr0();
    __writecr0(cr0 | KARNEL_CR0_WP_BIT);
    _enable();
    KeLowerIrql(Irql);
}

static VOID
KarnelWriteProtectedMemory(
    _Out_writes_bytes_(Length) PVOID Destination,
    _In_reads_bytes_(Length) PVOID Source,
    _In_ SIZE_T Length
    )
{
    KIRQL irql;

    irql = KarnelDisableWriteProtection();
    RtlCopyMemory(Destination, Source, Length);
    KarnelEnableWriteProtection(irql);
}

static VOID
KarnelBuildAbsoluteJump(
    _Out_writes_(KARNEL_HOOK_PATCH_SIZE) PUCHAR Buffer,
    _In_ PVOID Target
    )
{
    Buffer[0] = 0x48;
    Buffer[1] = 0xB8;
    RtlCopyMemory(&Buffer[2], &Target, sizeof(PVOID));
    Buffer[10] = 0xFF;
    Buffer[11] = 0xE0;
}

/* -------------------------------------------------------------------------- */
/* win32k export resolution (module list + PE exports only)                   */
/* -------------------------------------------------------------------------- */

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _KARNEL_MODULE_INFO {
    PVOID ImageBase;
    ULONG ImageSize;
} KARNEL_MODULE_INFO, *PKARNEL_MODULE_INFO;

static NTSTATUS
KarnelFindSystemModule(
    _In_ PCSTR ModuleName,
    _Out_ PKARNEL_MODULE_INFO ModuleInfo
    )
{
    NTSTATUS status;
    PVOID buffer = NULL;
    ULONG bufferSize = 0x10000;
    PRTL_PROCESS_MODULES modules;
    ANSI_STRING targetName;
    ANSI_STRING currentName;

    RtlZeroMemory(ModuleInfo, sizeof(*ModuleInfo));
    RtlInitAnsiString(&targetName, ModuleName);

    for (;;) {
        buffer = ExAllocatePool2(POOL_FLAG_PAGED, bufferSize, 'lekr');
        if (buffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = ZwQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &bufferSize);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            ExFreePoolWithTag(buffer, 'lekr');
            buffer = NULL;
            continue;
        }

        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(buffer, 'lekr');
            return status;
        }

        break;
    }

    modules = (PRTL_PROCESS_MODULES)buffer;

    for (ULONG i = 0; i < modules->NumberOfModules; i++) {
        RtlInitAnsiString(&currentName, (PCSZ)modules->Modules[i].FullPathName);

        if (currentName.Length >= targetName.Length &&
            _stricmp(currentName.Buffer + currentName.Length - targetName.Length, ModuleName) == 0) {
            ModuleInfo->ImageBase = modules->Modules[i].ImageBase;
            ModuleInfo->ImageSize = modules->Modules[i].ImageSize;
            ExFreePoolWithTag(buffer, 'lekr');
            return STATUS_SUCCESS;
        }
    }

    ExFreePoolWithTag(buffer, 'lekr');
    return STATUS_NOT_FOUND;
}

static PVOID
KarnelGetExportAddress(
    _In_ PVOID ImageBase,
    _In_ PCSTR ExportName
    )
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS64 ntHeaders;
    PIMAGE_EXPORT_DIRECTORY exportDirectory;
    PULONG nameTable;
    PUSHORT ordinalTable;
    PULONG functionTable;
    ULONG exportSize;
    ANSI_STRING targetName;
    ANSI_STRING currentName;

    if (ImageBase == NULL || ExportName == NULL) {
        return NULL;
    }

    dosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    ntHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)ImageBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    exportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(
        ImageBase,
        TRUE,
        IMAGE_DIRECTORY_ENTRY_EXPORT,
        &exportSize);

    if (exportDirectory == NULL) {
        return NULL;
    }

    nameTable = (PULONG)((PUCHAR)ImageBase + exportDirectory->AddressOfNames);
    ordinalTable = (PUSHORT)((PUCHAR)ImageBase + exportDirectory->AddressOfNameOrdinals);
    functionTable = (PULONG)((PUCHAR)ImageBase + exportDirectory->AddressOfFunctions);

    RtlInitAnsiString(&targetName, ExportName);

    for (ULONG i = 0; i < exportDirectory->NumberOfNames; i++) {
        RtlInitAnsiString(&currentName, (PCSZ)((PUCHAR)ImageBase + nameTable[i]));

        if (RtlCompareString(&targetName, &currentName, TRUE) != 0) {
            continue;
        }

        return (PUCHAR)ImageBase + functionTable[ordinalTable[i]];
    }

    return NULL;
}

static PVOID
KarnelResolveWin32kRoutine(
    _In_ PCSTR ExportName
    )
{
    static const PCSTR moduleCandidates[] = {
        "win32kbase.sys",
        "win32k.sys",
        "win32kfull.sys"
    };

    KARNEL_MODULE_INFO moduleInfo;
    PVOID exportAddress = NULL;

    for (ULONG i = 0; i < RTL_NUMBER_OF(moduleCandidates); i++) {
        if (!NT_SUCCESS(KarnelFindSystemModule(moduleCandidates[i], &moduleInfo))) {
            continue;
        }

        exportAddress = KarnelGetExportAddress(moduleInfo.ImageBase, ExportName);
        if (exportAddress != NULL) {
            return exportAddress;
        }
    }

    return NULL;
}

/* -------------------------------------------------------------------------- */
/* Memory helpers (core snapshot routines — unchanged behavior)               */
/* -------------------------------------------------------------------------- */

NTSTATUS
KarnelLockProcessMemory(
    _In_ HANDLE ProcessId,
    _In_ PVOID VirtualAddress,
    _In_ SIZE_T Length,
    _Out_ PKARNEL_LOCKED_MEMORY LockedMemory,
    _In_ LOCK_OPERATION AccessMode
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PMDL mdl = NULL;
    KAPC_STATE apcState;

    RtlZeroMemory(LockedMemory, sizeof(*LockedMemory));

    if (VirtualAddress == NULL || Length == 0 || Length > MAXULONG) {
        return STATUS_INVALID_PARAMETER;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    mdl = IoAllocateMdl(VirtualAddress, (ULONG)Length, FALSE, FALSE, NULL);
    if (mdl == NULL) {
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeStackAttachProcess(process, &apcState);

    __try {
        MmProbeAndLockPages(mdl, UserMode, AccessMode);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        KeUnstackDetachProcess(&apcState);
        IoFreeMdl(mdl);
        ObDereferenceObject(process);
        return status;
    }

    KeUnstackDetachProcess(&apcState);

    LockedMemory->Process = process;
    LockedMemory->Mdl = mdl;
    LockedMemory->VirtualAddress = VirtualAddress;
    LockedMemory->Length = Length;
    LockedMemory->PagesLocked = TRUE;

    return STATUS_SUCCESS;
}

VOID
KarnelUnlockProcessMemory(
    _Inout_ PKARNEL_LOCKED_MEMORY LockedMemory
    )
{
    if (LockedMemory == NULL) {
        return;
    }

    if (LockedMemory->PagesLocked && LockedMemory->Mdl != NULL) {
        MmUnlockPages(LockedMemory->Mdl);
        LockedMemory->PagesLocked = FALSE;
    }

    if (LockedMemory->Mdl != NULL) {
        IoFreeMdl(LockedMemory->Mdl);
        LockedMemory->Mdl = NULL;
    }

    if (LockedMemory->Process != NULL) {
        ObDereferenceObject(LockedMemory->Process);
        LockedMemory->Process = NULL;
    }

    LockedMemory->VirtualAddress = NULL;
    LockedMemory->Length = 0;
}

PVOID
KarnelGetLockedSystemAddress(
    _In_ PKARNEL_LOCKED_MEMORY LockedMemory
    )
{
    if (LockedMemory == NULL ||
        !LockedMemory->PagesLocked ||
        LockedMemory->Mdl == NULL) {
        return NULL;
    }

    return MmGetSystemAddressForMdlSafe(LockedMemory->Mdl, NormalPagePriority);
}

/* -------------------------------------------------------------------------- */
/* Command dispatch                                                           */
/* -------------------------------------------------------------------------- */

static NTSTATUS
KarnelDispatchCommand(
    _Inout_ PDRIVER_COMMAND Command
    )
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PVOID systemAddress = NULL;
    SIZE_T copyLength = 0;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    ExAcquireFastMutex(&g_CommandMutex);

    __try {
        switch (Command->CommandType) {
        case KarnelCommandLockMemory:
            KarnelUnlockProcessMemory(&g_ActiveLock);
            status = KarnelLockProcessMemory(
                Command->ProcessId,
                Command->VirtualAddress,
                Command->Length,
                &g_ActiveLock,
                (LOCK_OPERATION)Command->AccessMode);
            break;

        case KarnelCommandUnlockMemory:
            KarnelUnlockProcessMemory(&g_ActiveLock);
            status = STATUS_SUCCESS;
            break;

        case KarnelCommandReadLockedMemory:
            if (!g_ActiveLock.PagesLocked) {
                status = STATUS_INVALID_DEVICE_STATE;
                break;
            }

            if (Command->OutBuffer == NULL || Command->Length == 0) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            systemAddress = KarnelGetLockedSystemAddress(&g_ActiveLock);
            if (systemAddress == NULL) {
                status = STATUS_UNSUCCESSFUL;
                break;
            }

            copyLength = min(Command->Length, g_ActiveLock.Length);
            ProbeForWrite(Command->OutBuffer, copyLength, sizeof(UCHAR));
            RtlCopyMemory(Command->OutBuffer, systemAddress, copyLength);
            status = STATUS_SUCCESS;
            break;

        default:
            status = STATUS_INVALID_PARAMETER;
            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    ExReleaseFastMutex(&g_CommandMutex);
    return status;
}

/* -------------------------------------------------------------------------- */
/* Hook intercept                                                             */
/* -------------------------------------------------------------------------- */

BOOL
NTAPI
HookedNtUserUserHandleGrantAccess(
    _In_ HANDLE hUserHandle,
    _In_ HANDLE hProcess,
    _In_ BOOL bGrantAccess
    )
{
    PDRIVER_COMMAND command = NULL;
    DRIVER_COMMAND localCommand;
    BOOL originalResult = FALSE;

    UNREFERENCED_PARAMETER(hProcess);
    UNREFERENCED_PARAMETER(bGrantAccess);

    if (InterlockedCompareExchange(&g_PayloadInitialized, 1, 1) != 1) {
        goto ForwardToOriginal;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        goto ForwardToOriginal;
    }

    if (hUserHandle == NULL) {
        goto ForwardToOriginal;
    }

    __try {
        command = (PDRIVER_COMMAND)hUserHandle;
        ProbeForRead(command, sizeof(DRIVER_COMMAND), TYPE_ALIGNMENT(ULONG64));

        if (command->MagicKey != KARNEL_MAGIC_KEY) {
            goto ForwardToOriginal;
        }

        RtlCopyMemory(&localCommand, command, sizeof(localCommand));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        goto ForwardToOriginal;
    }

    localCommand.ReturnStatus = KarnelDispatchCommand(&localCommand);

    __try {
        ProbeForWrite(
            &((PDRIVER_COMMAND)hUserHandle)->ReturnStatus,
            sizeof(NTSTATUS),
            TYPE_ALIGNMENT(NTSTATUS));
        ((PDRIVER_COMMAND)hUserHandle)->ReturnStatus = localCommand.ReturnStatus;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        goto ForwardToOriginal;
    }

    return TRUE;

ForwardToOriginal:
    if (g_OriginalRoutine != NULL) {
        originalResult = g_OriginalRoutine(hUserHandle, hProcess, bGrantAccess);
    }

    return originalResult;
}

/* -------------------------------------------------------------------------- */
/* Hook install / remove (no DriverObject or registry dependencies)           */
/* -------------------------------------------------------------------------- */

static VOID
KarnelFreeTrampoline(
    VOID
    )
{
    if (g_Trampoline != NULL) {
        ExFreePoolWithTag(g_Trampoline, 'pmrT');
        g_Trampoline = NULL;
    }

    g_OriginalRoutine = NULL;
}

static NTSTATUS
KarnelInstallHook(
    VOID
    )
{
    UCHAR jumpPatch[KARNEL_HOOK_PATCH_SIZE];
    SIZE_T trampolineSize;

    if (InterlockedCompareExchange(&g_HookInstalled, 0, 0) != 0) {
        return STATUS_ALREADY_REGISTERED;
    }

    g_HookTarget = KarnelResolveWin32kRoutine("NtUserUserHandleGrantAccess");
    if (g_HookTarget == NULL) {
        return STATUS_NOT_FOUND;
    }

    RtlCopyMemory(g_OriginalBytes, g_HookTarget, sizeof(g_OriginalBytes));

    trampolineSize = sizeof(g_OriginalBytes) + KARNEL_HOOK_PATCH_SIZE;
    g_Trampoline = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, trampolineSize, 'pmrT');
    if (g_Trampoline == NULL) {
        g_HookTarget = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_Trampoline, trampolineSize);
    RtlCopyMemory(g_Trampoline, g_OriginalBytes, sizeof(g_OriginalBytes));
    KarnelBuildAbsoluteJump(
        g_Trampoline + sizeof(g_OriginalBytes),
        (PUCHAR)g_HookTarget + sizeof(g_OriginalBytes));

    g_OriginalRoutine = (PFN_NtUserUserHandleGrantAccess)(PVOID)g_Trampoline;

    KarnelBuildAbsoluteJump(jumpPatch, HookedNtUserUserHandleGrantAccess);
    KarnelWriteProtectedMemory(g_HookTarget, jumpPatch, sizeof(jumpPatch));

    InterlockedExchange(&g_HookInstalled, 1);
    return STATUS_SUCCESS;
}

static VOID
KarnelRemoveHook(
    VOID
    )
{
    if (InterlockedCompareExchange(&g_HookInstalled, 1, 1) != 1) {
        return;
    }

    if (g_HookTarget != NULL) {
        KarnelWriteProtectedMemory(g_HookTarget, g_OriginalBytes, sizeof(g_OriginalBytes));
        g_HookTarget = NULL;
    }

    InterlockedExchange(&g_HookInstalled, 0);
    KarnelFreeTrampoline();
}

/* -------------------------------------------------------------------------- */
/* Manual-map entry point (no DriverObject, no WDF, no DriverUnload)          */
/* -------------------------------------------------------------------------- */

NTSTATUS
CustomDriverlessEntry(
    _In_ PVOID PhysicalMappingBase,
    _In_ PVOID MappingSize
    )
{
    NTSTATUS status;
    SIZE_T mappingSize;

    if (PhysicalMappingBase == NULL || MappingSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    mappingSize = (SIZE_T)(ULONG_PTR)MappingSize;
    if (mappingSize == 0 || mappingSize > MAXULONG_PTR) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&g_PayloadInitialized, 1, 0) != 0) {
        return STATUS_ALREADY_REGISTERED;
    }

    g_PayloadMappingBase = PhysicalMappingBase;
    g_PayloadMappingSize = mappingSize;

    RtlZeroMemory(&g_ActiveLock, sizeof(g_ActiveLock));
    ExInitializeFastMutex(&g_CommandMutex);

    status = KarnelInstallHook();
    if (!NT_SUCCESS(status)) {
        KarnelRemoveHook();
        KarnelUnlockProcessMemory(&g_ActiveLock);
        g_PayloadMappingBase = NULL;
        g_PayloadMappingSize = 0;
        InterlockedExchange(&g_PayloadInitialized, 0);
        return status;
    }

    return STATUS_SUCCESS;
}

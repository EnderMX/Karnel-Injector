# Karnel — Kernel-Backed Memory Diagnostics (Educational PoC)

> **Status:** Experimental Proof-of-Concept · x64 · Windows 10/11  
> **Scope:** Isolated virtual-machine research only  
> **Components:** `driver.c` (driverless Ring 0 payload) · `main.cpp` (Ring 3 controller)

---

## 1. Academic Project Overview & Asymmetry

### Formal Introduction

**Karnel** is an educational, kernel-backed memory diagnostics utility designed to demonstrate how low-level forensic operators can capture stable, read-only snapshots of user-mode virtual memory without routing control traffic through conventional driver I/O surfaces.

The project is split into two decoupled artifacts:

| Artifact | Privilege | Role |
|----------|-----------|------|
| `driver.c` | Ring 0 | Driverless payload: MDL lock, win32k hook, command dispatch |
| `main.cpp` | Ring 3 | Elevated controller: PID resolution, protocol packing, hook invocation |

Together they form a **closed diagnostic loop**: the user-mode controller packs forensic parameters into a shared validation block, invokes a hooked GUI subsystem routine, and the payload — operating entirely outside the target process — resolves `EPROCESS`, attaches briefly, and pins the requested virtual range with an MDL.

This is not a general-purpose injector, cheat framework, or production forensic suite. It is a deliberately narrow teaching artifact for studying **privilege asymmetry**, **alternative kernel communication design**, and **telemetry-aware architectural trade-offs**.

---

### Privilege Asymmetry (Ring 0 vs. Ring 3)

Modern user-mode processes operate under strict visibility constraints:

- They cannot directly inspect another process's committed virtual pages without `OpenProcess` + appropriate access rights.
- Anti-tamper and EDR stacks instrument those cross-process APIs aggressively.
- Even with access, user-mode reads race against page churn, remapping, and intentional obfuscation.

A **driverless Ring 0 payload** inverts that relationship.

```
  Ring 3 (Target Process)                Ring 0 (Karnel Payload)
  ┌─────────────────────────┐            ┌─────────────────────────┐
  │ User VA space           │            │ No DriverObject         │
  │ Threads, heaps, modules │  ◄─ MDL ── │ PsLookupProcessByProcessId
  │ Completely unaware of   │   lock     │ KeStackAttachProcess    │
  │ kernel-side observation │            │ MmProbeAndLockPages     │
  └─────────────────────────┘            └─────────────────────────┘
         ▲                                           │
         │         Out of sight line                 │
         └───────────────────────────────────────────┘
              Target never receives a handle,
              thread injection, or usermode API call
              originating from the analyzer itself.
```

**Privilege asymmetry** here means:

1. **Context resolution happens in kernel space** — `PsLookupProcessByProcessId` locates `EPROCESS` without the target participating in a handshake.
2. **Memory is pinned, not copied through a device** — `IoAllocateMdl` + `MmProbeAndLockPages` produce a forensic-stable mapping the target cannot "see" as a normal I/O operation against itself.
3. **Control plane traffic never touches `\Device\` objects** — the target's usermode code path has no named driver surface to enumerate, filter, or correlate.

The target process continues executing in Ring 3 while analysis occurs from a context it was never designed to observe.

---

### Hook Mechanics — Syscall Trampoline on `NtUserUserHandleGrantAccess`

Standard WDM/KMDF drivers expose predictable telemetry:

```
IoCreateDevice  →  \Device\Karnel
IoCreateSymbolicLink  →  \DosDevices\Karnel
IRP_MJ_DEVICE_CONTROL  →  IOCTL forensic opcodes
```

Karnel **eliminates all three**.

#### Communication path

```
main.cpp
  │
  ├─ Resolve user32!NtUserUserHandleGrantAccess
  ├─ Populate DRIVER_COMMAND { MagicKey, PID, VA, Length, ... }
  └─ Call routine( (HANDLE)&command, NULL, FALSE )
           │
           ▼
win32k!NtUserUserHandleGrantAccess  (patched entry)
           │
           ├─ MagicKey == KARNEL_MAGIC_KEY (0xABCDEF1234567890)
           │       └─► HookedNtUserUserHandleGrantAccess
           │               └─► KarnelDispatchCommand → MDL routines
           │
           └─ No match
                   └─► Executable trampoline → original bytes
```

#### Patch model

| Stage | Mechanism |
|-------|-----------|
| Target resolution | `ZwQuerySystemInformation(SystemModuleInformation)` + PE export walk of `win32kbase.sys` / `win32k.sys` / `win32kfull.sys` |
| Trampoline | `ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE)` — original prologue bytes + absolute `mov rax; jmp rax` continuation |
| Hook install | CR0 WP bit cleared via `__readcr0()` / `__writecr0()`, 12-byte patch written, WP restored |
| Validation | First parameter probed as user memory; `KARNEL_MAGIC_KEY` gates command absorption |
| Fallback | Non-matching calls transparently forward through the trampoline — GUI subsystem behavior preserved |

Commands are tunneled through **registers and usermode-visible GUI syscall semantics**, not through logged IRP major functions or static IOCTL dispatch tables.

---

## 2. Deconstructing the Cybryk Audit (Why Standard Injectors Fail)

### Architectural Defense: Deconstructing Public Telemetry Vulnerabilities

Public injector repositories are valuable research artifacts — and equally valuable **audit targets**. Issue **#3** in [`cybryk/kernelmodeinjector`](https://github.com/cybryk/kernelmodeinjector/issues/3), authored by **@kryptik-commits**, documents structural weaknesses common to textbook kernel injector designs: predictable I/O surfaces, test-signing fingerprints, and control-flow integrity violations during injection.

Karnel's architecture is an explicit pivot away from those audited vectors.

---

#### Audit Finding → Karnel Mitigation Matrix

| Audited Vector (per @kryptik-commits, Issue #3) | Observable Telemetry | Karnel Mitigation |
|-------------------------------------------------|----------------------|-------------------|
| **IOCTL communication sequences** | Predictable control codes, fixed input/output buffer layouts, dispatch-table fingerprints | **Total elimination of IOCTL.** No `IoCreateDevice`, no symbolic link, no `IRP_MJ_DEVICE_CONTROL`. Commands ride the `NtUserUserHandleGrantAccess` hook behind `KARNEL_MAGIC_KEY`. |
| **Named device objects** | `\Device\ModernInjector`-class paths trivially enumerable by kernel and usermode scanners | **No device namespace registration.** Payload is manually mapped — no `\Device\` object, no `DriverSection` linkage in the conventional service-load path. |
| **Test-signing requirement** | `bcdedit /set testsigning on` is a high-confidence enterprise / anti-cheat flag | **Driverless manual-map entry.** `CustomDriverlessEntry(PVOID PhysicalMappingBase, PVOID MappingSize)` — no `PDRIVER_OBJECT`, no `RegistryPath`, no KMDF container. Compatible with BYOVD-style loaders on retail builds with testsigning **off**. |
| **Thread hijacking (RIP overwrite)** | Breaks CFG / CET expectations; anomalous return addresses during stack walks | **Threadless routing.** No remote thread creation, no context structure surgery. Interception occurs at a shared win32k stub via a non-paged executable trampoline page. |
| **Standard `DriverEntry` coupling** | Null `DriverObject` dereference → `PAGE_FAULT_IN_NONPAGED_AREA` under manual mappers | **Custom entry signature** with one-time init guard (`g_PayloadInitialized`) and fast-mutex serialization (`g_CommandMutex`). |

---

#### IOCTL vs. Magic-Key Tunnel (Side-by-Side)

**Traditional pattern (audited):**

```c
// Telemetry-rich: device object + IOCTL opcode + METHOD_BUFFERED struct
DeviceIoControl(hDevice, IOCTL_INJECT_PROCESS, &Input, sizeof(Input), ...);
```

**Karnel pattern (mitigated):**

```c
DRIVER_COMMAND cmd = {};
cmd.MagicKey   = KARNEL_MAGIC_KEY;          // 0xABCDEF1234567890ULL
cmd.CommandType = KarnelCommandLockMemory;
cmd.ProcessId  = (HANDLE)(ULONG_PTR)targetPid;
cmd.VirtualAddress = targetVa;
cmd.Length     = regionSize;
cmd.AccessMode = IoReadAccess;

NtUserUserHandleGrantAccess((HANDLE)&cmd, NULL, FALSE);
// ReturnStatus populated in-place by Ring 0 dispatch
```

The control plane resembles an ordinary GUI subsystem call. The forensic semantics live entirely inside a probed, magic-gated structure — not a registered IOCTL table.

---

#### Manual Map vs. Service-Load Driver

**Removed (BSOD-prone under mappers):**

```c
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
DriverObject->DriverUnload = ...;
WdfDriverCreate(...);
```

**Present (mapper-safe):**

```c
NTSTATUS CustomDriverlessEntry(
    _In_ PVOID PhysicalMappingBase,
    _In_ PVOID MappingSize
);
```

Stripping `PDRIVER_OBJECT` and KMDF registration removes the null-pointer dereference class that manual mappers trigger when they copy raw `.sys` bytes without constructing a valid driver object frame.

---

## 3. Dual-Component Implementation Blueprint

### Component A — Driverless Payload (`driver.c`)

**Entry & lifecycle**

| Symbol | Purpose |
|--------|---------|
| `CustomDriverlessEntry` | One-shot init: records mapping base/size, initializes mutex, installs hook |
| `g_PayloadInitialized` | `InterlockedCompareExchange` guard against double initialization |
| `KarnelRemoveHook` | Internal restore path on init failure (no OS `DriverUnload`) |

**Memory forensics core (unchanged semantics)**

| Function | Behavior |
|----------|----------|
| `KarnelLockProcessMemory` | `PsLookupProcessByProcessId` → `KeStackAttachProcess` → `IoAllocateMdl` → `MmProbeAndLockPages` inside `__try` / `__except` |
| `KarnelUnlockProcessMemory` | `MmUnlockPages` → `IoFreeMdl` → `ObDereferenceObject` |
| `KarnelGetLockedSystemAddress` | `MmGetSystemAddressForMdlSafe` for kernel-readable snapshot |
| `KarnelDispatchCommand` | Serializes lock / read / unlock via `g_CommandMutex` at `PASSIVE_LEVEL` |

**Hook infrastructure**

```c
// CR0 write-protection override (hook patch window)
irql = KeRaiseIrqlToDpcLevel();
cr0  = __readcr0();
__writecr0(cr0 & ~KARNEL_CR0_WP_BIT);   // Clear WP bit
// ... write 12-byte absolute jump ...
__writecr0(cr0 | KARNEL_CR0_WP_BIT);    // Restore WP bit
KeLowerIrql(irql);

// Executable trampoline (non-paged, RX pool)
g_Trampoline = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, trampolineSize, 'pmrT');
```

**Shared protocol (`DRIVER_COMMAND`)**

```c
typedef struct _DRIVER_COMMAND {
    ULONG64 MagicKey;           // KARNEL_MAGIC_KEY
    KARNEL_COMMAND_TYPE CommandType;
    HANDLE ProcessId;
    PVOID VirtualAddress;
    SIZE_T Length;
    ULONG AccessMode;           // IoReadAccess | IoModifyAccess
    PVOID OutBuffer;
    NTSTATUS ReturnStatus;
} DRIVER_COMMAND;
```

**Supported commands**

| `CommandType` | Action |
|---------------|--------|
| `KarnelCommandLockMemory` (1) | MDL-pin target VA range |
| `KarnelCommandReadLockedMemory` (2) | Copy locked pages → `OutBuffer` |
| `KarnelCommandUnlockMemory` (3) | Release active MDL lock |

---

### Component B — User-Mode Controller (`main.cpp`)

**Security gate**

```cpp
if (!IsRunningAsAdministrator()) {
    // [!] Error: This application must be run as Administrator
    //     to invoke win32k system hooks natively.
    return 1;
}
```

Implemented via `AllocateAndInitializeSid` + `CheckTokenMembership` against the built-in Administrators group.

**Dynamic process resolution**

```cpp
DWORD targetPid = LookupProcessIdByName(L"Overwatch.exe");
// CreateToolhelp32Snapshot → Process32FirstW / Process32NextW
// Case-insensitive match via _wcsicmp
```

| Condition | Behavior |
|-----------|----------|
| `Overwatch.exe` running | PID printed; used in `lockCommand.ProcessId` |
| Process absent | Warning emitted; falls back to `GetCurrentProcessId()` for local self-tests |

> **Integration note:** When targeting an external process, `VirtualAddress` must belong to **that** process's address space. The bundled sample buffer lives in the controller's own VA range — valid only when the fallback PID is used or when you supply a target-resident address.

**Invocation (protocol intact)**

```cpp
static BOOL InvokeDriverCommand(PDRIVER_COMMAND command, PFN_NtUserUserHandleGrantAccess routine)
{
    command->MagicKey = KARNEL_MAGIC_KEY;
    command->ReturnStatus = STATUS_NOT_SUPPORTED;
    return routine(reinterpret_cast<HANDLE>(command), nullptr, FALSE);
}
```

---

### End-to-End Test Sequence

```
[Admin elevation check]
        ↓
[Resolve user32!NtUserUserHandleGrantAccess]
        ↓
[Lookup Overwatch.exe PID — or fallback]
        ↓
[1] KarnelCommandLockMemory   → MDL pin
[2] KarnelCommandReadLockedMemory → snapshot copy
[3] KarnelCommandUnlockMemory → release
        ↓
[Print ReturnStatus / HookAccepted per stage]
```

---

### Build Reference

**Payload (`driver.c`)**

- WDK x64 kernel mode build
- Link as raw `.sys` suitable for manual mapping
- Entry point: `CustomDriverlessEntry` (configure mapper / linker accordingly)
- No KMDF, no INF service registration required for lab mapping

**Controller (`main.cpp`)**

```text
cl /EHsc /W4 /std:c++17 main.cpp user32.lib advapi32.lib
```

Run elevated inside the same interactive session as the mapped payload (win32k must be loaded).

---

## 4. Credits & References

### Open-Source Research Foundations

| Project / Community | Contribution Acknowledged |
|---------------------|---------------------------|
| [**kdmapper**](https://github.com/TheCzarGaming/kdmapper) (TheCzarGaming / z175 / SecHex lineage) | Established BYOVD manual-mapping primitives — copying unsigned payload bytes into kernel VA space using a signed, loadable helper driver as the staging primitive. |
| [**cybryk/kernelmodeinjector**](https://github.com/cybryk/kernelmodeinjector) · Issue [#3](https://github.com/cybryk/kernelmodeinjector/issues/3) by **@kryptik-commits** | Public telemetry audit that directly informed Karnel's pivot away from IOCTL surfaces, test-signing dependency, and thread-hijack injection models. |
| **UnknownCheats Research Community** (Satascha, Cat Injector lineage) | Foundational work on driverless kernel execution states and non-standard Ring 0 ↔ Ring 3 communication channels outside conventional `DeviceIoControl` paths. |

### Internal References

| File | Description |
|------|-------------|
| `driver.c` | Driverless payload, hook install, MDL forensics routines |
| `main.cpp` | Elevated controller, PID lookup, protocol packing |
| `README.md` | Architectural documentation (this file) |

---

## 5. Lab Isolation & System Stability Warning

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                         ⚠  ACADEMIC DISCLAIMER  ⚠                           ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Karnel is an EXPERIMENTAL PROOF-OF-CONCEPT for isolated virtual-machine    ║
║  research and low-level systems education ONLY.                               ║
║                                                                              ║
║  RISK SURFACE:                                                               ║
║  • Absolute hook patches against win32k export prologues                     ║
║  • CR0 write-protection manipulation during live kernel execution            ║
║  • Manual mapping without DriverObject lifecycle management                  ║
║  • Potential PatchGuard / KPP conflicts on non-lab Windows builds            ║
║                                                                              ║
║  CONSEQUENCES:                                                               ║
║  • BUGCHECK (BSOD) — PAGE_FAULT_IN_NONPAGED_AREA, IRQL_NOT_LESS_OR_EQUAL,   ║
║    SYSTEM_SERVICE_EXCEPTION, memory corruption class faults                  ║
║  • Unrecoverable win32k subsystem instability until reboot                   ║
║  • Undefined behavior if payload is mapped twice or torn down uncleanly      ║
║                                                                              ║
║  DO NOT:                                                                     ║
║  • Deploy on production systems, corporate endpoints, or live game clients   ║
║  • Use against third-party software you do not own or lack authorization     ║
║    to analyze                                                                  ║
║  • Treat this repository as a bypass, cheat, or EDR-evasion product          ║
║                                                                              ║
║  DO:                                                                         ║
║  • Use hardware-isolated VMs with snapshots                                  ║
║  • Capture crash dumps (WinDbg) for post-mortem study                        ║
║  • Revert VM state after every hook experiment                               ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

**Operator expectation:** If the hook patch size does not align with the target export prologue, if win32k module layout differs across builds, or if the payload is initialized concurrently from multiple threads without respecting the fast mutex, **system crash is the expected failure mode** — not a graceful error dialog.

This utility exists to teach how kernel-backed diagnostics *can* be structured — and why every structural choice carries instability and policy weight.

---

*Karnel · Educational Memory Diagnostics PoC · Ring 0 / Ring 3 Asymmetry Study*

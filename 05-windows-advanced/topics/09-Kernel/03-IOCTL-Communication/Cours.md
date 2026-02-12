# Module W73 : Communication IOCTL

## Objectifs

A la fin de ce module, vous serez capable de :
- Comprendre le mecanisme IOCTL (Input/Output Control)
- Implementer des handlers IOCTL dans un driver
- Communiquer entre user-mode et kernel-mode
- Definir des codes IOCTL personnalises
- Gerer les buffers d'entree/sortie de maniere securisee

## Prerequis

Avant de commencer ce module, assurez-vous de maitriser :
- Module W71 (Driver Basics)
- Module W72 (Kernel Memory)
- Concepts de communication inter-processus
- Structures IRP (I/O Request Packets)

## 1. Introduction aux IOCTL

### 1.1 Qu'est-ce qu'un IOCTL?

IOCTL = I/O Control = Canal de communication entre user-mode et kernel-mode.
Imaginez un IOCTL comme un "telephone" entre votre application et le driver.

```
COMMUNICATION FLOW:

User-Mode Application                  Kernel-Mode Driver
┌──────────────────┐                  ┌──────────────────┐
│                  │                  │                  │
│  DeviceIoControl ├─────────────────>│  IRP_MJ_DEVICE_  │
│     (IOCTL)      │    IRP Packet    │     CONTROL      │
│                  │                  │                  │
│  Input Buffer ───┼──────────────────┼──> Read Data     │
│                  │                  │                  │
│  Output Buffer <─┼──────────────────┼─── Write Data    │
│                  │                  │                  │
└──────────────────┘                  └──────────────────┘

Key Points:
- IOCTL Code : Identifie la commande
- Input Buffer : Donnees envoyees au driver
- Output Buffer : Donnees retournees par le driver
- IRP : Paquet contenant toute l'information
```

### 1.2 Structure d'un Code IOCTL

```c
// Format d'un code IOCTL (32 bits)
//
// 31  30 29  28 27    16 15    14 13      2 1     0
// ┌────┬─────┬──────────┬─────────┬────────┬───────┐
// │Comm│Custo│  Device  │ Functi  │ Method │Access │
// │on  │ m   │   Type   │   on    │        │       │
// └────┴─────┴──────────┴─────────┴────────┴───────┘
//
// Common : 0 = Kernel-defined, 1 = User-defined
// Custom : Toujours 0
// DeviceType : Type de device (FILE_DEVICE_UNKNOWN = 0x22)
// Function : Numero de fonction (0x800-0xFFF pour custom)
// Method : Methode de buffering
// Access : Permissions requises

// Macro pour creer un IOCTL
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))

// Device Types (examples)
#define FILE_DEVICE_UNKNOWN      0x00000022

// Methods de buffering
#define METHOD_BUFFERED          0   // Buffered I/O
#define METHOD_IN_DIRECT         1   // Direct I/O (input)
#define METHOD_OUT_DIRECT        2   // Direct I/O (output)
#define METHOD_NEITHER           3   // Neither (dangerous)

// Access Rights
#define FILE_ANY_ACCESS          0
#define FILE_READ_ACCESS         1
#define FILE_WRITE_ACCESS        2
```

### 1.3 Definition d'IOCTL Personnalises

```c
// Exemple : Driver de communication simple

// Base pour nos IOCTL (0x800 = custom range)
#define IOCTL_BASE 0x800

// Definir nos IOCTL codes
#define IOCTL_HELLO \
    CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GET_VERSION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 1, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_SEND_DATA \
    CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 2, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_READ_PROCESS_MEMORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Verification des valeurs
// IOCTL_HELLO = 0x00222000
// IOCTL_GET_VERSION = 0x00226004
// etc.
```

## 2. Implementation Cote Driver

### 2.1 Handler IRP_MJ_DEVICE_CONTROL

```c
#include <ntddk.h>

// Structures pour communication
typedef struct _VERSION_INFO {
    ULONG Major;
    ULONG Minor;
    ULONG Build;
} VERSION_INFO, *PVERSION_INFO;

typedef struct _READ_MEMORY_REQUEST {
    ULONG ProcessId;
    PVOID Address;
    SIZE_T Size;
} READ_MEMORY_REQUEST, *PREAD_MEMORY_REQUEST;

// Dispatch routine pour IOCTL
NTSTATUS DispatchDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
) {
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp = NULL;
    ULONG ioControlCode = 0;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    ULONG inputBufferLength = 0;
    ULONG outputBufferLength = 0;
    ULONG bytesReturned = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    // Obtenir la stack location (contient les parametres)
    irpSp = IoGetCurrentIrpStackLocation(Irp);

    // Extraire les informations
    ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    // Pour METHOD_BUFFERED, input et output utilisent le meme buffer
    inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    outputBuffer = Irp->AssociatedIrp.SystemBuffer;

    DbgPrint("[*] IOCTL received: 0x%08X\n", ioControlCode);
    DbgPrint("    Input Length: %u, Output Length: %u\n",
             inputBufferLength, outputBufferLength);

    // Router vers le bon handler
    switch (ioControlCode) {
        case IOCTL_HELLO:
            status = HandleHello(outputBuffer, outputBufferLength, &bytesReturned);
            break;

        case IOCTL_GET_VERSION:
            status = HandleGetVersion(outputBuffer, outputBufferLength, &bytesReturned);
            break;

        case IOCTL_SEND_DATA:
            status = HandleSendData(inputBuffer, inputBufferLength);
            break;

        case IOCTL_READ_PROCESS_MEMORY:
            status = HandleReadProcessMemory(
                inputBuffer, inputBufferLength,
                outputBuffer, outputBufferLength,
                &bytesReturned
            );
            break;

        default:
            DbgPrint("[!] Unknown IOCTL: 0x%08X\n", ioControlCode);
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    // Completer l'IRP
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}
```

### 2.2 Implementation des Handlers

```c
// Handler simple : retourner un message
NTSTATUS HandleHello(
    PVOID OutputBuffer,
    ULONG OutputBufferLength,
    PULONG BytesReturned
) {
    const char* message = "Hello from Kernel!";
    SIZE_T messageLength = strlen(message) + 1;

    if (OutputBufferLength < messageLength) {
        DbgPrint("[!] Output buffer too small\n");
        *BytesReturned = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(OutputBuffer, message, messageLength);
    *BytesReturned = (ULONG)messageLength;

    DbgPrint("[+] IOCTL_HELLO handled\n");
    return STATUS_SUCCESS;
}

// Handler : retourner version du driver
NTSTATUS HandleGetVersion(
    PVOID OutputBuffer,
    ULONG OutputBufferLength,
    PULONG BytesReturned
) {
    PVERSION_INFO versionInfo = NULL;

    if (OutputBufferLength < sizeof(VERSION_INFO)) {
        *BytesReturned = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    versionInfo = (PVERSION_INFO)OutputBuffer;
    versionInfo->Major = 1;
    versionInfo->Minor = 0;
    versionInfo->Build = 100;

    *BytesReturned = sizeof(VERSION_INFO);

    DbgPrint("[+] Version: %u.%u.%u\n",
             versionInfo->Major, versionInfo->Minor, versionInfo->Build);

    return STATUS_SUCCESS;
}

// Handler : recevoir des donnees
NTSTATUS HandleSendData(
    PVOID InputBuffer,
    ULONG InputBufferLength
) {
    if (InputBuffer == NULL || InputBufferLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrint("[*] Received %u bytes:\n", InputBufferLength);

    // Afficher les premiers bytes (dump hexadecimal)
    PUCHAR data = (PUCHAR)InputBuffer;
    for (ULONG i = 0; i < min(InputBufferLength, 64); i++) {
        DbgPrint("%02X ", data[i]);
        if ((i + 1) % 16 == 0) DbgPrint("\n");
    }
    DbgPrint("\n");

    return STATUS_SUCCESS;
}

// Handler complexe : lire memoire processus
NTSTATUS HandleReadProcessMemory(
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength,
    PULONG BytesReturned
) {
    NTSTATUS status = STATUS_SUCCESS;
    PREAD_MEMORY_REQUEST request = NULL;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;

    *BytesReturned = 0;

    // Valider input
    if (InputBufferLength < sizeof(READ_MEMORY_REQUEST)) {
        return STATUS_INVALID_PARAMETER;
    }

    request = (PREAD_MEMORY_REQUEST)InputBuffer;

    // Valider output
    if (OutputBufferLength < request->Size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    DbgPrint("[*] Reading PID %u, Address %p, Size %llu\n",
             request->ProcessId, request->Address, request->Size);

    // Obtenir EPROCESS
    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->ProcessId,
        &process
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[!] Process not found: 0x%X\n", status);
        return status;
    }

    __try {
        // Attacher au processus
        KeStackAttachProcess(process, &apcState);

        // Prober et lire
        ProbeForRead(request->Address, request->Size, 1);
        RtlCopyMemory(OutputBuffer, request->Address, request->Size);

        *BytesReturned = (ULONG)request->Size;

        // Detacher
        KeUnstackDetachProcess(&apcState);

        DbgPrint("[+] Memory read successful\n");

    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[!] Exception: 0x%X\n", status);
    }

    ObDereferenceObject(process);
    return status;
}
```

## 3. Implementation Cote User-Mode

### 3.1 Application Cliente

```c
#include <windows.h>
#include <stdio.h>

// Memes definitions IOCTL
#define IOCTL_BASE 0x800

#define IOCTL_HELLO \
    CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GET_VERSION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 1, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_SEND_DATA \
    CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 2, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_READ_PROCESS_MEMORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Structures
typedef struct _VERSION_INFO {
    ULONG Major;
    ULONG Minor;
    ULONG Build;
} VERSION_INFO, *PVERSION_INFO;

typedef struct _READ_MEMORY_REQUEST {
    ULONG ProcessId;
    PVOID Address;
    SIZE_T Size;
} READ_MEMORY_REQUEST, *PREAD_MEMORY_REQUEST;

// Ouvrir le device
HANDLE OpenDevice(const char* deviceName) {
    HANDLE hDevice = NULL;

    hDevice = CreateFileA(
        deviceName,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFile failed: %d\n", GetLastError());
        return NULL;
    }

    printf("[+] Device opened: %s\n", deviceName);
    return hDevice;
}

// Envoyer un IOCTL
BOOL SendIoctl(
    HANDLE hDevice,
    DWORD ioControlCode,
    PVOID inputBuffer,
    DWORD inputSize,
    PVOID outputBuffer,
    DWORD outputSize,
    PDWORD bytesReturned
) {
    BOOL success = FALSE;

    success = DeviceIoControl(
        hDevice,
        ioControlCode,
        inputBuffer,
        inputSize,
        outputBuffer,
        outputSize,
        bytesReturned,
        NULL
    );

    if (!success) {
        printf("[!] DeviceIoControl failed: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] IOCTL 0x%08X successful, returned %u bytes\n",
           ioControlCode, *bytesReturned);

    return TRUE;
}

int main(int argc, char* argv[]) {
    HANDLE hDevice = NULL;
    DWORD bytesReturned = 0;
    char outputBuffer[256] = {0};
    VERSION_INFO version = {0};

    // Ouvrir le device
    hDevice = OpenDevice("\\\\.\\MyDriver");
    if (!hDevice) {
        return 1;
    }

    // Test 1: IOCTL_HELLO
    printf("\n[*] Test 1: IOCTL_HELLO\n");
    if (SendIoctl(hDevice, IOCTL_HELLO, NULL, 0,
                  outputBuffer, sizeof(outputBuffer), &bytesReturned)) {
        printf("    Message: %s\n", outputBuffer);
    }

    // Test 2: IOCTL_GET_VERSION
    printf("\n[*] Test 2: IOCTL_GET_VERSION\n");
    if (SendIoctl(hDevice, IOCTL_GET_VERSION, NULL, 0,
                  &version, sizeof(version), &bytesReturned)) {
        printf("    Version: %u.%u.%u\n",
               version.Major, version.Minor, version.Build);
    }

    // Test 3: IOCTL_SEND_DATA
    printf("\n[*] Test 3: IOCTL_SEND_DATA\n");
    char testData[] = "Hello Kernel from User-Mode!";
    SendIoctl(hDevice, IOCTL_SEND_DATA,
              testData, sizeof(testData), NULL, 0, &bytesReturned);

    // Test 4: IOCTL_READ_PROCESS_MEMORY
    printf("\n[*] Test 4: IOCTL_READ_PROCESS_MEMORY\n");
    READ_MEMORY_REQUEST request;
    request.ProcessId = GetCurrentProcessId();
    request.Address = (PVOID)main;  // Notre propre fonction main
    request.Size = 64;

    BYTE memoryDump[64] = {0};
    if (SendIoctl(hDevice, IOCTL_READ_PROCESS_MEMORY,
                  &request, sizeof(request),
                  memoryDump, sizeof(memoryDump), &bytesReturned)) {
        printf("    Memory dump (first 64 bytes):\n    ");
        for (int i = 0; i < 64; i++) {
            printf("%02X ", memoryDump[i]);
            if ((i + 1) % 16 == 0) printf("\n    ");
        }
        printf("\n");
    }

    // Fermer le handle
    CloseHandle(hDevice);
    printf("\n[+] Device closed\n");

    return 0;
}
```

## 4. Methodes de Buffering

### 4.1 METHOD_BUFFERED (Recommande)

```c
// Le kernel copie les buffers dans un buffer systeme
// + Securise
// + Simple a utiliser
// - Moins performant pour grandes donnees

NTSTATUS HandleBuffered(PIRP Irp) {
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    // Input et Output utilisent le meme buffer
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    // Lire input
    if (inputLen > 0) {
        // Traiter input...
    }

    // Ecrire output
    if (outputLen > 0) {
        // Remplir buffer...
    }

    return STATUS_SUCCESS;
}
```

### 4.2 METHOD_IN_DIRECT / METHOD_OUT_DIRECT

```c
// Utilise MDL pour acces direct a la memoire user
// + Tres performant
// + Pas de copie pour grandes donnees
// - Plus complexe

NTSTATUS HandleDirect(PIRP Irp) {
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;

    // Input : toujours buffered
    inputBuffer = Irp->AssociatedIrp.SystemBuffer;

    // Output : via MDL
    if (Irp->MdlAddress != NULL) {
        outputBuffer = MmGetSystemAddressForMdlSafe(
            Irp->MdlAddress,
            NormalPagePriority | MdlMappingNoExecute
        );

        if (outputBuffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Ecrire directement dans le buffer user
        // ...
    }

    return STATUS_SUCCESS;
}
```

### 4.3 METHOD_NEITHER (Dangereux)

```c
// Acces direct aux pointeurs user-mode
// + Maximum de controle
// - TRES DANGEREUX (peut crasher)
// - Necessite ProbeForRead/ProbeForWrite

NTSTATUS HandleNeither(PIRP Irp) {
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;

    // Pointeurs RAW user-mode (DANGER!)
    inputBuffer = irpSp->Parameters.DeviceIoControl.Type3InputBuffer;
    outputBuffer = Irp->UserBuffer;

    __try {
        // OBLIGATOIRE : Prober avant acces
        if (inputBuffer != NULL) {
            ProbeForRead(
                inputBuffer,
                irpSp->Parameters.DeviceIoControl.InputBufferLength,
                1
            );
            // Utiliser inputBuffer...
        }

        if (outputBuffer != NULL) {
            ProbeForWrite(
                outputBuffer,
                irpSp->Parameters.DeviceIoControl.OutputBufferLength,
                1
            );
            // Utiliser outputBuffer...
        }

    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_INVALID_USER_BUFFER;
    }

    return STATUS_SUCCESS;
}
```

## 5. Securite et Validation

### 5.1 Validation des Parametres

```c
// TOUJOURS valider les inputs
NTSTATUS HandleIoctlSecure(
    PVOID InputBuffer,
    ULONG InputLength,
    PVOID OutputBuffer,
    ULONG OutputLength
) {
    // 1. Verifier les pointeurs
    if (InputBuffer == NULL && InputLength > 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // 2. Verifier les tailles
    if (InputLength < sizeof(EXPECTED_STRUCTURE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // 3. Verifier les valeurs
    PREQUEST request = (PREQUEST)InputBuffer;
    if (request->ProcessId == 0 || request->ProcessId > 65535) {
        return STATUS_INVALID_PARAMETER;
    }

    // 4. Verifier les ranges
    if (request->Size > MAX_ALLOWED_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    // 5. Verifier l'output
    if (OutputLength < request->Size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Traitement...
    return STATUS_SUCCESS;
}
```

### 5.2 Prevention TOCTOU (Time-Of-Check-Time-Of-Use)

```c
// MAUVAIS : Vulnerabilite TOCTOU
NTSTATUS BadHandler(PVOID InputBuffer, ULONG InputLength) {
    PREQUEST req = (PREQUEST)InputBuffer;

    // Check
    if (req->Size > MAX_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    // ... Autre code ...

    // Use (l'user peut modifier req->Size entre temps!)
    RtlCopyMemory(someBuffer, req->Data, req->Size);  // DANGER!

    return STATUS_SUCCESS;
}

// BON : Copier les valeurs localement
NTSTATUS GoodHandler(PVOID InputBuffer, ULONG InputLength) {
    PREQUEST req = (PREQUEST)InputBuffer;
    SIZE_T localSize = 0;

    // Copier la valeur
    localSize = req->Size;

    // Valider la copie locale
    if (localSize > MAX_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    // Utiliser la copie locale (safe)
    RtlCopyMemory(someBuffer, req->Data, localSize);

    return STATUS_SUCCESS;
}
```

## 6. Applications Offensives

### 6.1 Rootkit Command & Control

```c
// Driver rootkit avec interface IOCTL

#define IOCTL_HIDE_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_ELEVATE_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_INJECT_DLL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _HIDE_PROCESS_REQUEST {
    ULONG ProcessId;
    BOOLEAN Hide;  // TRUE = hide, FALSE = unhide
} HIDE_PROCESS_REQUEST;

typedef struct _ELEVATE_PROCESS_REQUEST {
    ULONG ProcessId;
} ELEVATE_PROCESS_REQUEST;

typedef struct _INJECT_DLL_REQUEST {
    ULONG ProcessId;
    WCHAR DllPath[MAX_PATH];
} INJECT_DLL_REQUEST;

// Handlers (implementations dans modules suivants)
NTSTATUS HandleHideProcess(PVOID Input, ULONG InputLen);
NTSTATUS HandleElevateProcess(PVOID Input, ULONG InputLen);
NTSTATUS HandleInjectDll(PVOID Input, ULONG InputLen);
```

### 6.2 EDR Killer via IOCTL

```c
// Driver pour desactiver EDR/AV

#define IOCTL_KILL_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x910, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_DISABLE_CALLBACK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x911, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_PATCH_ETW \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x912, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Kill un processus protege (bypass protections)
NTSTATUS HandleKillProcess(ULONG ProcessId) {
    PEPROCESS process = NULL;
    NTSTATUS status;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Forcer la terminaison (bypass PPL, etc.)
    status = ZwTerminateProcess(
        NtCurrentProcess(),
        STATUS_SUCCESS
    );

    ObDereferenceObject(process);
    return status;
}
```

## 7. Debugging IOCTL

### 7.1 Tracer les IOCTL

```c
// Logger tous les IOCTL recus
NTSTATUS DispatchDeviceControlDebug(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = irpSp->Parameters.DeviceIoControl.IoControlCode;

    // Decoder l'IOCTL
    ULONG deviceType = DEVICE_TYPE_FROM_CTL_CODE(ioctl);
    ULONG function = (ioctl >> 2) & 0xFFF;
    ULONG method = ioctl & 0x3;
    ULONG access = (ioctl >> 14) & 0x3;

    DbgPrint("[*] IOCTL Debug:\n");
    DbgPrint("    Code: 0x%08X\n", ioctl);
    DbgPrint("    DeviceType: 0x%X\n", deviceType);
    DbgPrint("    Function: 0x%X\n", function);
    DbgPrint("    Method: %u ", method);
    switch(method) {
        case METHOD_BUFFERED: DbgPrint("(BUFFERED)\n"); break;
        case METHOD_IN_DIRECT: DbgPrint("(IN_DIRECT)\n"); break;
        case METHOD_OUT_DIRECT: DbgPrint("(OUT_DIRECT)\n"); break;
        case METHOD_NEITHER: DbgPrint("(NEITHER)\n"); break;
    }
    DbgPrint("    Access: 0x%X\n", access);

    // Continuer le traitement normal
    return DispatchDeviceControl(DeviceObject, Irp);
}
```

## 8. Checklist IOCTL Communication

```
[ ] Comprendre la structure d'un code IOCTL
[ ] Definir des IOCTL codes personnalises
[ ] Implementer IRP_MJ_DEVICE_CONTROL handler
[ ] Router les IOCTL vers les bons handlers
[ ] Valider tous les parametres d'entree
[ ] Gerer les buffers de maniere securisee
[ ] Utiliser METHOD_BUFFERED par defaut
[ ] Implementer une application user-mode cliente
[ ] Gerer les erreurs proprement
[ ] Debugger les IOCTL avec DbgPrint/WinDbg
```

## 9. Exercices

Voir [exercice.md](exercice.md)

## Ressources Complementaires

- MSDN: I/O Control Codes
- OSR Online: IOCTL Deep Dive
- Windows Internals Part 1 (Chapter 8: I/O System)
- GitHub: Windows Driver Samples - IOCTL Examples

---

**Navigation**
- [Module precedent](../02-Kernel-Memory/)
- [Module suivant](../04-Callbacks/)

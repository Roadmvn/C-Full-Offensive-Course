# Module W71 : Bases des Drivers Windows

## Objectifs

A la fin de ce module, vous serez capable de :
- Comprendre l'architecture kernel Windows
- Developper un driver Windows basique (WDM)
- Compiler et signer un driver
- Charger et decharger un driver dans le kernel

## 1. Architecture Kernel Windows

### 1.1 User Mode vs Kernel Mode

Imaginez Windows comme un batiment a deux etages :
- **User Mode** (Ring 3) : L'etage public accessible a tous
- **Kernel Mode** (Ring 0) : Le sous-sol ultra-securise avec acces total

```
┌────────────────────────────────────────┐
│         USER MODE (Ring 3)             │
│                                        │
│  Applications    Services    DLLs      │
│  notepad.exe    svchost.exe  kernel32  │
│                                        │
├────────────────────────────────────────┤ <--- Transition
│        KERNEL MODE (Ring 0)            │
│                                        │
│  ┌──────────────────────────────────┐ │
│  │  Executive (ntoskrnl.exe)        │ │
│  │  - Object Manager                │ │
│  │  - Memory Manager                │ │
│  │  - I/O Manager                   │ │
│  │  - Security Reference Monitor    │ │
│  └──────────────────────────────────┘ │
│                                        │
│  ┌──────────────────────────────────┐ │
│  │  Drivers (.sys)                  │ │
│  │  - Filesystem drivers            │ │
│  │  - Device drivers                │ │
│  │  - Filter drivers                │ │
│  └──────────────────────────────────┘ │
│                                        │
│  ┌──────────────────────────────────┐ │
│  │  Kernel (ntoskrnl.exe - HAL)     │ │
│  │  - Scheduler                     │ │
│  │  - Interrupt handling            │ │
│  └──────────────────────────────────┘ │
│                                        │
└────────────────────────────────────────┘
         ▼
┌────────────────────────────────────────┐
│         HARDWARE                        │
└────────────────────────────────────────┘
```

### 1.2 Types de Drivers

```
DRIVER TYPES:

1. WDM (Windows Driver Model)
   - Legacy mais toujours utilise
   - Plus de controle bas niveau
   - Plus complexe

2. WDF (Windows Driver Framework)
   - KMDF (Kernel-Mode Driver Framework)
   - UMDF (User-Mode Driver Framework)
   - Plus simple, abstraction elevee

3. Minifilter
   - Pour le filtrage de fichiers
   - Framework specialise
   - Utilise par les antivirus

4. NDIS (Network Driver Interface Specification)
   - Drivers reseau
   - Framework specialise
```

### 1.3 Structure d'un Driver

```
COMPOSANTS D'UN DRIVER:

┌─────────────────────────────────────┐
│  DRIVER OBJECT                      │
│  - DriverEntry()     (Entry point)  │
│  - DriverUnload()    (Cleanup)      │
│  - Dispatch Routines (IRP handlers) │
│  - Device Objects                   │
└─────────────────────────────────────┘
         │
         ├──> DEVICE OBJECT 1
         │    ├─ IRP_MJ_CREATE
         │    ├─ IRP_MJ_CLOSE
         │    ├─ IRP_MJ_READ
         │    ├─ IRP_MJ_WRITE
         │    └─ IRP_MJ_DEVICE_CONTROL
         │
         └──> DEVICE OBJECT 2
              └─ ...
```

## 2. Premier Driver Windows

### 2.1 DriverEntry - Point d'Entree

```c
#include <ntddk.h>

// Prototype de la fonction de dechargement
VOID DriverUnload(PDRIVER_OBJECT DriverObject);

// Point d'entree du driver
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[+] DriverEntry called\n");
    DbgPrint("[*] DriverObject: %p\n", DriverObject);

    // Enregistrer la fonction de dechargement
    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("[+] Driver loaded successfully\n");
    return STATUS_SUCCESS;
}

// Fonction appelee lors du dechargement
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrint("[*] DriverUnload called\n");
    DbgPrint("[+] Driver unloaded successfully\n");
}
```

### 2.2 Creation d'un Device Object

```c
#include <ntddk.h>

#define DEVICE_NAME L"\\Device\\MyDriver"
#define SYMBOLIC_LINK L"\\DosDevices\\MyDriver"

// Dispatch routines
NTSTATUS DispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID DriverUnload(PDRIVER_OBJECT DriverObject);

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLink;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[+] MyDriver - DriverEntry\n");

    // Initialiser les noms
    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    RtlInitUnicodeString(&symbolicLink, SYMBOLIC_LINK);

    // Creer le device object
    status = IoCreateDevice(
        DriverObject,
        0,                              // Extension size
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[!] IoCreateDevice failed: 0x%X\n", status);
        return status;
    }

    DbgPrint("[+] Device created: %wZ\n", &deviceName);

    // Creer le symbolic link (pour acces depuis user-mode)
    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[!] IoCreateSymbolicLink failed: 0x%X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    DbgPrint("[+] Symbolic link created: %wZ\n", &symbolicLink);

    // Configurer les dispatch routines
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("[+] Driver initialization complete\n");
    return STATUS_SUCCESS;
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    DbgPrint("[*] IRP_MJ_CREATE\n");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    DbgPrint("[*] IRP_MJ_CLOSE\n");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;

    DbgPrint("[*] IRP_MJ_DEVICE_CONTROL: 0x%X\n", ioControlCode);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symbolicLink;

    DbgPrint("[*] MyDriver - DriverUnload\n");

    // Supprimer le symbolic link
    RtlInitUnicodeString(&symbolicLink, SYMBOLIC_LINK);
    IoDeleteSymbolicLink(&symbolicLink);

    // Supprimer le device object
    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
        DbgPrint("[+] Device deleted\n");
    }

    DbgPrint("[+] Driver unloaded\n");
}
```

## 3. Compilation d'un Driver

### 3.1 Environnement de Developpement

```
OUTILS NECESSAIRES:

1. Windows Driver Kit (WDK)
   - Telechargeable depuis Microsoft
   - Contient les headers kernel
   - Outils de compilation et signature

2. Visual Studio
   - Version compatible avec WDK
   - Templates de driver integres

3. SDK Windows
   - Headers Windows
   - Outils de build
```

### 3.2 Fichier de Build - sources

```makefile
# fichier: sources

TARGETNAME=MyDriver
TARGETTYPE=DRIVER
DRIVERTYPE=WDM

# Inclusion paths
INCLUDES=$(DDK_INC_PATH)

# Sources
SOURCES=driver.c

# Target OS
_NT_TARGET_VERSION=$(_NT_TARGET_VERSION_WIN7)
```

### 3.3 Build avec WDK

```bat
REM Ouvrir un "x64 Checked Build Environment"
cd C:\Drivers\MyDriver
build

REM Ou avec MSBuild (WDK moderne)
msbuild MyDriver.vcxproj /p:Configuration=Debug /p:Platform=x64
```

## 4. Signature de Driver

### 4.1 Driver Signature Enforcement (DSE)

```
DSE (depuis Vista 64-bit):
Tous les drivers doivent etre signes pour etre charges

OPTIONS POUR TESTER:

1. Mode Test Signing (developpement)
   bcdedit /set testsigning on
   Reboot

2. Disable Driver Signature (temporaire)
   F8 au boot -> Advanced Options
   -> Disable Driver Signature Enforcement

3. Signer avec certificat de test

4. BYOVD (production) - voir module W78
```

### 3.2 Creation d'un Certificat de Test

```bat
REM Creer un certificat de test
makecert -r -pe -ss PrivateCertStore -n "CN=MyDriverTestCert" MyDriverTest.cer

REM Signer le driver
signtool sign /v /s PrivateCertStore /n "MyDriverTestCert" /t http://timestamp.digicert.com MyDriver.sys

REM Verifier la signature
signtool verify /v /pa MyDriver.sys
```

## 5. Chargement du Driver

### 5.1 Service Control Manager

```c
#include <windows.h>
#include <stdio.h>

BOOL LoadDriver(const char* driverPath, const char* serviceName) {
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    BOOL success = FALSE;

    printf("[*] Chargement du driver: %s\n", driverPath);

    // Ouvrir le SCM
    hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCManager) {
        printf("[!] OpenSCManager failed: %d\n", GetLastError());
        return FALSE;
    }

    // Creer le service
    hService = CreateServiceA(
        hSCManager,
        serviceName,
        serviceName,
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        driverPath,
        NULL, NULL, NULL, NULL, NULL
    );

    if (!hService) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_EXISTS) {
            printf("[*] Service deja existant, ouverture...\n");
            hService = OpenServiceA(hSCManager, serviceName, SERVICE_ALL_ACCESS);
        } else {
            printf("[!] CreateService failed: %d\n", error);
            CloseServiceHandle(hSCManager);
            return FALSE;
        }
    }

    printf("[+] Service cree\n");

    // Demarrer le service (charge le driver)
    if (!StartServiceA(hService, 0, NULL)) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[*] Driver deja charge\n");
            success = TRUE;
        } else {
            printf("[!] StartService failed: %d\n", error);
        }
    } else {
        printf("[+] Driver charge avec succes\n");
        success = TRUE;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return success;
}

BOOL UnloadDriver(const char* serviceName) {
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS status;
    BOOL success = FALSE;

    printf("[*] Dechargement du driver: %s\n", serviceName);

    hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        printf("[!] OpenSCManager failed: %d\n", GetLastError());
        return FALSE;
    }

    hService = OpenServiceA(hSCManager, serviceName, SERVICE_ALL_ACCESS);
    if (!hService) {
        printf("[!] OpenService failed: %d\n", GetLastError());
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    // Arreter le service (decharge le driver)
    if (ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
        printf("[+] Driver arrete\n");
    }

    // Supprimer le service
    if (DeleteService(hService)) {
        printf("[+] Service supprime\n");
        success = TRUE;
    } else {
        printf("[!] DeleteService failed: %d\n", GetLastError());
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return success;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s load <driver.sys> <serviceName>\n", argv[0]);
        printf("  %s unload <serviceName>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "load") == 0 && argc >= 4) {
        LoadDriver(argv[2], argv[3]);
    } else if (strcmp(argv[1], "unload") == 0 && argc >= 3) {
        UnloadDriver(argv[2]);
    } else {
        printf("[!] Arguments invalides\n");
        return 1;
    }

    return 0;
}
```

## 6. Debugging de Driver

### 6.1 WinDbg et Kernel Debugging

```
CONFIGURATION DU DEBUGGING:

1. Machine hote (debugger):
   - Installer WinDbg (Windows SDK)

2. Machine cible (debuggee):
   - Configuration bcdedit:
     bcdedit /debug on
     bcdedit /dbgsettings serial debugport:1 baudrate:115200

3. Connexion:
   - Port serie (physique ou virtuel)
   - Network debugging (WinDbg Preview)
   - Virtual Machine (COM port)

4. Lancement WinDbg:
   windbg -k com:port=COM1,baud=115200
```

### 6.2 Commandes Utiles

```
COMMANDES WINDBG:

lm          # Lister les modules charges
!drvobj     # Informations sur un driver object
!devobj     # Informations sur un device object
bp          # Breakpoint
g           # Continue execution
k           # Stack trace
dt          # Display type (structure)
!process    # Informations sur les processus
```

## 7. Applications Offensives

### 7.1 Rootkit Basique

```c
// Driver basique pour cacher des processus
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[*] Rootkit Driver Loading...\n");

    // Setup dispatch routines
    DriverObject->DriverUnload = DriverUnload;

    // TODO: Implementer le hooking (voir modules suivants)

    return STATUS_SUCCESS;
}
```

### 7.2 Cas d'Usage Red Team

```
UTILISATION DES DRIVERS EN RED TEAM:

1. Elevation de Privileges
   - Exploiter des drivers vulnerables (BYOVD)
   - Bypass UAC via driver

2. Persistence
   - Driver malveillant charge au boot
   - Difficile a detecter et supprimer

3. Evasion
   - Desactiver EDR/AV au niveau kernel
   - Bypass de PatchGuard (avance)

4. Espionnage
   - Keylogger kernel
   - Network sniffer
   - Acces memoire complete
```

## 8. Checklist Driver Basics

```
[ ] Comprendre User Mode vs Kernel Mode
[ ] Connaitre les types de drivers (WDM, WDF, Minifilter)
[ ] Implementer DriverEntry et DriverUnload
[ ] Creer un Device Object
[ ] Implementer les dispatch routines basiques
[ ] Compiler un driver avec WDK
[ ] Signer un driver (certificat de test)
[ ] Charger/decharger un driver via SCM
[ ] Debugger un driver avec WinDbg
[ ] Comprendre DSE (Driver Signature Enforcement)
```

## 9. Exercices

Voir [exercice.md](exercice.md)

## Ressources Complementaires

- Microsoft: Windows Driver Kit Documentation
- OSR Online: Windows Driver Development Resources
- Windows Internals Part 1 (Chapter on I/O System)
- GitHub: Windows Driver Samples

---

**Navigation**
- [Module precedent](../../07-Credential-Access/06-DCOM-Lateral/)
- [Module suivant](../02-Kernel-Memory/)

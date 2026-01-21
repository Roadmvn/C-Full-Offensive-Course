# Module W03 : Gestion Mémoire Windows - Solutions

## Solution Exercice 1 : Allocation mémoire basique avec VirtualAlloc

**Objectif** : Comprendre l'utilisation de VirtualAlloc pour allouer de la mémoire

```c
#include <windows.h>
#include <stdio.h>

int main() {
    printf("[*] === Exercice 1 : VirtualAlloc basique ===\n\n");

    // Allouer 4096 bytes (1 page) en lecture/écriture
    LPVOID addr = VirtualAlloc(
        NULL,                    // Adresse automatique
        4096,                    // 1 page (4 KB)
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (addr == NULL) {
        printf("[-] VirtualAlloc echoue: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Memoire allouee a l'adresse: 0x%p\n", addr);
    printf("[+] Taille: 4096 bytes (1 page)\n");
    printf("[+] Protection: PAGE_READWRITE\n\n");

    // Ecrire des données dans la mémoire allouée
    char *data = (char*)addr;
    strcpy(data, "Bonjour depuis la memoire allouee!");
    printf("[+] Donnees ecrites: %s\n", data);

    // Libérer la mémoire
    if (VirtualFree(addr, 0, MEM_RELEASE)) {
        printf("[+] Memoire liberee avec succes\n");
    }

    return 0;
}
```

**Explications** :
- `VirtualAlloc` alloue de la mémoire virtuelle dans l'espace d'adressage du processus
- `MEM_COMMIT | MEM_RESERVE` : réserve et commit la mémoire en une seule opération
- `PAGE_READWRITE` : la mémoire est accessible en lecture et écriture
- `VirtualFree` avec `MEM_RELEASE` libère totalement la mémoire

---

## Solution Exercice 2 : Modification des permissions avec VirtualProtect

**Objectif** : Changer les permissions d'une zone mémoire de RW vers RX

```c
#include <windows.h>
#include <stdio.h>

int main() {
    printf("[*] === Exercice 2 : VirtualProtect ===\n\n");

    // Shellcode simple: ret (0xC3)
    unsigned char shellcode[] = "\xC3";

    // 1. Allouer en RW
    LPVOID exec_mem = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!exec_mem) {
        printf("[-] VirtualAlloc echoue\n");
        return 1;
    }

    printf("[+] Memoire allouee en RW: 0x%p\n", exec_mem);

    // 2. Copier le shellcode
    memcpy(exec_mem, shellcode, sizeof(shellcode));
    printf("[+] Shellcode copie\n");

    // 3. Changer protection RW -> RX
    DWORD oldProtect;
    if (!VirtualProtect(exec_mem, sizeof(shellcode),
                        PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[-] VirtualProtect echoue: %lu\n", GetLastError());
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return 1;
    }

    printf("[+] Protection changee: RW -> RX\n");
    printf("[+] Ancienne protection: 0x%lx\n", oldProtect);

    // 4. Executer le shellcode
    void (*func)() = (void(*)())exec_mem;
    func();
    printf("[+] Shellcode execute avec succes!\n");

    // 5. Nettoyer
    VirtualFree(exec_mem, 0, MEM_RELEASE);

    return 0;
}
```

**Explications** :
- L'approche RW → RX est plus furtive que d'allouer directement en RWX
- Les EDR surveillent les allocations PAGE_EXECUTE_READWRITE
- `VirtualProtect` retourne l'ancienne protection dans `oldProtect`

---

## Solution Exercice 3 : Scanner la mémoire avec VirtualQuery

**Objectif** : Énumérer toutes les pages mémoire commitées du processus

```c
#include <windows.h>
#include <stdio.h>

const char* GetProtectionString(DWORD protect) {
    switch(protect & 0xFF) {
        case PAGE_NOACCESS: return "---";
        case PAGE_READONLY: return "R--";
        case PAGE_READWRITE: return "RW-";
        case PAGE_EXECUTE: return "--X";
        case PAGE_EXECUTE_READ: return "R-X";
        case PAGE_EXECUTE_READWRITE: return "RWX";
        case PAGE_EXECUTE_WRITECOPY: return "RWC";
        default: return "???";
    }
}

int main() {
    printf("[*] === Exercice 3 : Scanner la memoire ===\n\n");

    MEMORY_BASIC_INFORMATION mbi;
    LPVOID addr = NULL;
    int pageCount = 0;

    printf("%-18s %-12s %-10s %-5s\n",
           "Adresse", "Taille", "Etat", "Prot");
    printf("-----------------------------------------------------\n");

    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        // Afficher uniquement les pages commitées
        if (mbi.State == MEM_COMMIT) {
            printf("0x%-16p %-12zu COMMIT     %s\n",
                   mbi.BaseAddress,
                   mbi.RegionSize,
                   GetProtectionString(mbi.Protect));
            pageCount++;
        }

        // Passer à la région suivante
        addr = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    printf("-----------------------------------------------------\n");
    printf("[+] Total: %d pages commitees\n", pageCount);

    return 0;
}
```

**Explications** :
- `VirtualQuery` retourne des informations sur une région mémoire
- On itère sur tout l'espace d'adressage en incrémentant de `RegionSize`
- Utile pour identifier les zones RWX suspectes en forensics

---

## Solution Exercice 4 : Lecture mémoire d'un processus distant

**Objectif** : Lire la mémoire d'un autre processus avec ReadProcessMemory

```c
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

DWORD FindProcessByName(const char *processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <processus> <adresse_hex>\n", argv[0]);
        printf("Exemple: %s notepad.exe 0x7FF12345000\n", argv[0]);
        return 1;
    }

    const char *processName = argv[1];
    LPVOID addr = (LPVOID)strtoull(argv[2], NULL, 16);

    printf("[*] === Exercice 4 : ReadProcessMemory ===\n\n");

    // 1. Trouver le processus
    DWORD pid = FindProcessByName(processName);
    if (pid == 0) {
        printf("[-] Processus '%s' non trouve\n", processName);
        return 1;
    }
    printf("[+] PID de %s: %lu\n", processName, pid);

    // 2. Ouvrir le processus
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        printf("[-] OpenProcess echoue: %lu\n", GetLastError());
        printf("[-] Droits administrateur probablement necessaires\n");
        return 1;
    }
    printf("[+] Handle obtenu: 0x%p\n", hProcess);

    // 3. Lire 128 bytes
    char buffer[128] = {0};
    SIZE_T bytesRead;

    if (ReadProcessMemory(hProcess, addr, buffer, sizeof(buffer), &bytesRead)) {
        printf("[+] Lu %zu bytes a l'adresse 0x%p:\n\n", bytesRead, addr);

        // Affichage hexadécimal
        for (SIZE_T i = 0; i < bytesRead; i++) {
            printf("%02X ", (unsigned char)buffer[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n\n");

        // Affichage ASCII
        printf("ASCII: ");
        for (SIZE_T i = 0; i < bytesRead; i++) {
            char c = buffer[i];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        printf("\n");

    } else {
        printf("[-] ReadProcessMemory echoue: %lu\n", GetLastError());
        printf("[-] Adresse probablement invalide ou non accessible\n");
    }

    CloseHandle(hProcess);
    return 0;
}
```

**Explications** :
- `OpenProcess` avec `PROCESS_VM_READ` donne le droit de lire la mémoire
- `ReadProcessMemory` copie les données du processus distant vers notre buffer
- Nécessite des privilèges élevés pour lire certains processus (SYSTEM, protected)
- Utile pour dumper des credentials (lsass.exe), analyser du code, etc.

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :
- [x] Allouer de la mémoire avec VirtualAlloc et la libérer avec VirtualFree
- [x] Modifier les permissions d'une zone mémoire avec VirtualProtect
- [x] Scanner la mémoire d'un processus avec VirtualQuery
- [x] Lire la mémoire d'un processus distant avec ReadProcessMemory
- [x] Comprendre les implications OPSEC (éviter RWX, préférer RW→RX)
- [x] Identifier les cas d'usage en contexte offensif (shellcode injection, dumping credentials)

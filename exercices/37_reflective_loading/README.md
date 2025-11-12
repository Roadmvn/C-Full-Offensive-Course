# Module 37 : Reflective Loading

## Vue d'ensemble

Ce module explore le **Reflective DLL Injection**, technique avancée permettant de charger une DLL directement depuis la mémoire sans passer par le système de fichiers. Cette méthode est utilisée par des malwares sophistiqués pour éviter la détection et dans des contextes légitimes pour le chargement dynamique de modules.

## Concepts clés

### Reflective DLL Injection

Processus de chargement d'une DLL **sans CreateFile** :
```
DLL en mémoire (buffer) → Parsing PE → Relocation → Import resolution → Exécution
```

Avantages :
- **Pas de fichier sur disque** : Évite la détection par antivirus
- **Chargement furtif** : Pas d'appel à LoadLibrary
- **Flexibilité** : Chargement depuis réseau, mémoire, etc.

### Format PE (Portable Executable)

Structure d'un fichier EXE/DLL Windows :
```
PE File
├── DOS Header (MZ)
├── DOS Stub
├── PE Signature (PE\0\0)
├── COFF File Header
├── Optional Header
├── Section Headers
├── .text (code)
├── .data (données)
├── .rdata (données read-only)
└── .reloc (informations de relocation)
```

### Position Independent Code (PIC)

Code capable de s'exécuter à n'importe quelle adresse mémoire :
- **Pas d'adresses absolues hardcodées**
- **Relocations** : Corrections d'adresses au chargement
- **Relatif à RIP/EIP** : Adressage relatif au pointeur d'instruction

### Manual PE Parsing

Étapes de parsing manuel :
1. **Vérifier la signature PE** (MZ, PE\0\0)
2. **Lire les headers** (COFF, Optional)
3. **Itérer sur les sections** (.text, .data, etc.)
4. **Extraire les tables** (Import, Export, Relocation)

### Relocation

Correction des adresses lors du chargement :
```c
Base Address Desired : 0x10000000
Base Address Actual  : 0x50000000
Delta = 0x40000000

Pour chaque relocation :
    *address = *address + delta
```

### Import Resolution

Résolution manuelle des imports :
1. **Parser Import Directory Table**
2. **Pour chaque DLL** : LoadLibrary
3. **Pour chaque fonction** : GetProcAddress
4. **Écrire l'adresse** dans Import Address Table (IAT)

### TLS Callbacks

Thread Local Storage - Callbacks exécutés avant main() :
```c
PIMAGE_TLS_CALLBACK TlsCallbacks[] = {
    TlsCallback1,
    TlsCallback2,
    NULL
};
```

Utilisés pour :
- Initialisation pré-main
- Détection de debugging (anti-debug)
- Chargement de modules additionnels

## ⚠️ AVERTISSEMENT LÉGAL STRICT ⚠️

### ATTENTION CRITIQUE

Le Reflective Loading est une technique **EXTRÊMEMENT SENSIBLE** :

**Utilisations légitimes** :
- Frameworks de pentest (Metasploit, Cobalt Strike)
- Chargement de plugins sans fichier temporaire
- Sandboxing et isolation de code
- Recherche en sécurité informatique

**Utilisations ILLÉGALES** :
- Malware et ransomware
- Rootkits et backdoors
- Contournement d'antivirus/EDR
- Injection dans des processus sans autorisation

### Cadre légal

**INTERDICTIONS ABSOLUES** :
- ❌ Développer des malwares ou outils d'attaque
- ❌ Injecter du code dans des processus sans autorisation
- ❌ Contourner des protections de sécurité en production
- ❌ Utiliser sur des systèmes sans autorisation écrite

**AUTORISATIONS REQUISES** :
- ✅ Environnement de test isolé (VM)
- ✅ Autorisation écrite du propriétaire système
- ✅ Cadre professionnel de sécurité (pentest contractuel)
- ✅ Recherche académique éthique

### Conséquences légales

Sanctions pour usage illégal :
- **CFAA (USA)** : Jusqu'à 20 ans de prison
- **Directive NIS2 (UE)** : Amendes jusqu'à 10M€
- **Loi Godfrain (France)** : Jusqu'à 5 ans + 150k€
- **Responsabilité civile** : Dommages et intérêts

### Responsabilité

**VOUS ÊTES PERSONNELLEMENT RESPONSABLE** de :
- Toute utilisation de ces techniques
- Respect des lois locales et internationales
- Obtention des autorisations nécessaires
- Conséquences de vos actions

**L'auteur décline toute responsabilité** pour usage illégal.

## Détection et prévention

### Indicateurs de Reflective Loading

Comportements suspects :
- Allocation mémoire RWX
- Modifications d'Import Address Table (IAT)
- Chargement manuel via GetProcAddress répété
- Absence de DLL correspondante sur disque
- Modifications de .text après chargement

### Outils de détection

**EDR (Endpoint Detection and Response)** :
- CrowdStrike Falcon
- Microsoft Defender for Endpoint
- SentinelOne
- Carbon Black

**Monitoring** :
- Sysmon (Event ID 7, 8, 10)
- Process Hacker
- PE-sieve
- Moneta

### Protections système

**Windows Defender** :
- AMSI (Antimalware Scan Interface)
- Behavior monitoring
- Memory scanning

**Control Flow Guard (CFG)** :
- Prévient les détournements de flux
- Validation des appels indirects

**Code Integrity** :
- Signature des DLL requise
- Blocage de code non signé

## APIs et structures essentielles

### Structures PE

```c
typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic;     // MZ
    // ...
    LONG e_lfanew;    // Offset vers PE Header
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;              // PE\0\0
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS;

typedef struct _IMAGE_SECTION_HEADER {
    BYTE Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    // ...
} IMAGE_SECTION_HEADER;
```

### APIs Windows

```c
HMODULE LoadLibrary(LPCSTR lpLibFileName);
FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
```

## Étapes d'implémentation

### 1. Lire la DLL en mémoire
```c
HANDLE hFile = CreateFile("mydll.dll", ...);
DWORD size = GetFileSize(hFile, NULL);
BYTE *buffer = malloc(size);
ReadFile(hFile, buffer, size, ...);
```

### 2. Parser les headers PE
```c
PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(buffer + dosHeader->e_lfanew);
```

### 3. Allouer mémoire pour l'image
```c
LPVOID baseAddress = VirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

### 4. Copier les sections
```c
PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
    memcpy(baseAddress + section[i].VirtualAddress,
           buffer + section[i].PointerToRawData,
           section[i].SizeOfRawData);
}
```

### 5. Résoudre les imports
```c
PIMAGE_IMPORT_DESCRIPTOR importDesc = ...;
while (importDesc->Name) {
    HMODULE hDll = LoadLibraryA((char*)(baseAddress + importDesc->Name));
    // Résoudre chaque fonction...
}
```

### 6. Appliquer les relocations
```c
PIMAGE_BASE_RELOCATION reloc = ...;
DWORD_PTR delta = (DWORD_PTR)baseAddress - ntHeaders->OptionalHeader.ImageBase;
// Appliquer delta à chaque relocation...
```

### 7. Exécuter le point d'entrée
```c
typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);
DllMain_t DllMain = (DllMain_t)(baseAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint);
DllMain((HINSTANCE)baseAddress, DLL_PROCESS_ATTACH, NULL);
```

## Objectifs pédagogiques

À la fin de ce module, vous devriez comprendre :
- Structure du format PE
- Processus de chargement de DLL Windows
- Mécanismes de relocation
- Résolution manuelle d'imports
- Techniques de détection et prévention
- Implications de sécurité

## Prérequis

- Connaissance approfondie de Windows
- Compréhension de la mémoire virtuelle
- Expérience avec les pointeurs et structures C
- Notions d'architecture x86/x64

## Références

- Microsoft PE/COFF Specification
- "Windows Internals" (Russinovich, Solomon, Ionescu)
- Reflective DLL Injection (Stephen Fewer)
- MITRE ATT&CK : T1055.001 (Process Injection: Dynamic-link Library Injection)
- PE Format Documentation (Microsoft Docs)

---

**RAPPEL FINAL** : Le Reflective Loading est une technique puissante avec des implications de sécurité majeures. Utilisez ces connaissances **exclusivement** à des fins éthiques, légales et défensives.

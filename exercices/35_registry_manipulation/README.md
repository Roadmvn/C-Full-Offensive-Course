# Module 35 : Registry Manipulation

## Vue d'ensemble

Ce module explore la manipulation du **Registre Windows** (Windows Registry), base de données hiérarchique centrale qui stocke les paramètres de configuration du système d'exploitation, des applications et des utilisateurs. La maîtrise du registre est essentielle pour l'administration système, le développement Windows et l'analyse de sécurité.

## Concepts clés

### Structure du Registre Windows

Le registre est organisé en une structure hiérarchique similaire à un système de fichiers :

```
Registre Windows
├── HKEY_CLASSES_ROOT (HKCR)
│   └── Associations de fichiers et COM
├── HKEY_CURRENT_USER (HKCU)
│   └── Configuration de l'utilisateur actuel
├── HKEY_LOCAL_MACHINE (HKLM)
│   └── Configuration système globale
├── HKEY_USERS (HKU)
│   └── Profils de tous les utilisateurs
└── HKEY_CURRENT_CONFIG (HKCC)
    └── Configuration matérielle active
```

### Clés (Keys) et Valeurs (Values)

**Clés** : Conteneurs hiérarchiques (similaires aux dossiers)
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion
```

**Valeurs** : Données stockées dans les clés (similaires aux fichiers)
- **Nom** : Identifiant de la valeur
- **Type** : REG_SZ, REG_DWORD, REG_BINARY, etc.
- **Données** : Contenu de la valeur

### Types de valeurs du registre

| Type | Description | Exemple |
|------|-------------|---------|
| REG_SZ | Chaîne de caractères | "C:\\Windows\\System32" |
| REG_DWORD | Entier 32 bits | 0x00000001 |
| REG_QWORD | Entier 64 bits | 0x0000000000000001 |
| REG_BINARY | Données binaires | 01 02 03 04 |
| REG_MULTI_SZ | Tableau de chaînes | "Line1\0Line2\0" |
| REG_EXPAND_SZ | Chaîne avec variables | "%SystemRoot%\\system32" |

### APIs essentielles

#### RegOpenKeyEx
Ouvre une clé de registre existante :
```c
LSTATUS RegOpenKeyEx(
    HKEY hKey,              // Clé racine (HKLM, HKCU, etc.)
    LPCSTR lpSubKey,        // Chemin de la sous-clé
    DWORD ulOptions,        // Options (0 généralement)
    REGSAM samDesired,      // Droits d'accès
    PHKEY phkResult         // Handle résultant
);
```

#### RegCreateKeyEx
Crée ou ouvre une clé de registre :
```c
LSTATUS RegCreateKeyEx(
    HKEY hKey,
    LPCSTR lpSubKey,
    DWORD Reserved,
    LPSTR lpClass,
    DWORD dwOptions,
    REGSAM samDesired,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY phkResult,
    LPDWORD lpdwDisposition
);
```

#### RegSetValueEx
Définit une valeur dans le registre :
```c
LSTATUS RegSetValueEx(
    HKEY hKey,
    LPCSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,
    const BYTE *lpData,
    DWORD cbData
);
```

#### RegQueryValueEx
Lit une valeur du registre :
```c
LSTATUS RegQueryValueEx(
    HKEY hKey,
    LPCSTR lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData
);
```

#### RegDeleteKeyEx / RegDeleteValue
Supprime des clés ou valeurs :
```c
LSTATUS RegDeleteKeyEx(HKEY hKey, LPCSTR lpSubKey, REGSAM samDesired, DWORD Reserved);
LSTATUS RegDeleteValue(HKEY hKey, LPCSTR lpValueName);
```

### Persistence via le Registre

Le registre est un vecteur de persistence privilégié pour les applications et malwares :

**Clés de démarrage automatique (Run Keys)** :
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

**Services Windows** :
```
HKLM\SYSTEM\CurrentControlSet\Services
```

**Scheduled Tasks** :
```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache
```

### Hiding Data in Registry

Techniques de dissimulation de données :

1. **Null-byte injection** : Utiliser des caractères nuls dans les noms
2. **Binary values** : Stocker des données chiffrées en REG_BINARY
3. **Obscure locations** : Clés peu visitées ou déguisées
4. **Alternate Data Streams** : Techniques avancées de dissimulation

## ⚠️ AVERTISSEMENT LÉGAL STRICT ⚠️

### ATTENTION CRITIQUE

La manipulation du registre Windows est une technique **SENSIBLE** pouvant causer :

**Conséquences techniques** :
- Corruption du système d'exploitation
- Impossibilité de démarrer Windows
- Perte de données critiques
- Instabilité système permanente

**Utilisations légitimes** :
- Administration et configuration système
- Développement d'applications Windows
- Scripts d'installation légitimes
- Outils de diagnostic et monitoring

**Utilisations ILLÉGALES** :
- Installation de malware avec persistence
- Dissimulation de données malveillantes
- Altération de paramètres de sécurité
- Contournement de protections système

### Cadre légal

**INTERDICTIONS STRICTES** :
- ❌ Modifier le registre de systèmes sans autorisation
- ❌ Implanter des mécanismes de persistence malveillants
- ❌ Dissimuler des données illégales dans le registre
- ❌ Altérer des paramètres de sécurité sans autorisation

**AUTORISATIONS REQUISES** :
- ✅ Machine de test personnelle ou VM isolée
- ✅ Autorisation écrite du propriétaire du système
- ✅ Backup complet avant toute modification
- ✅ Documentation de toutes les modifications

### Conséquences légales

Violation des lois :
- **Computer Fraud and Abuse Act (CFAA)** - USA
- **Directive NIS2** - Union Européenne
- **Loi Godfrain** - France (Articles 323-1 à 323-7)
- **Computer Misuse Act** - Royaume-Uni

**Responsabilité civile et pénale** :
- Dommages matériels et immatériels
- Amendes substantielles
- Peines de prison possibles
- Interdiction professionnelle

### Responsabilité

**VOUS ÊTES PERSONNELLEMENT RESPONSABLE** :
- Des modifications apportées au registre
- De la sauvegarde et restauration du système
- Du respect des lois et réglementations
- Des conséquences de vos actions

**L'auteur de ce module décline toute responsabilité** pour :
- Corruption de système
- Perte de données
- Usage illégal ou non autorisé
- Violations de lois

## Bonnes pratiques de sécurité

### Avant toute modification

1. **Backup complet du registre** :
   ```
   reg export HKLM backup_hklm.reg
   reg export HKCU backup_hkcu.reg
   ```

2. **Point de restauration système** :
   - Créer un point de restauration Windows
   - Snapshot de VM si environnement virtuel

3. **Documentation** :
   - Noter toutes les modifications effectuées
   - Conserver les valeurs originales
   - Plan de rollback

### Pendant les modifications

- **Principe du moindre privilège** : Droits minimums nécessaires
- **Validation des données** : Vérifier types et formats
- **Gestion d'erreurs** : Toujours vérifier les codes retour
- **Fermeture des handles** : Toujours appeler RegCloseKey

### Après les modifications

- **Vérification** : Confirmer que les changements sont corrects
- **Testing** : Tester la stabilité du système
- **Monitoring** : Surveiller les comportements anormaux
- **Restauration** : Plan B en cas de problème

## Détection de modifications malveillantes

### Outils de monitoring

- **Process Monitor (Sysinternals)** : Surveillance en temps réel
- **Registry Monitor** : Détection de modifications
- **Windows Event Logs** : Audit des accès au registre
- **EDR Solutions** : Détection comportementale

### Indicateurs de compromission (IOCs)

Modifications suspectes :
- Nouvelles entrées dans les Run Keys
- Modifications de services système
- Valeurs binaires inhabituelles
- Clés avec noms suspects ou aléatoires
- Modifications de paramètres de sécurité

## Objectifs pédagogiques

À la fin de ce module, vous devriez comprendre :
- Structure et organisation du registre Windows
- APIs de manipulation du registre
- Techniques de persistence
- Méthodes de dissimulation de données
- Détection et prévention des abus
- Restauration et récupération

## Prérequis

- Connaissance de l'architecture Windows
- Compréhension des APIs Win32
- Notions de sécurité système
- Expérience avec l'Éditeur de registre (regedit.exe)

## Environnement de test recommandé

```
Configuration idéale :
├── Machine virtuelle Windows
├── Snapshots réguliers
├── Aucune donnée importante
├── Isolation réseau
└── Backups automatiques
```

## Références

- Microsoft Documentation : Registry Functions
- Windows Internals (Russinovich, Solomon, Ionescu)
- MITRE ATT&CK : T1547 (Boot or Logon Autostart Execution)
- Registry Analysis Tools (SANS, RegRipper)

## Outils utiles

- **regedit.exe** : Éditeur graphique de registre
- **reg.exe** : Outil CLI pour le registre
- **Process Monitor** : Monitoring en temps réel
- **RegShot** : Comparaison d'états du registre
- **RegRipper** : Analyse forensique du registre

---

**RAPPEL FINAL** : Le registre Windows est critique pour la stabilité du système. Toute modification inconsidérée peut rendre le système inutilisable. Utilisez ces connaissances de manière éthique, légale et responsable, dans un environnement de test isolé avec backups appropriés.

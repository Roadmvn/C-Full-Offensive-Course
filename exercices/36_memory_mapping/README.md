# Module 36 : Memory Mapping

## Vue d'ensemble

Ce module explore les techniques de **Memory Mapping** (mappage mémoire), mécanisme puissant permettant de mapper des fichiers ou de la mémoire partagée directement dans l'espace d'adressage d'un processus. Cette technique est fondamentale pour la performance, l'IPC (Inter-Process Communication) et certaines techniques avancées d'exploitation.

## Concepts clés

### Memory Mapping - Vue générale

Le memory mapping crée une correspondance directe entre :
- **Fichiers sur disque** ↔ Mémoire virtuelle du processus
- **Mémoire physique** ↔ Mémoire virtuelle partagée entre processus

Avantages :
- **Performance** : Accès direct sans read/write syscalls
- **Efficacité** : Le noyau gère automatiquement le paging
- **Partage** : Communication inter-processus efficace
- **Simplicité** : Manipulation de fichiers comme des tableaux

### Linux : mmap()

API POSIX pour le memory mapping :

```c
void *mmap(
    void *addr,          // Adresse suggérée (NULL = choix automatique)
    size_t length,       // Taille du mapping
    int prot,            // Protection (PROT_READ, PROT_WRITE, PROT_EXEC)
    int flags,           // Flags (MAP_SHARED, MAP_PRIVATE, MAP_ANONYMOUS)
    int fd,              // File descriptor (ou -1 pour anonymous)
    off_t offset         // Offset dans le fichier
);
```

Drapeaux de protection :
- **PROT_READ** : Lecture autorisée
- **PROT_WRITE** : Écriture autorisée
- **PROT_EXEC** : Exécution autorisée
- **PROT_NONE** : Aucun accès

Drapeaux de mapping :
- **MAP_SHARED** : Modifications visibles par tous les processus
- **MAP_PRIVATE** : Modifications privées (copy-on-write)
- **MAP_ANONYMOUS** : Pas de fichier associé (mémoire pure)
- **MAP_FIXED** : Adresse exacte imposée

### Windows : CreateFileMapping / MapViewOfFile

APIs Windows équivalentes :

```c
HANDLE CreateFileMapping(
    HANDLE hFile,                      // Handle fichier ou INVALID_HANDLE_VALUE
    LPSECURITY_ATTRIBUTES lpAttributes,
    DWORD flProtect,                   // PAGE_READONLY, PAGE_READWRITE
    DWORD dwMaximumSizeHigh,          // Taille (32 bits hauts)
    DWORD dwMaximumSizeLow,           // Taille (32 bits bas)
    LPCSTR lpName                     // Nom (pour partage entre processus)
);

LPVOID MapViewOfFile(
    HANDLE hFileMappingObject,
    DWORD dwDesiredAccess,            // FILE_MAP_READ, FILE_MAP_WRITE
    DWORD dwFileOffsetHigh,
    DWORD dwFileOffsetLow,
    SIZE_T dwNumberOfBytesToMap
);
```

### Shared Memory (Mémoire partagée)

Technique IPC permettant à plusieurs processus de partager une région mémoire :

**Linux (POSIX)** :
```c
int shm_fd = shm_open("/mon_shm", O_CREAT | O_RDWR, 0666);
ftruncate(shm_fd, SIZE);
void *ptr = mmap(NULL, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
```

**Windows** :
```c
HANDLE hMapFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
                                    PAGE_READWRITE, 0, SIZE, "Global\\MySharedMem");
LPVOID pBuf = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, SIZE);
```

### File Mapping

Mapper un fichier en mémoire pour I/O rapide :

```
Fichier disque (1 GB)
    ↓ mmap()
Mémoire virtuelle processus (1 GB)
    ↓ Accès direct (pointeur)
Lecture/écriture comme un tableau
    ↓ Modifications automatiques
Fichier mis à jour sur disque
```

Avantages :
- **Pas de buffer intermédiaire** : Économie mémoire
- **Lazy loading** : Pages chargées à la demande
- **Cache du noyau** : Performances optimales
- **Accès concurrent** : Plusieurs processus simultanément

### Anonymous Mapping

Mapping sans fichier associé (mémoire pure) :

**Utilisations** :
- Allocation mémoire alternative à malloc
- Mémoire partagée entre processus (avec fork)
- Contrôle précis des permissions (RWX)
- Placement mémoire spécifique

**Linux** :
```c
void *mem = mmap(NULL, SIZE, PROT_READ | PROT_WRITE,
                MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
```

**Windows** :
```c
HANDLE hMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
                               PAGE_READWRITE, 0, SIZE, NULL);
```

### Protection Flags (RWX)

Permissions mémoire :
- **R (Read)** : Lecture autorisée
- **W (Write)** : Écriture autorisée
- **X (Execute)** : Exécution autorisée

Combinaisons courantes :
- **RW-** : Données normales
- **R-X** : Code exécutable
- **RWX** : Shellcode (suspect, détecté par DEP/NX)

Modification dynamique :
```c
// Linux
mprotect(addr, size, PROT_READ | PROT_EXEC);

// Windows
VirtualProtect(addr, size, PAGE_EXECUTE_READ, &oldProtect);
```

## ⚠️ AVERTISSEMENT LÉGAL STRICT ⚠️

### ATTENTION CRITIQUE

Le memory mapping, particulièrement avec permissions **RWX**, est utilisé dans :

**Utilisations légitimes** :
- Optimisation I/O fichiers volumineux
- IPC haute performance
- Bases de données (memory-mapped files)
- JIT compilation (langages dynamiques)

**Utilisations ILLÉGALES** :
- Injection de shellcode
- Contournement DEP/NX
- Process injection avancée
- Malware et rootkits

### Cadre légal

**INTERDICTIONS STRICTES** :
- ❌ Mapper du code malveillant en mémoire
- ❌ Injecter du code dans d'autres processus
- ❌ Contourner les protections système
- ❌ Utiliser sur systèmes sans autorisation

**AUTORISATIONS REQUISES** :
- ✅ Environnement de test isolé
- ✅ Autorisation écrite du propriétaire système
- ✅ Cadre éducatif ou de recherche légitime
- ✅ Développement d'applications légitimes

### Conséquences légales

Violation des lois sur la cybersécurité :
- **CFAA** (USA) - Computer Fraud and Abuse Act
- **Directive NIS2** (UE) - Sécurité des réseaux et systèmes d'information
- **Loi Godfrain** (France) - Articles 323-1 à 323-7
- **Computer Misuse Act** (UK)

Sanctions :
- Amendes jusqu'à plusieurs millions d'euros
- Peines de prison (jusqu'à 20 ans selon juridiction)
- Interdiction d'exercer dans l'IT
- Responsabilité civile pour dommages

### Responsabilité

**VOUS ÊTES PERSONNELLEMENT RESPONSABLE** de :
- L'utilisation de ces techniques
- La conformité aux lois locales
- L'obtention des autorisations nécessaires
- Les conséquences de vos actions

**L'auteur décline toute responsabilité** pour usage illégal.

## Utilisation éthique

### Environnement de test

```
Configuration recommandée :
├── VM Linux isolée
├── VM Windows isolée
├── Pas de réseau externe
├── Snapshots réguliers
└── Aucune donnée sensible
```

### Checklist avant utilisation

- [ ] Autorisation écrite si système non personnel
- [ ] Environnement de test isolé
- [ ] Compréhension des implications légales
- [ ] Objectifs pédagogiques clairs
- [ ] Backup complet si nécessaire

## APIs et fonctions essentielles

### Linux (POSIX)

```c
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int munmap(void *addr, size_t length);
int mprotect(void *addr, size_t len, int prot);
int msync(void *addr, size_t length, int flags);
int shm_open(const char *name, int oflag, mode_t mode);
int shm_unlink(const char *name);
```

### Windows

```c
HANDLE CreateFileMapping(...);
LPVOID MapViewOfFile(...);
BOOL UnmapViewOfFile(LPCVOID lpBaseAddress);
BOOL VirtualProtect(...);
BOOL FlushViewOfFile(...);
```

## Cas d'usage légitimes

### 1. Base de données haute performance
```c
// Mapper un fichier DB de 10 GB
void *db = mmap(NULL, 10ULL * 1024 * 1024 * 1024,
               PROT_READ | PROT_WRITE,
               MAP_SHARED, fd, 0);
// Accès direct ultra-rapide
```

### 2. Traitement d'images volumineuses
```c
// Mapper une image de 500 MB
void *image = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
// Traitement sans charger tout en RAM
```

### 3. IPC entre processus
```c
// Parent crée, enfant hérite
void *shared = mmap(NULL, SIZE, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
```

## Objectifs pédagogiques

À la fin de ce module, vous devriez comprendre :
- Mécanismes du memory mapping (Linux et Windows)
- Différences entre MAP_SHARED et MAP_PRIVATE
- Utilisation de mémoire partagée pour IPC
- Gestion des permissions mémoire (RWX)
- Performance et optimisations
- Risques de sécurité associés

## Prérequis

- Compréhension de la mémoire virtuelle
- Notions d'architecture système (Linux/Windows)
- Expérience avec la manipulation de fichiers
- Connaissance des processus et threads

## Détection et sécurité

### Protection système

**DEP/NX (Data Execution Prevention)** :
- Empêche l'exécution de code dans zones données
- Détecte tentatives de mapping RWX
- Requiert mprotect/VirtualProtect pour contournement

**ASLR (Address Space Layout Randomization)** :
- Randomise les adresses de mapping
- Complique les attaques ciblées
- MAP_FIXED peut contourner (suspect)

### Détection

Comportements suspects :
- Mapping avec PROT_EXEC sur mémoire anonyme
- Modification de permissions vers RWX
- Mapping à adresses fixes répétées
- Grands mappings anonymes

Outils :
- `/proc/[pid]/maps` (Linux)
- Process Explorer (Windows)
- Sysmon
- EDR solutions

## Références

- POSIX Programmer's Manual : mmap(2)
- Windows API Documentation : Memory Management
- Linux Kernel Documentation : Memory Mapping
- "Understanding the Linux Virtual Memory Manager" (Gorman)
- "Windows Internals" (Russinovich, Solomon, Ionescu)

---

**RAPPEL FINAL** : Le memory mapping est un outil puissant avec des implications de sécurité importantes. Utilisez ces connaissances de manière éthique, légale et responsable uniquement.

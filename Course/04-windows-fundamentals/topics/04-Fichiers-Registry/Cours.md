# Module W04 : Opérations Fichiers Windows

## Objectifs

A la fin de ce module, vous serez capable de :
- Comprendre le système de handles Windows
- Utiliser CreateFile pour ouvrir/créer des fichiers
- Lire et écrire des fichiers avec ReadFile/WriteFile
- Manipuler les attributs et métadonnées de fichiers
- Appliquer ces techniques dans un contexte Red Team

---

## 1. Système de Handles Windows

### 1.1 Qu'est-ce qu'un Handle ?

**Analogie** : Un handle est comme un **ticket de vestiaire**. Vous donnez votre manteau (fichier) au vestiaire (kernel), et on vous remet un ticket (handle). Pour récupérer votre manteau, vous montrez le ticket.

**Handle** : Un nombre entier opaque qui représente une ressource kernel (fichier, processus, thread, mutex, etc.).

```ascii
Application                   Kernel Windows
    │                              │
    │  CreateFile("file.txt")      │
    ├──────────────────────────────►│
    │                              │ Ouvre le fichier
    │                              │ Crée une structure interne
    │  ◄────────────────────────────┤
    │  HANDLE = 0x0000012C          │
    │                              │
    │  ReadFile(0x0000012C, ...)   │
    ├──────────────────────────────►│
    │                              │ Utilise handle pour accéder
    │  ◄────────────────────────────┤
    │  Données lues                 │
    │                              │
    │  CloseHandle(0x0000012C)     │
    ├──────────────────────────────►│
    │                              │ Libère la ressource
```

### 1.2 Pourquoi des Handles ?

1. **Sécurité** : L'application ne peut pas accéder directement aux structures kernel
2. **Abstraction** : Un handle peut représenter n'importe quelle ressource
3. **Gestion** : Le kernel peut suivre qui utilise quoi

### 1.3 Types de Handles Communs

| Type | Description |
|------|-------------|
| Fichier | Créé par `CreateFile` |
| Processus | Créé par `OpenProcess`, `CreateProcess` |
| Thread | Créé par `CreateThread` |
| Mutex | Créé par `CreateMutex` |
| Event | Créé par `CreateEvent` |
| Registry | Créé par `RegOpenKey` |

---

## 2. CreateFile - L'API Universelle

### 2.1 Principe

`CreateFile` est l'API **universelle** pour ouvrir/créer des fichiers, devices, pipes, etc.

**Nom trompeur** : Malgré son nom, CreateFile peut aussi **ouvrir** des fichiers existants !

### 2.2 Syntaxe

```c
HANDLE CreateFileA(
    LPCSTR                lpFileName,        // Nom du fichier
    DWORD                 dwDesiredAccess,   // GENERIC_READ, GENERIC_WRITE
    DWORD                 dwShareMode,       // FILE_SHARE_READ, etc.
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition, // CREATE_NEW, OPEN_EXISTING
    DWORD                 dwFlagsAndAttributes,  // FILE_ATTRIBUTE_NORMAL
    HANDLE                hTemplateFile
);
```

### 2.3 Paramètres Importants

**dwDesiredAccess** (accès souhaité) :
```c
GENERIC_READ       // Lecture
GENERIC_WRITE      // Écriture
GENERIC_EXECUTE    // Exécution
GENERIC_ALL        // Tout
```

**dwShareMode** (partage) :
```c
0                  // Accès exclusif (bloque autres processus)
FILE_SHARE_READ    // Autorise lecture simultanée
FILE_SHARE_WRITE   // Autorise écriture simultanée
FILE_SHARE_DELETE  // Autorise suppression
```

**dwCreationDisposition** (action) :
```c
CREATE_NEW         // Crée, échoue si existe
CREATE_ALWAYS      // Crée, écrase si existe
OPEN_EXISTING      // Ouvre, échoue si n'existe pas
OPEN_ALWAYS        // Ouvre, crée si n'existe pas
TRUNCATE_EXISTING  // Ouvre et vide, échoue si n'existe pas
```

### 2.4 Exemple Basique - Lire un Fichier

```c
#include <windows.h>
#include <stdio.h>

int main() {
    // Ouvrir un fichier en lecture
    HANDLE hFile = CreateFileA(
        "test.txt",           // Nom du fichier
        GENERIC_READ,         // Lecture seule
        FILE_SHARE_READ,      // Autorise lecture simultanée
        NULL,                 // Sécurité par défaut
        OPEN_EXISTING,        // Doit exister
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Erreur CreateFile: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Fichier ouvert: handle 0x%p\n", hFile);

    // Toujours fermer le handle !
    CloseHandle(hFile);
    return 0;
}
```

---

## 3. ReadFile et WriteFile

### 3.1 ReadFile - Lire des Données

**Syntaxe** :
```c
BOOL ReadFile(
    HANDLE       hFile,              // Handle du fichier
    LPVOID       lpBuffer,           // Buffer de destination
    DWORD        nNumberOfBytesToRead, // Taille à lire
    LPDWORD      lpNumberOfBytesRead,  // Bytes lus (out)
    LPOVERLAPPED lpOverlapped        // Pour I/O asynchrone (NULL)
);
```

**Exemple Complet** :
```c
#include <windows.h>
#include <stdio.h>

int main() {
    HANDLE hFile = CreateFileA(
        "test.txt",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Fichier introuvable\n");
        return 1;
    }

    // Buffer pour lire
    char buffer[1024] = {0};
    DWORD bytesRead;

    // Lire le fichier
    if (ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        printf("[+] Lu %lu bytes:\n", bytesRead);
        printf("%s\n", buffer);
    } else {
        printf("[-] Erreur ReadFile: %lu\n", GetLastError());
    }

    CloseHandle(hFile);
    return 0;
}
```

### 3.2 WriteFile - Écrire des Données

**Syntaxe** :
```c
BOOL WriteFile(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
);
```

**Exemple** :
```c
#include <windows.h>
#include <stdio.h>

int main() {
    // Créer/écraser un fichier
    HANDLE hFile = CreateFileA(
        "output.txt",
        GENERIC_WRITE,
        0,                    // Accès exclusif
        NULL,
        CREATE_ALWAYS,        // Crée ou écrase
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Erreur création fichier\n");
        return 1;
    }

    // Données à écrire
    const char *data = "Hello from Windows!\n";
    DWORD bytesWritten;

    if (WriteFile(hFile, data, strlen(data), &bytesWritten, NULL)) {
        printf("[+] Écrit %lu bytes\n", bytesWritten);
    } else {
        printf("[-] Erreur WriteFile: %lu\n", GetLastError());
    }

    CloseHandle(hFile);
    return 0;
}
```

---

## 4. Manipulation de Fichiers

### 4.1 GetFileSize - Taille d'un Fichier

```c
HANDLE hFile = CreateFileA("file.bin", GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

DWORD fileSize = GetFileSize(hFile, NULL);
printf("[+] Taille du fichier: %lu bytes\n", fileSize);

CloseHandle(hFile);
```

**Pour fichiers > 4 GB** :
```c
DWORD fileSizeLow, fileSizeHigh;
fileSizeLow = GetFileSize(hFile, &fileSizeHigh);

ULONGLONG totalSize = ((ULONGLONG)fileSizeHigh << 32) | fileSizeLow;
printf("[+] Taille: %llu bytes\n", totalSize);
```

### 4.2 SetFilePointer - Déplacer le Curseur

```c
// Aller au début du fichier
SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

// Avancer de 100 bytes
SetFilePointer(hFile, 100, NULL, FILE_CURRENT);

// Aller à la fin
SetFilePointer(hFile, 0, NULL, FILE_END);
```

**Exemple - Lire les 16 derniers bytes** :
```c
HANDLE hFile = CreateFileA("file.bin", GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

// Aller 16 bytes avant la fin
SetFilePointer(hFile, -16, NULL, FILE_END);

char buffer[16];
DWORD bytesRead;
ReadFile(hFile, buffer, 16, &bytesRead, NULL);

printf("[+] Derniers bytes: ");
for (int i = 0; i < bytesRead; i++) {
    printf("%02X ", (unsigned char)buffer[i]);
}
printf("\n");

CloseHandle(hFile);
```

### 4.3 GetFileTime - Timestamps

```c
HANDLE hFile = CreateFileA("file.txt", GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

FILETIME ftCreation, ftLastAccess, ftLastWrite;

if (GetFileTime(hFile, &ftCreation, &ftLastAccess, &ftLastWrite)) {
    printf("[+] Timestamps récupérés\n");

    // Convertir en temps système
    SYSTEMTIME stLastWrite;
    FileTimeToSystemTime(&ftLastWrite, &stLastWrite);

    printf("[+] Dernière modification: %02d/%02d/%04d %02d:%02d:%02d\n",
           stLastWrite.wDay, stLastWrite.wMonth, stLastWrite.wYear,
           stLastWrite.wHour, stLastWrite.wMinute, stLastWrite.wSecond);
}

CloseHandle(hFile);
```

### 4.4 SetFileTime - Modifier les Timestamps (Timestomping)

```c
// Ouvrir le fichier en écriture
HANDLE hFile = CreateFileA("file.txt", GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

// Créer un timestamp fictif (1er janvier 2020, 00:00:00)
SYSTEMTIME st = {0};
st.wYear = 2020;
st.wMonth = 1;
st.wDay = 1;

FILETIME ft;
SystemTimeToFileTime(&st, &ft);

// Modifier les timestamps
if (SetFileTime(hFile, &ft, &ft, &ft)) {
    printf("[+] Timestamps modifiés (timestomping réussi)\n");
}

CloseHandle(hFile);
```

---

## 5. Énumération de Fichiers

### 5.1 FindFirstFile / FindNextFile

```c
#include <windows.h>
#include <stdio.h>

int main() {
    WIN32_FIND_DATAA findData;
    HANDLE hFind;

    // Chercher tous les fichiers .txt
    hFind = FindFirstFileA("*.txt", &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        printf("[-] Aucun fichier trouvé\n");
        return 1;
    }

    printf("[+] Fichiers .txt trouvés:\n");
    printf("─────────────────────────────────────\n");

    do {
        // Ignorer . et ..
        if (strcmp(findData.cFileName, ".") == 0 ||
            strcmp(findData.cFileName, "..") == 0) {
            continue;
        }

        // Afficher nom et taille
        ULONGLONG fileSize = ((ULONGLONG)findData.nFileSizeHigh << 32) |
                              findData.nFileSizeLow;

        printf("%-30s %10llu bytes\n", findData.cFileName, fileSize);

    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
    return 0;
}
```

### 5.2 Énumération Récursive

```c
#include <windows.h>
#include <stdio.h>

void listFilesRecursive(const char *path, int depth) {
    char searchPath[MAX_PATH];
    snprintf(searchPath, MAX_PATH, "%s\\*", path);

    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath, &findData);

    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (strcmp(findData.cFileName, ".") == 0 ||
            strcmp(findData.cFileName, "..") == 0) {
            continue;
        }

        // Indentation selon la profondeur
        for (int i = 0; i < depth; i++) printf("  ");

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            printf("[DIR]  %s\n", findData.cFileName);

            // Récursion dans le sous-dossier
            char subPath[MAX_PATH];
            snprintf(subPath, MAX_PATH, "%s\\%s", path, findData.cFileName);
            listFilesRecursive(subPath, depth + 1);
        } else {
            printf("[FILE] %s\n", findData.cFileName);
        }

    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
}

int main() {
    printf("[+] Énumération récursive:\n");
    listFilesRecursive(".", 0);
    return 0;
}
```

---

## 6. Suppression et Déplacement

### 6.1 DeleteFile - Supprimer un Fichier

```c
if (DeleteFileA("file.txt")) {
    printf("[+] Fichier supprimé\n");
} else {
    printf("[-] Erreur suppression: %lu\n", GetLastError());
}
```

### 6.2 MoveFile - Déplacer/Renommer

```c
// Renommer
if (MoveFileA("old.txt", "new.txt")) {
    printf("[+] Fichier renommé\n");
}

// Déplacer
if (MoveFileA("file.txt", "C:\\Temp\\file.txt")) {
    printf("[+] Fichier déplacé\n");
}
```

### 6.3 CopyFile - Copier

```c
// Copier un fichier
if (CopyFileA("source.txt", "dest.txt", FALSE)) {
    printf("[+] Fichier copié\n");
}

// FALSE = écrase si existe, TRUE = échoue si existe
```

---

## 7. Attributs de Fichiers

### 7.1 GetFileAttributes

```c
DWORD attrs = GetFileAttributesA("file.txt");

if (attrs != INVALID_FILE_ATTRIBUTES) {
    if (attrs & FILE_ATTRIBUTE_HIDDEN) {
        printf("[+] Fichier caché\n");
    }
    if (attrs & FILE_ATTRIBUTE_READONLY) {
        printf("[+] Fichier en lecture seule\n");
    }
    if (attrs & FILE_ATTRIBUTE_SYSTEM) {
        printf("[+] Fichier système\n");
    }
}
```

### 7.2 SetFileAttributes - Rendre un Fichier Caché

```c
// Ajouter l'attribut caché
DWORD attrs = GetFileAttributesA("secret.txt");
attrs |= FILE_ATTRIBUTE_HIDDEN;

if (SetFileAttributesA("secret.txt", attrs)) {
    printf("[+] Fichier maintenant caché\n");
}
```

---

## 8. Applications Offensives

### 8.1 Contexte Red Team

Les opérations fichiers sont cruciales pour :

1. **Exfiltration** : Lire des fichiers sensibles (credentials, configs)
2. **Persistence** : Modifier des fichiers de démarrage
3. **Timestomping** : Cacher l'heure de modification d'un fichier
4. **Fichiers Cachés** : Cacher des outils avec `FILE_ATTRIBUTE_HIDDEN`
5. **Alternate Data Streams (ADS)** : Cacher des données dans les streams NTFS

### 8.2 Exemple - Exfiltration de Fichier

```c
#include <windows.h>
#include <stdio.h>

// Lire un fichier et l'encoder en base64 (simplifié)
void exfiltrateFile(const char *filename) {
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Impossible d'ouvrir %s\n", filename);
        return;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    char *buffer = (char*)malloc(fileSize + 1);

    DWORD bytesRead;
    if (ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
        buffer[bytesRead] = '\0';

        printf("[+] Fichier lu: %s (%lu bytes)\n", filename, bytesRead);
        printf("[*] Contenu (premiers 100 bytes):\n%.100s\n", buffer);

        // Ici : envoyer via HTTP, DNS, etc.
    }

    free(buffer);
    CloseHandle(hFile);
}

int main() {
    // Exemple : exfiltrer un fichier de configuration
    exfiltrateFile("C:\\Users\\Public\\config.ini");
    return 0;
}
```

### 8.3 Alternate Data Streams (ADS)

**Principe** : NTFS permet de stocker des flux de données alternatifs invisibles.

**Créer un ADS** :
```c
// Écrire dans un ADS nommé "hidden"
HANDLE hFile = CreateFileA(
    "normal.txt:hidden",  // filename:stream_name
    GENERIC_WRITE,
    0,
    NULL,
    CREATE_ALWAYS,
    FILE_ATTRIBUTE_NORMAL,
    NULL
);

const char *secret = "Secret data hidden in ADS";
DWORD written;
WriteFile(hFile, secret, strlen(secret), &written, NULL);
CloseHandle(hFile);

printf("[+] Données cachées dans ADS normal.txt:hidden\n");
```

**Lire un ADS** :
```c
HANDLE hFile = CreateFileA("normal.txt:hidden", GENERIC_READ,
                           FILE_SHARE_READ, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);

char buffer[256] = {0};
DWORD bytesRead;
ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL);

printf("[+] ADS lu: %s\n", buffer);
CloseHandle(hFile);
```

### 8.4 Timestomping - Anti-Forensics

```c
#include <windows.h>
#include <stdio.h>

void timestomp(const char *filename, const char *referenceFile) {
    // Lire les timestamps d'un fichier légitime
    HANDLE hRef = CreateFileA(referenceFile, GENERIC_READ, FILE_SHARE_READ,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    FILETIME ftCreation, ftAccess, ftWrite;
    GetFileTime(hRef, &ftCreation, &ftAccess, &ftWrite);
    CloseHandle(hRef);

    // Appliquer au fichier suspect
    HANDLE hTarget = CreateFileA(filename, GENERIC_WRITE, 0, NULL,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (SetFileTime(hTarget, &ftCreation, &ftAccess, &ftWrite)) {
        printf("[+] Timestamps clonés: %s -> %s\n", referenceFile, filename);
    }

    CloseHandle(hTarget);
}

int main() {
    // Cloner les timestamps de notepad.exe sur notre malware
    timestomp("malware.exe", "C:\\Windows\\System32\\notepad.exe");
    return 0;
}
```

### 8.5 Considérations OPSEC

**Problèmes détectés** :

1. **Ouverture de fichiers sensibles** : EDR surveille l'accès à SAM, SYSTEM, etc.
   - **Solution** : Utiliser des techniques de shadow copy

2. **Création de fichiers suspects** : Fichiers dans des dossiers système
   - **Solution** : Utiliser des emplacements légitimes (%TEMP%, %APPDATA%)

3. **Modification de timestamps** : Peut être détecté par analyse forensique
   - **Solution** : Cloner des timestamps réalistes

---

## 9. Checklist

- [ ] Comprendre le concept de handles
- [ ] Ouvrir/créer des fichiers avec `CreateFile`
- [ ] Lire et écrire avec `ReadFile`/`WriteFile`
- [ ] Manipuler les timestamps (timestomping)
- [ ] Énumérer des fichiers avec `FindFirstFile`
- [ ] Utiliser les Alternate Data Streams
- [ ] Comprendre les implications OPSEC

---

## 10. Exercices

Voir [exercice.md](exercice.md)

---

## 11. Ressources Complémentaires

- [MSDN - CreateFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)
- [MSDN - ReadFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile)
- [MSDN - File Management](https://docs.microsoft.com/en-us/windows/win32/fileio/file-management)
- [Alternate Data Streams](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e2b19412-a925-4360-b009-86e3b8a020c8)

---

**Navigation**
- [Module précédent](../W03_memory_windows/)
- [Module suivant](../W05_registry/)

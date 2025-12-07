# Module W04 : Opérations Fichiers Windows - Solutions

## Solution Exercice 1 : Lire un fichier avec CreateFile et ReadFile

**Objectif** : Ouvrir et lire le contenu d'un fichier texte

```c
#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <fichier>\n", argv[0]);
        return 1;
    }

    printf("[*] === Exercice 1 : Lecture de fichier ===\n\n");

    // 1. Ouvrir le fichier en lecture
    HANDLE hFile = CreateFileA(
        argv[1],              // Nom du fichier
        GENERIC_READ,         // Lecture seule
        FILE_SHARE_READ,      // Autoriser lecture simultanee
        NULL,                 // Securite par defaut
        OPEN_EXISTING,        // Le fichier doit exister
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Impossible d'ouvrir le fichier: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Fichier ouvert: %s\n", argv[1]);

    // 2. Obtenir la taille du fichier
    DWORD fileSize = GetFileSize(hFile, NULL);
    printf("[+] Taille: %lu bytes\n", fileSize);

    // 3. Allouer un buffer
    char *buffer = (char*)malloc(fileSize + 1);
    if (!buffer) {
        printf("[-] Allocation memoire echouee\n");
        CloseHandle(hFile);
        return 1;
    }

    // 4. Lire le fichier
    DWORD bytesRead;
    if (ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
        buffer[bytesRead] = '\0';
        printf("[+] Lu %lu bytes:\n\n", bytesRead);
        printf("=== CONTENU ===\n%s\n", buffer);
    } else {
        printf("[-] ReadFile echoue: %lu\n", GetLastError());
    }

    // 5. Nettoyer
    free(buffer);
    CloseHandle(hFile);

    return 0;
}
```

**Explications** :
- `CreateFileA` ouvre le fichier et retourne un handle
- `GENERIC_READ` : accès en lecture seule
- `FILE_SHARE_READ` : d'autres processus peuvent lire le fichier simultanément
- `OPEN_EXISTING` : échoue si le fichier n'existe pas

---

## Solution Exercice 2 : Écrire dans un fichier

**Objectif** : Créer un fichier et y écrire du texte

```c
#include <windows.h>
#include <stdio.h>

int main() {
    printf("[*] === Exercice 2 : Ecriture de fichier ===\n\n");

    // 1. Créer/écraser un fichier
    HANDLE hFile = CreateFileA(
        "output.txt",
        GENERIC_WRITE,
        0,                    // Acces exclusif
        NULL,
        CREATE_ALWAYS,        // Cree ou ecrase
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile echoue: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Fichier cree: output.txt\n");

    // 2. Données à écrire
    const char *data = "Bonjour depuis Windows API!\r\n"
                       "Deuxieme ligne de texte.\r\n"
                       "Fin du fichier.\r\n";

    DWORD bytesWritten;
    if (WriteFile(hFile, data, strlen(data), &bytesWritten, NULL)) {
        printf("[+] Ecrit %lu bytes\n", bytesWritten);
    } else {
        printf("[-] WriteFile echoue: %lu\n", GetLastError());
    }

    CloseHandle(hFile);

    // 3. Vérifier en relisant
    hFile = CreateFileA("output.txt", GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        char buffer[256] = {0};
        DWORD bytesRead;
        ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
        printf("\n[+] Verification (contenu lu):\n%s\n", buffer);
        CloseHandle(hFile);
    }

    return 0;
}
```

**Explications** :
- `CREATE_ALWAYS` : crée le fichier ou l'écrase s'il existe déjà
- `GENERIC_WRITE` : accès en écriture seule
- Accès exclusif (0) : empêche les autres processus d'accéder au fichier

---

## Solution Exercice 3 : Énumération de fichiers

**Objectif** : Lister tous les fichiers d'un répertoire

```c
#include <windows.h>
#include <stdio.h>

void ListFiles(const char *path) {
    WIN32_FIND_DATAA findData;
    HANDLE hFind;
    char searchPath[MAX_PATH];

    snprintf(searchPath, MAX_PATH, "%s\\*", path);

    hFind = FindFirstFileA(searchPath, &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        printf("[-] Aucun fichier trouve dans %s\n", path);
        return;
    }

    printf("[+] Fichiers dans %s:\n\n", path);
    printf("%-40s %15s %10s\n", "Nom", "Taille", "Type");
    printf("--------------------------------------------------------------------\n");

    do {
        // Ignorer . et ..
        if (strcmp(findData.cFileName, ".") == 0 ||
            strcmp(findData.cFileName, "..") == 0) {
            continue;
        }

        // Taille du fichier
        ULONGLONG fileSize = ((ULONGLONG)findData.nFileSizeHigh << 32) |
                              findData.nFileSizeLow;

        // Type
        const char *type = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                           ? "DIR" : "FILE";

        printf("%-40s %15llu %10s\n", findData.cFileName, fileSize, type);

    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
}

int main(int argc, char *argv[]) {
    printf("[*] === Exercice 3 : Enumeration de fichiers ===\n\n");

    const char *path = (argc > 1) ? argv[1] : ".";
    ListFiles(path);

    return 0;
}
```

**Explications** :
- `FindFirstFileA` : commence l'énumération
- `FindNextFileA` : itère sur les fichiers suivants
- `FILE_ATTRIBUTE_DIRECTORY` : distingue les dossiers des fichiers
- Toujours ignorer `.` et `..` pour éviter les boucles infinies

---

## Solution Exercice 4 : Timestomping - Modification des timestamps

**Objectif** : Cloner les timestamps d'un fichier légitime sur un fichier suspect

```c
#include <windows.h>
#include <stdio.h>

void PrintFileTime(const char *label, FILETIME *ft) {
    SYSTEMTIME st;
    FileTimeToSystemTime(ft, &st);
    printf("%s: %04d-%02d-%02d %02d:%02d:%02d\n",
           label,
           st.wYear, st.wMonth, st.wDay,
           st.wHour, st.wMinute, st.wSecond);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <fichier_source> <fichier_cible>\n", argv[0]);
        printf("Exemple: %s C:\\Windows\\notepad.exe malware.exe\n", argv[0]);
        return 1;
    }

    printf("[*] === Exercice 4 : Timestomping ===\n\n");

    const char *sourceFile = argv[1];
    const char *targetFile = argv[2];

    // 1. Lire les timestamps du fichier source
    HANDLE hSource = CreateFileA(
        sourceFile,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hSource == INVALID_HANDLE_VALUE) {
        printf("[-] Impossible d'ouvrir le fichier source: %lu\n", GetLastError());
        return 1;
    }

    FILETIME ftCreation, ftAccess, ftWrite;
    if (!GetFileTime(hSource, &ftCreation, &ftAccess, &ftWrite)) {
        printf("[-] GetFileTime echoue: %lu\n", GetLastError());
        CloseHandle(hSource);
        return 1;
    }

    printf("[+] Timestamps du fichier source (%s):\n", sourceFile);
    PrintFileTime("  Creation    ", &ftCreation);
    PrintFileTime("  Dernier acces", &ftAccess);
    PrintFileTime("  Modification ", &ftWrite);
    printf("\n");

    CloseHandle(hSource);

    // 2. Appliquer au fichier cible
    HANDLE hTarget = CreateFileA(
        targetFile,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hTarget == INVALID_HANDLE_VALUE) {
        printf("[-] Impossible d'ouvrir le fichier cible: %lu\n", GetLastError());
        return 1;
    }

    if (SetFileTime(hTarget, &ftCreation, &ftAccess, &ftWrite)) {
        printf("[+] Timestamps clones sur %s avec succes!\n", targetFile);

        // Vérification
        FILETIME ftNewCreation, ftNewAccess, ftNewWrite;
        GetFileTime(hTarget, &ftNewCreation, &ftNewAccess, &ftNewWrite);
        printf("\n[+] Nouveaux timestamps de %s:\n", targetFile);
        PrintFileTime("  Creation    ", &ftNewCreation);
        PrintFileTime("  Dernier acces", &ftNewAccess);
        PrintFileTime("  Modification ", &ftNewWrite);
    } else {
        printf("[-] SetFileTime echoue: %lu\n", GetLastError());
    }

    CloseHandle(hTarget);

    return 0;
}
```

**Explications** :
- `GetFileTime` : récupère les 3 timestamps (création, accès, modification)
- `SetFileTime` : modifie les timestamps d'un fichier
- Technique anti-forensics pour masquer l'heure de dépôt d'un malware
- Cloner les timestamps d'un binaire système légitime rend le fichier suspect moins visible

---

## Solution Exercice 5 : Alternate Data Streams (ADS)

**Objectif** : Cacher des données dans un flux alternatif NTFS

```c
#include <windows.h>
#include <stdio.h>

int main() {
    printf("[*] === Exercice 5 : Alternate Data Streams ===\n\n");

    // 1. Créer un fichier normal
    HANDLE hFile = CreateFileA(
        "document.txt",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    const char *visibleData = "Ceci est un document normal.\r\n";
    DWORD written;
    WriteFile(hFile, visibleData, strlen(visibleData), &written, NULL);
    CloseHandle(hFile);
    printf("[+] Fichier principal cree: document.txt (%lu bytes)\n", written);

    // 2. Créer un ADS caché
    hFile = CreateFileA(
        "document.txt:hidden",  // filename:stream_name
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    const char *secretData = "SECRET: Donnees cachees dans l'ADS!\r\n"
                             "Invisible dans l'explorateur Windows.\r\n";
    WriteFile(hFile, secretData, strlen(secretData), &written, NULL);
    CloseHandle(hFile);
    printf("[+] ADS cree: document.txt:hidden (%lu bytes)\n\n", written);

    // 3. Lire le fichier principal
    hFile = CreateFileA("document.txt", GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    char buffer[256] = {0};
    DWORD bytesRead;
    ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
    printf("[+] Contenu visible (document.txt):\n%s\n", buffer);
    CloseHandle(hFile);

    // 4. Lire l'ADS
    hFile = CreateFileA("document.txt:hidden", GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    memset(buffer, 0, sizeof(buffer));
    ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
    printf("[+] Contenu cache (ADS document.txt:hidden):\n%s\n", buffer);
    CloseHandle(hFile);

    printf("[*] Verification:\n");
    printf("    dir document.txt          -> Montre la taille du fichier principal\n");
    printf("    dir /R document.txt       -> Montre aussi les ADS caches\n");
    printf("    type document.txt:hidden  -> Affiche le contenu de l'ADS\n");

    return 0;
}
```

**Explications** :
- Les ADS sont une fonctionnalité NTFS invisible dans l'explorateur Windows
- Syntaxe : `filename:stream_name`
- Utilisés pour cacher des payloads, configurations, données exfiltrées
- La commande `dir /R` permet de détecter les ADS

---

## Auto-évaluation

Avant de passer au module suivant, vérifiez que vous pouvez :
- [x] Ouvrir/créer des fichiers avec CreateFile
- [x] Lire et écrire des données avec ReadFile/WriteFile
- [x] Énumérer des fichiers avec FindFirstFile/FindNextFile
- [x] Manipuler les timestamps (timestomping anti-forensics)
- [x] Utiliser les Alternate Data Streams pour cacher des données
- [x] Comprendre les implications OPSEC (accès à des fichiers sensibles, artefacts)

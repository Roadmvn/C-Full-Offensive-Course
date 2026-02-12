/*
 * OBJECTIF  : Maitriser les operations fichiers Windows (CreateFile, ReadFile, WriteFile)
 * PREREQUIS : Bases du C, API Windows
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Ce programme demontre les operations sur fichiers avec l'API Windows :
 * - Creation, lecture, ecriture de fichiers
 * - Attributs et metadata
 * - Alternate Data Streams (ADS) - utilise pour la persistence
 * - File mapping (memoire partagee)
 */

#include <windows.h>
#include <stdio.h>

/* Demo 1 : Operations basiques sur les fichiers */
void demo_file_ops(void) {
    printf("[1] Operations fichiers basiques\n\n");

    const char* filename = "demo_test.txt";

    /* Creer et ecrire */
    HANDLE hFile = CreateFileA(filename, GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("    [-] CreateFile echoue (err %lu)\n", GetLastError());
        return;
    }

    const char* data = "Ceci est un test de l'API fichiers Windows.\r\n";
    DWORD written;
    WriteFile(hFile, data, (DWORD)strlen(data), &written, NULL);
    printf("    [+] Ecrit %lu octets dans %s\n", written, filename);
    CloseHandle(hFile);

    /* Lire le fichier */
    hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL,
                         OPEN_EXISTING, 0, NULL);
    char buffer[256] = {0};
    DWORD read;
    ReadFile(hFile, buffer, sizeof(buffer) - 1, &read, NULL);
    printf("    [+] Lu %lu octets : \"%s\"\n", read, buffer);

    /* Taille du fichier */
    LARGE_INTEGER size;
    GetFileSizeEx(hFile, &size);
    printf("    [+] Taille : %lld octets\n", size.QuadPart);
    CloseHandle(hFile);

    /* Attributs du fichier */
    DWORD attrs = GetFileAttributesA(filename);
    printf("    [+] Attributs : 0x%lX", attrs);
    if (attrs & FILE_ATTRIBUTE_ARCHIVE)   printf(" [ARCHIVE]");
    if (attrs & FILE_ATTRIBUTE_HIDDEN)    printf(" [HIDDEN]");
    if (attrs & FILE_ATTRIBUTE_SYSTEM)    printf(" [SYSTEM]");
    if (attrs & FILE_ATTRIBUTE_READONLY)  printf(" [READONLY]");
    printf("\n");

    /* Supprimer le fichier */
    DeleteFileA(filename);
    printf("    [+] Fichier supprime\n\n");
}

/* Demo 2 : Alternate Data Streams (ADS) */
void demo_ads(void) {
    printf("[2] Alternate Data Streams (ADS)\n\n");

    printf("    [*] Les ADS permettent de cacher des donnees dans un fichier\n");
    printf("    [*] sans modifier sa taille visible dans l'explorateur.\n\n");

    const char* host_file = "ads_demo.txt";
    const char* ads_name = "ads_demo.txt:hidden_payload";

    /* Creer le fichier hote */
    HANDLE hFile = CreateFileA(host_file, GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    const char* visible = "Contenu visible normal\r\n";
    DWORD written;
    WriteFile(hFile, visible, (DWORD)strlen(visible), &written, NULL);
    CloseHandle(hFile);
    printf("    [+] Fichier hote cree : %s (%lu octets)\n", host_file, written);

    /* Ecrire dans un ADS (stream cache) */
    HANDLE hAds = CreateFileA(ads_name, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hAds != INVALID_HANDLE_VALUE) {
        const char* hidden = "PAYLOAD_CACHE_DANS_ADS";
        WriteFile(hAds, hidden, (DWORD)strlen(hidden), &written, NULL);
        CloseHandle(hAds);
        printf("    [+] ADS ecrit : %s (%lu octets)\n", ads_name, written);

        /* Lire depuis l'ADS */
        hAds = CreateFileA(ads_name, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
        char buf[256] = {0};
        DWORD read;
        ReadFile(hAds, buf, sizeof(buf) - 1, &read, NULL);
        CloseHandle(hAds);
        printf("    [+] ADS lu : \"%s\"\n", buf);

        printf("    [!] L'ADS n'est PAS visible avec 'dir'\n");
        printf("    [!] Pour le voir : dir /R ou streams.exe (Sysinternals)\n");
    }

    DeleteFileA(host_file);
    printf("\n");
}

/* Demo 3 : File Mapping (memoire partagee) */
void demo_file_mapping(void) {
    printf("[3] File Mapping (memoire partagee)\n\n");

    /* Creer un file mapping anonyme (pas lie a un fichier) */
    HANDLE hMapping = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL,
                                          PAGE_READWRITE, 0, 4096,
                                          "Local\\DemoSharedMemory");
    if (!hMapping) {
        printf("    [-] CreateFileMapping echoue (err %lu)\n", GetLastError());
        return;
    }
    printf("    [+] File mapping cree : %p\n", hMapping);

    /* Mapper la vue en memoire */
    LPVOID view = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 4096);
    if (view) {
        printf("    [+] Vue mappee a : %p\n", view);

        /* Ecrire dans la memoire partagee */
        strcpy((char*)view, "Donnees partagees entre processus!");
        printf("    [+] Ecrit : \"%s\"\n", (char*)view);
        printf("    [*] Un autre processus peut ouvrir ce mapping par son nom\n");
        printf("    [*] et lire les memes donnees (IPC)\n");

        UnmapViewOfFile(view);
    }

    CloseHandle(hMapping);
    printf("\n");
}

/* Demo 4 : Enumeration de repertoire */
void demo_directory_enum(void) {
    printf("[4] Enumeration de repertoire\n\n");

    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA("C:\\Windows\\System32\\*.dll", &ffd);

    if (hFind == INVALID_HANDLE_VALUE) {
        printf("    [-] FindFirstFile echoue\n");
        return;
    }

    int count = 0;
    printf("    Premieres DLLs dans System32 :\n");
    do {
        if (count < 10) {
            LARGE_INTEGER size;
            size.HighPart = ffd.nFileSizeHigh;
            size.LowPart = ffd.nFileSizeLow;
            printf("    %-30s  %8lld KB\n", ffd.cFileName, size.QuadPart / 1024);
        }
        count++;
    } while (FindNextFileA(hFind, &ffd));

    FindClose(hFind);
    printf("    ... Total : %d fichiers .dll trouves\n\n", count);
}

int main(void) {
    printf("[*] Demo : Operations fichiers Windows\n");
    printf("[*] ==========================================\n\n");

    demo_file_ops();
    demo_ads();
    demo_file_mapping();
    demo_directory_enum();

    printf("[+] Exemple termine avec succes\n");
    return 0;
}

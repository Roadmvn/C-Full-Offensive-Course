/*
 * ═══════════════════════════════════════════════════════════════════
 * Module 36 : Memory Mapping - Mappage Mémoire Multi-plateforme
 * ═══════════════════════════════════════════════════════════════════
 *
 * ⚠️  AVERTISSEMENT LÉGAL STRICT ⚠️
 *
 * Ce code démontre des techniques de memory mapping qui peuvent être
 * utilisées de manière légitime ou malveillante.
 *
 * UTILISATIONS LÉGALES UNIQUEMENT :
 * - Environnement de test isolé avec autorisation
 * - Développement d'applications légitimes
 * - Recherche académique éthique
 * - Optimisation I/O fichiers
 *
 * L'utilisation pour injection de code, shellcode ou contournement
 * de protections système est ILLÉGALE et peut entraîner des poursuites.
 *
 * L'auteur décline toute responsabilité pour usage illégal.
 * ═══════════════════════════════════════════════════════════════════
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <windows.h>
    #define PLATFORM "Windows"
#else
    #include <sys/mman.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
    #define PLATFORM "Linux/POSIX"
#endif

#define SEPARATEUR "═══════════════════════════════════════════════════════════════════\n"
#define SHARED_SIZE 4096

// ═══════════════════════════════════════════════════════════════════
// Prototypes de fonctions
// ═══════════════════════════════════════════════════════════════════

void afficher_titre(const char *titre);
void demonstrer_file_mapping();
void demonstrer_anonymous_mapping();
void demonstrer_shared_memory();
void demonstrer_permissions_rwx();

// ═══════════════════════════════════════════════════════════════════
// Fonction : Afficher un titre formaté
// ═══════════════════════════════════════════════════════════════════

void afficher_titre(const char *titre) {
    printf("\n");
    printf(SEPARATEUR);
    printf("  %s\n", titre);
    printf(SEPARATEUR);
}

// ═══════════════════════════════════════════════════════════════════
// Démonstration 1 : File Mapping (mappage de fichier)
// ═══════════════════════════════════════════════════════════════════

void demonstrer_file_mapping() {
    afficher_titre("DÉMONSTRATION 1 : File Mapping");

    printf("\n[*] Création d'un fichier de test...\n");

    const char *filename = "test_mapping.dat";
    const char *data = "Ceci est un fichier de test pour memory mapping.\n"
                       "Les modifications en mémoire seront reflétées sur disque.\n";

#ifdef _WIN32
    // === WINDOWS ===
    HANDLE hFile, hMapping;
    LPVOID pData;

    // Créer et écrire le fichier
    hFile = CreateFile(filename, GENERIC_READ | GENERIC_WRITE,
                      0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Échec création fichier : %lu\n", GetLastError());
        return;
    }

    DWORD written;
    WriteFile(hFile, data, strlen(data), &written, NULL);

    printf("[+] Fichier créé : %s (%lu bytes)\n", filename, written);

    // Créer le mapping
    hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (!hMapping) {
        printf("[-] Échec CreateFileMapping : %lu\n", GetLastError());
        CloseHandle(hFile);
        return;
    }

    printf("[+] File mapping object créé\n");

    // Mapper la vue
    pData = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!pData) {
        printf("[-] Échec MapViewOfFile : %lu\n", GetLastError());
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

    printf("[+] Fichier mappé en mémoire à l'adresse : %p\n", pData);

    // Afficher le contenu
    printf("\n[*] Contenu du mapping :\n");
    printf("%s\n", (char*)pData);

    // Modifier en mémoire
    printf("[*] Modification du contenu en mémoire...\n");
    strcpy((char*)pData + 50, "[MODIFIÉ VIA MEMORY MAPPING]");

    // Synchroniser avec le disque
    FlushViewOfFile(pData, 0);
    printf("[+] Modifications synchronisées sur disque\n");

    // Nettoyer
    UnmapViewOfFile(pData);
    CloseHandle(hMapping);
    CloseHandle(hFile);

#else
    // === LINUX/POSIX ===
    int fd;
    void *map;
    struct stat sb;

    // Créer et écrire le fichier
    fd = open(filename, O_RDWR | O_CREAT, 0666);
    if (fd == -1) {
        perror("[-] Échec open");
        return;
    }

    write(fd, data, strlen(data));
    printf("[+] Fichier créé : %s (%zu bytes)\n", filename, strlen(data));

    // Récupérer la taille
    if (fstat(fd, &sb) == -1) {
        perror("[-] Échec fstat");
        close(fd);
        return;
    }

    // Mapper le fichier
    map = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        perror("[-] Échec mmap");
        close(fd);
        return;
    }

    printf("[+] Fichier mappé en mémoire à l'adresse : %p\n", map);

    // Afficher le contenu
    printf("\n[*] Contenu du mapping :\n");
    printf("%s\n", (char*)map);

    // Modifier en mémoire
    printf("[*] Modification du contenu en mémoire...\n");
    strcpy((char*)map + 50, "[MODIFIÉ VIA MEMORY MAPPING]");

    // Synchroniser avec le disque
    msync(map, sb.st_size, MS_SYNC);
    printf("[+] Modifications synchronisées sur disque\n");

    // Nettoyer
    munmap(map, sb.st_size);
    close(fd);
#endif

    printf("\n[+] Le fichier %s a été modifié via memory mapping\n", filename);
    printf("[+] Vérifiez son contenu avec : cat %s\n", filename);
}

// ═══════════════════════════════════════════════════════════════════
// Démonstration 2 : Anonymous Mapping (mémoire sans fichier)
// ═══════════════════════════════════════════════════════════════════

void demonstrer_anonymous_mapping() {
    afficher_titre("DÉMONSTRATION 2 : Anonymous Mapping");

    printf("\n[*] Allocation de mémoire via anonymous mapping...\n");

    size_t size = 8192;  // 8 KB
    void *mem;

#ifdef _WIN32
    // === WINDOWS ===
    HANDLE hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
                                       PAGE_READWRITE, 0, size, NULL);
    if (!hMapping) {
        printf("[-] Échec CreateFileMapping : %lu\n", GetLastError());
        return;
    }

    mem = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, size);
    if (!mem) {
        printf("[-] Échec MapViewOfFile : %lu\n", GetLastError());
        CloseHandle(hMapping);
        return;
    }

    printf("[+] Mémoire anonyme mappée : %p (%zu bytes)\n", mem, size);

    // Écrire dans la mémoire
    sprintf((char*)mem, "Ceci est une mémoire anonyme mappée (Windows)");
    printf("[+] Données écrites : %s\n", (char*)mem);

    // Nettoyer
    UnmapViewOfFile(mem);
    CloseHandle(hMapping);

#else
    // === LINUX/POSIX ===
    mem = mmap(NULL, size, PROT_READ | PROT_WRITE,
              MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if (mem == MAP_FAILED) {
        perror("[-] Échec mmap");
        return;
    }

    printf("[+] Mémoire anonyme mappée : %p (%zu bytes)\n", mem, size);

    // Écrire dans la mémoire
    sprintf((char*)mem, "Ceci est une mémoire anonyme mappée (Linux)");
    printf("[+] Données écrites : %s\n", (char*)mem);

    // Nettoyer
    munmap(mem, size);
#endif

    printf("[+] Anonymous mapping libéré\n");
}

// ═══════════════════════════════════════════════════════════════════
// Démonstration 3 : Shared Memory (mémoire partagée IPC)
// ═══════════════════════════════════════════════════════════════════

void demonstrer_shared_memory() {
    afficher_titre("DÉMONSTRATION 3 : Shared Memory IPC");

    printf("\n[*] Démonstration de mémoire partagée entre processus...\n");

#ifdef _WIN32
    // === WINDOWS ===
    const char *shm_name = "Global\\MySharedMemory";

    HANDLE hMapFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
                                       PAGE_READWRITE, 0, SHARED_SIZE, shm_name);

    if (!hMapFile) {
        printf("[-] Échec CreateFileMapping : %lu\n", GetLastError());
        return;
    }

    BOOL existed = (GetLastError() == ERROR_ALREADY_EXISTS);

    LPVOID pBuf = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, SHARED_SIZE);
    if (!pBuf) {
        printf("[-] Échec MapViewOfFile : %lu\n", GetLastError());
        CloseHandle(hMapFile);
        return;
    }

    if (existed) {
        printf("[+] Mémoire partagée existante ouverte : %s\n", shm_name);
        printf("[+] Contenu : %s\n", (char*)pBuf);
    } else {
        printf("[+] Nouvelle mémoire partagée créée : %s\n", shm_name);
        sprintf((char*)pBuf, "Message depuis le processus PID %lu", GetCurrentProcessId());
        printf("[+] Message écrit : %s\n", (char*)pBuf);
    }

    printf("\n[*] La mémoire partagée est accessible à d'autres processus\n");
    printf("[*] Lancez ce programme dans un autre terminal pour voir le partage\n");

    UnmapViewOfFile(pBuf);
    CloseHandle(hMapFile);

#else
    // === LINUX/POSIX ===
    const char *shm_name = "/my_shared_memory";

    int shm_fd = shm_open(shm_name, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("[-] Échec shm_open");
        return;
    }

    // Définir la taille
    if (ftruncate(shm_fd, SHARED_SIZE) == -1) {
        perror("[-] Échec ftruncate");
        close(shm_fd);
        return;
    }

    void *ptr = mmap(NULL, SHARED_SIZE, PROT_READ | PROT_WRITE,
                    MAP_SHARED, shm_fd, 0);

    if (ptr == MAP_FAILED) {
        perror("[-] Échec mmap");
        close(shm_fd);
        return;
    }

    printf("[+] Mémoire partagée créée : %s\n", shm_name);

    // Vérifier si déjà des données
    if (strlen((char*)ptr) > 0) {
        printf("[+] Contenu existant : %s\n", (char*)ptr);
    } else {
        sprintf((char*)ptr, "Message depuis le processus PID %d", getpid());
        printf("[+] Message écrit : %s\n", (char*)ptr);
    }

    printf("\n[*] La mémoire partagée est accessible à d'autres processus\n");
    printf("[*] Lancez ce programme dans un autre terminal pour voir le partage\n");

    munmap(ptr, SHARED_SIZE);
    close(shm_fd);
    // Note : shm_unlink() pour supprimer définitivement
#endif
}

// ═══════════════════════════════════════════════════════════════════
// Démonstration 4 : Permissions mémoire (RWX)
// ═══════════════════════════════════════════════════════════════════

void demonstrer_permissions_rwx() {
    afficher_titre("DÉMONSTRATION 4 : Permissions Mémoire RWX");

    printf("\n[*] Démonstration de modification de permissions mémoire\n");
    printf("    ⚠️  Attention : RWX est suspect et détecté par DEP/NX\n\n");

    size_t size = 4096;
    void *mem;

#ifdef _WIN32
    // === WINDOWS ===
    HANDLE hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
                                       PAGE_EXECUTE_READWRITE, 0, size, NULL);
    if (!hMapping) {
        printf("[-] Échec CreateFileMapping : %lu\n", GetLastError());
        printf("    Probablement bloqué par DEP (Data Execution Prevention)\n");
        return;
    }

    mem = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, size);
    if (!mem) {
        printf("[-] Échec MapViewOfFile : %lu\n", GetLastError());
        CloseHandle(hMapping);
        return;
    }

    printf("[+] Mémoire RWX allouée : %p\n", mem);
    printf("[+] Permissions : PAGE_EXECUTE_READWRITE\n");

    // Écrire des données
    strcpy((char*)mem, "Zone mémoire avec permissions RWX");
    printf("[+] Données écrites : %s\n", (char*)mem);

    UnmapViewOfFile(mem);
    CloseHandle(hMapping);

#else
    // === LINUX/POSIX ===
    mem = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
              MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if (mem == MAP_FAILED) {
        perror("[-] Échec mmap avec PROT_EXEC");
        printf("    Probablement bloqué par NX (No-eXecute)\n");
        return;
    }

    printf("[+] Mémoire RWX allouée : %p\n", mem);
    printf("[+] Permissions : PROT_READ | PROT_WRITE | PROT_EXEC\n");

    // Écrire des données
    strcpy((char*)mem, "Zone mémoire avec permissions RWX");
    printf("[+] Données écrites : %s\n", (char*)mem);

    // Démonstration : modifier les permissions
    printf("\n[*] Modification des permissions vers RX uniquement...\n");
    if (mprotect(mem, size, PROT_READ | PROT_EXEC) == 0) {
        printf("[+] Permissions modifiées : PROT_READ | PROT_EXEC\n");
        printf("[+] L'écriture est maintenant interdite\n");
    }

    munmap(mem, size);
#endif

    printf("\n⚠️  NOTE IMPORTANTE :\n");
    printf("    Les zones mémoire RWX sont fortement suspectes\n");
    printf("    Détectées par : DEP, NX, ASLR, EDR, antivirus\n");
    printf("    Utilisées légitimement par : JIT compilers, émulateurs\n");
}

// ═══════════════════════════════════════════════════════════════════
// Fonction principale
// ═══════════════════════════════════════════════════════════════════

int main(void) {
    printf(SEPARATEUR);
    printf("  MODULE 36 : MEMORY MAPPING\n");
    printf("  Mappage Mémoire Multi-plateforme (%s)\n", PLATFORM);
    printf(SEPARATEUR);

    printf("\n⚠️  AVERTISSEMENT LÉGAL ⚠️\n\n");
    printf("Ce programme démontre des techniques de memory mapping.\n");
    printf("Certaines techniques (RWX) peuvent être utilisées malicieusement.\n\n");
    printf("UTILISATIONS LÉGALES UNIQUEMENT :\n");
    printf("  - Environnement de test isolé\n");
    printf("  - Développement d'applications légitimes\n");
    printf("  - Recherche académique éthique\n\n");
    printf("Appuyez sur ENTRÉE pour continuer...\n");
    getchar();

    // Démonstration 1 : File Mapping
    demonstrer_file_mapping();
    printf("\n\nAppuyez sur ENTRÉE pour continuer...\n");
    getchar();

    // Démonstration 2 : Anonymous Mapping
    demonstrer_anonymous_mapping();
    printf("\n\nAppuyez sur ENTRÉE pour continuer...\n");
    getchar();

    // Démonstration 3 : Shared Memory
    demonstrer_shared_memory();
    printf("\n\nAppuyez sur ENTRÉE pour continuer...\n");
    getchar();

    // Démonstration 4 : Permissions RWX
    demonstrer_permissions_rwx();

    printf("\n");
    afficher_titre("FIN DES DÉMONSTRATIONS");
    printf("\n[+] Toutes les démonstrations terminées\n");
    printf("[+] Consultez exercice.txt pour des défis pratiques\n\n");

    return 0;
}

/*
 * ═══════════════════════════════════════════════════════════════════
 * Notes techniques importantes
 * ═══════════════════════════════════════════════════════════════════
 *
 * 1. DIFFÉRENCES LINUX/WINDOWS :
 *    Linux : mmap() / munmap()
 *    Windows : CreateFileMapping() / MapViewOfFile() / UnmapViewOfFile()
 *
 * 2. TYPES DE MAPPING :
 *    - File-backed : Associé à un fichier sur disque
 *    - Anonymous : Mémoire pure (pas de fichier)
 *    - Shared : Modifications visibles par tous
 *    - Private : Copy-on-write
 *
 * 3. SÉCURITÉ :
 *    - DEP/NX bloque l'exécution de zones RW
 *    - ASLR randomise les adresses
 *    - RWX est fortement suspect
 *    - Utilisé par malware pour shellcode
 *
 * 4. PERFORMANCE :
 *    - Pas de syscalls read/write répétés
 *    - Lazy loading (pages chargées à la demande)
 *    - Cache du noyau partagé
 *    - Idéal pour fichiers volumineux
 *
 * 5. IPC (INTER-PROCESS COMMUNICATION) :
 *    - Shared memory = IPC le plus rapide
 *    - Pas de copie de données
 *    - Synchronisation requise (mutex/semaphore)
 *
 * ═══════════════════════════════════════════════════════════════════
 */

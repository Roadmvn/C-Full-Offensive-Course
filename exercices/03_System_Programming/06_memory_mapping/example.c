/*
 * ⚠️ AVERTISSEMENT STRICT
 * Techniques de malware development. Usage éducatif uniquement.
 *
 * Module 36 : Memory Mapping Techniques
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

// 1. File mapping (map fichier en mémoire)
#ifdef _WIN32
void* demo_file_mapping_windows(const char* filename, size_t* size) {
    HANDLE hFile = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE,
                               0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile failed\n");
        return NULL;
    }

    *size = GetFileSize(hFile, NULL);
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    CloseHandle(hFile);

    if (!hMap) {
        printf("[-] CreateFileMapping failed\n");
        return NULL;
    }

    void* view = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    CloseHandle(hMap);

    if (!view) {
        printf("[-] MapViewOfFile failed\n");
        return NULL;
    }

    printf("[+] File mapped at %p (%zu bytes)\n", view, *size);
    return view;
}
#endif

// 2. Anonymous mapping RWX (shellcode execution zone)
void* demo_anonymous_rwx(size_t size) {
#ifdef _WIN32
    HANDLE hMap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL,
                                     PAGE_EXECUTE_READWRITE, 0, size, NULL);
    if (!hMap) {
        printf("[-] CreateFileMapping failed (DEP blocked?)\n");
        return NULL;
    }

    void* mem = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, size);
    CloseHandle(hMap);

    if (!mem) {
        printf("[-] MapViewOfFile failed\n");
        return NULL;
    }

    printf("[+] RWX memory at %p (%zu bytes)\n", mem, size);
    return mem;
#else
    void* mem = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if (mem == MAP_FAILED) {
        perror("[-] mmap RWX failed (NX blocked?)");
        return NULL;
    }

    printf("[+] RWX memory at %p (%zu bytes)\n", mem, size);
    return mem;
#endif
}

// 3. Shared memory IPC
void* demo_shared_memory(const char* name, size_t size) {
#ifdef _WIN32
    char fullname[256];
    snprintf(fullname, sizeof(fullname), "Global\\%s", name);

    HANDLE hMap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL,
                                     PAGE_READWRITE, 0, size, fullname);
    if (!hMap) {
        printf("[-] CreateFileMapping failed\n");
        return NULL;
    }

    BOOL existed = (GetLastError() == ERROR_ALREADY_EXISTS);

    void* view = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, size);
    CloseHandle(hMap);

    if (!view) {
        printf("[-] MapViewOfFile failed\n");
        return NULL;
    }

    printf("[+] Shared memory %s (%s) at %p\n", fullname,
           existed ? "opened" : "created", view);
    return view;
#else
    int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("[-] shm_open failed");
        return NULL;
    }

    ftruncate(shm_fd, size);

    void* ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_SHARED, shm_fd, 0);
    close(shm_fd);

    if (ptr == MAP_FAILED) {
        perror("[-] mmap failed");
        return NULL;
    }

    printf("[+] Shared memory %s at %p\n", name, ptr);
    return ptr;
#endif
}

int main() {
    printf("\n⚠️  AVERTISSEMENT : Techniques de memory mapping malware dev\n");
    printf("   Usage éducatif uniquement. Tests VM isolées.\n\n");

    printf("=== MEMORY MAPPING DEMO ===\n\n");

    // Demo 1: Anonymous RWX (shellcode zone)
    printf("[1] Anonymous RWX Mapping\n");
    size_t rwx_size = 4096;
    void* rwx_mem = demo_anonymous_rwx(rwx_size);

    if (rwx_mem) {
        // Write "harmless" data (not actual shellcode)
        strcpy((char*)rwx_mem, "RWX zone (for shellcode in real malware)");
        printf("[*] Data written: %s\n", (char*)rwx_mem);

#ifdef _WIN32
        UnmapViewOfFile(rwx_mem);
#else
        munmap(rwx_mem, rwx_size);
#endif
    }

    // Demo 2: Shared memory IPC
    printf("\n[2] Shared Memory IPC\n");
    size_t shm_size = 4096;
    void* shm = demo_shared_memory("TestSharedMem", shm_size);

    if (shm) {
        sprintf((char*)shm, "Message from PID %d", getpid());
        printf("[*] Message written: %s\n", (char*)shm);
        printf("[*] Run this program again to see shared data\n");

#ifdef _WIN32
        UnmapViewOfFile(shm);
#else
        munmap(shm, shm_size);
#endif
    }

    printf("\n[!] NOTES:\n");
    printf("- RWX mappings = suspect (shellcode execution)\n");
    printf("- Fileless payloads = never touch disk\n");
    printf("- Shared memory = fastest IPC method\n");
    printf("- Detection: DEP/NX, /proc/[pid]/maps, Sysmon\n");

    return 0;
}

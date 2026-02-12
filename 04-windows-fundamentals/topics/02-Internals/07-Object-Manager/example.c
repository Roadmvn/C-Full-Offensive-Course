/*
 * OBJECTIF  : Comprendre le gestionnaire d'objets Windows (handles, types d'objets)
 * PREREQUIS : Bases du C, API Windows (CreateFile, OpenProcess)
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Sous Windows, tout est un "objet" : fichiers, processus, threads, mutexes, etc.
 * Chaque objet est accessible via un HANDLE. Ce programme explore les handles
 * du processus courant et montre comment le noyau gere les objets.
 */

#include <windows.h>
#include <stdio.h>

/* Definitions pour NtQuerySystemInformation */
typedef LONG NTSTATUS;
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

#define SystemHandleInformation 16

typedef struct _SYSTEM_HANDLE_ENTRY {
    USHORT ProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} SYSTEM_HANDLE_ENTRY;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_ENTRY Handles[1];
} SYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(
    ULONG, PVOID, ULONG, PULONG);

/* Demo 1 : Creer differents types d'objets et observer les handles */
void demo_create_objects(void) {
    printf("[1] Creation de differents objets Windows\n\n");

    /* Objet Fichier */
    HANDLE hFile = CreateFileA("NUL", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    printf("    Fichier  (NUL device) : Handle = 0x%p\n", hFile);

    /* Objet Mutex */
    HANDLE hMutex = CreateMutexA(NULL, FALSE, "Local\\DemoMutex");
    printf("    Mutex                 : Handle = 0x%p\n", hMutex);

    /* Objet Event */
    HANDLE hEvent = CreateEventA(NULL, TRUE, FALSE, "Local\\DemoEvent");
    printf("    Event                 : Handle = 0x%p\n", hEvent);

    /* Objet Semaphore */
    HANDLE hSemaphore = CreateSemaphoreA(NULL, 1, 10, "Local\\DemoSemaphore");
    printf("    Semaphore             : Handle = 0x%p\n", hSemaphore);

    /* Objet Thread (le thread courant) */
    HANDLE hThread = GetCurrentThread();
    printf("    Thread (courant)      : Handle = 0x%p (pseudo-handle)\n", hThread);

    /* Objet Processus (le processus courant) */
    HANDLE hProcess = GetCurrentProcess();
    printf("    Processus (courant)   : Handle = 0x%p (pseudo-handle)\n", hProcess);

    /* Objet Section (file mapping) */
    HANDLE hMapping = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL,
                                          PAGE_READWRITE, 0, 4096, "Local\\DemoMapping");
    printf("    FileMapping           : Handle = 0x%p\n", hMapping);

    printf("\n    [*] Chaque handle est un index dans la table des handles du processus\n");
    printf("    [*] Le noyau maintient un compteur de references pour chaque objet\n\n");

    /* Fermer les handles - decremente le compteur de references */
    CloseHandle(hFile);
    CloseHandle(hMutex);
    CloseHandle(hEvent);
    CloseHandle(hSemaphore);
    CloseHandle(hMapping);
    printf("    [+] Handles fermes (compteurs de references decrementes)\n\n");
}

/* Demo 2 : Dupliquer un handle */
void demo_handle_duplication(void) {
    printf("[2] Duplication de handle\n\n");

    HANDLE hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    printf("    Handle original : 0x%p\n", hEvent);

    HANDLE hDup = NULL;
    BOOL ok = DuplicateHandle(
        GetCurrentProcess(), hEvent,
        GetCurrentProcess(), &hDup,
        0, FALSE, DUPLICATE_SAME_ACCESS);

    if (ok) {
        printf("    Handle duplique : 0x%p\n", hDup);
        printf("    [*] Les deux handles pointent vers le meme objet kernel\n");
        printf("    [*] Le compteur de references est maintenant a 2\n");
        CloseHandle(hDup);
    }

    CloseHandle(hEvent);
    printf("\n");
}

/* Demo 3 : Enumerer les handles du processus courant */
void demo_enumerate_handles(void) {
    printf("[3] Enumeration des handles du processus courant\n\n");

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtQuerySystemInformation NtQuerySystemInformation =
        (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");

    if (!NtQuerySystemInformation) {
        printf("    [-] NtQuerySystemInformation non trouvee\n");
        return;
    }

    DWORD pid = GetCurrentProcessId();
    ULONG bufSize = 0x100000;
    SYSTEM_HANDLE_INFORMATION* info = NULL;
    NTSTATUS status;

    /* Allouer un buffer suffisamment grand */
    do {
        info = (SYSTEM_HANDLE_INFORMATION*)realloc(info, bufSize);
        status = NtQuerySystemInformation(SystemHandleInformation, info, bufSize, NULL);
        if (status == STATUS_INFO_LENGTH_MISMATCH)
            bufSize *= 2;
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        printf("    [-] NtQuerySystemInformation echoue : 0x%08lX\n", status);
        free(info);
        return;
    }

    /* Compter les handles de notre processus */
    int our_handles = 0;
    printf("    %-8s  %-6s  %-18s  %-10s\n",
           "Handle", "Type", "Objet Kernel", "Acces");
    printf("    %-8s  %-6s  %-18s  %-10s\n",
           "--------", "------", "------------------", "----------");

    for (ULONG i = 0; i < info->NumberOfHandles; i++) {
        if (info->Handles[i].ProcessId == pid) {
            if (our_handles < 20) {
                printf("    0x%04X    %-6d  %p  0x%08lX\n",
                       info->Handles[i].HandleValue,
                       info->Handles[i].ObjectTypeIndex,
                       info->Handles[i].Object,
                       info->Handles[i].GrantedAccess);
            }
            our_handles++;
        }
    }

    printf("\n    [+] Total handles pour PID %lu : %d\n", pid, our_handles);
    printf("    [+] Total handles systeme : %lu\n", info->NumberOfHandles);

    free(info);
    printf("\n");
}

/* Demo 4 : Noms d'objets dans le namespace */
void demo_object_namespace(void) {
    printf("[4] Namespace des objets (noms symboliques)\n\n");

    printf("    Windows organise les objets dans un namespace hierarchique :\n");
    printf("    \\Device\\HarddiskVolume1  -> Disque physique\n");
    printf("    \\Device\\Tcp              -> Stack TCP/IP\n");
    printf("    \\BaseNamedObjects\\       -> Mutexes, Events nommes\n");
    printf("    \\Sessions\\1\\BaseNamedObjects\\ -> Objets par session\n");
    printf("    \\KnownDlls\\             -> DLLs pre-mappees\n\n");

    /* Creer un objet nomme */
    HANDLE hMutex = CreateMutexA(NULL, FALSE, "Global\\TestObjectManager");
    if (hMutex) {
        printf("    [+] Mutex cree : Global\\TestObjectManager\n");
        printf("        -> Visible dans WinObj sous \\BaseNamedObjects\\\n");
        CloseHandle(hMutex);
    } else {
        printf("    [-] Creation mutex echouee (err %lu)\n", GetLastError());
    }
}

int main(void) {
    printf("[*] Demo : Object Manager - Gestionnaire d'objets Windows\n");
    printf("[*] ==========================================\n\n");

    demo_create_objects();
    demo_handle_duplication();
    demo_enumerate_handles();
    demo_object_namespace();

    printf("[+] Exemple termine avec succes\n");
    return 0;
}

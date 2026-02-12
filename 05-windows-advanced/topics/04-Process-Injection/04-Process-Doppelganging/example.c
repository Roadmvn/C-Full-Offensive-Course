/*
 * OBJECTIF  : Comprendre le Process Doppelganging (injection via TxF)
 * PREREQUIS : Module 03-Process-Hollowing, format PE, NTAPI
 * COMPILE   : cl example.c /Fe:example.exe /link ntdll.lib
 *
 * Le Process Doppelganging utilise les transactions NTFS (TxF) pour creer
 * un processus a partir d'un fichier qui n'existe jamais reellement sur disque.
 * Etapes :
 * 1. Creer une transaction NTFS
 * 2. Ecrire le payload dans un fichier transactionnel
 * 3. Creer une section (image) depuis ce fichier
 * 4. Annuler la transaction (le fichier disparait!)
 * 5. Creer le processus depuis la section
 *
 * Cette technique est tres furtive car le fichier n'est jamais visible sur disque.
 */

#include <windows.h>
#include <stdio.h>

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

/* Prototypes NTAPI necessaires */
typedef NTSTATUS (NTAPI *pNtCreateSection)(
    PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *pNtCreateProcessEx)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, ULONG);

/* Prototype KTM (Kernel Transaction Manager) */
typedef HANDLE (WINAPI *pCreateTransaction)(
    LPSECURITY_ATTRIBUTES, LPGUID, DWORD, DWORD, DWORD, DWORD, LPWSTR);
typedef HANDLE (WINAPI *pCreateFileTransactedA)(
    LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE, HANDLE, PUSHORT, PVOID);
typedef BOOL (WINAPI *pRollbackTransaction)(HANDLE);

void demo_doppelganging_steps(void) {
    printf("[1] Etapes du Process Doppelganging\n\n");

    /* Charger les fonctions necessaires */
    HMODULE ktmw32 = LoadLibraryA("ktmw32.dll");
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    if (!ktmw32) {
        printf("    [-] ktmw32.dll non disponible (Windows 10+ requis)\n");
        printf("    [*] Explication theorique ci-dessous\n\n");
    }

    pCreateTransaction CreateTransaction = ktmw32 ?
        (pCreateTransaction)GetProcAddress(ktmw32, "CreateTransaction") : NULL;
    pRollbackTransaction RollbackTransaction = ktmw32 ?
        (pRollbackTransaction)GetProcAddress(ktmw32, "RollbackTransaction") : NULL;
    pCreateFileTransactedA CreateFileTransactedA = (pCreateFileTransactedA)
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileTransactedA");

    pNtCreateSection NtCreateSection =
        (pNtCreateSection)GetProcAddress(ntdll, "NtCreateSection");

    printf("    CreateTransaction       : %p\n", CreateTransaction);
    printf("    CreateFileTransactedA   : %p\n", CreateFileTransactedA);
    printf("    RollbackTransaction     : %p\n", RollbackTransaction);
    printf("    NtCreateSection         : %p\n", NtCreateSection);
    printf("\n");

    /* Etape 1 : Creer une transaction NTFS */
    printf("    [Etape 1] Creer une transaction NTFS\n");
    HANDLE hTransaction = NULL;
    if (CreateTransaction) {
        hTransaction = CreateTransaction(NULL, NULL, 0, 0, 0, 0, NULL);
        if (hTransaction && hTransaction != INVALID_HANDLE_VALUE)
            printf("    [+] Transaction creee : %p\n", hTransaction);
        else
            printf("    [-] CreateTransaction echoue\n");
    } else {
        printf("    [*] CreateTransaction non disponible\n");
    }

    /* Etape 2 : Creer un fichier dans la transaction */
    printf("\n    [Etape 2] Creer un fichier transactionnel\n");
    HANDLE hFile = INVALID_HANDLE_VALUE;
    if (CreateFileTransactedA && hTransaction) {
        hFile = CreateFileTransactedA(
            "C:\\Windows\\Temp\\doppel_temp.exe",
            GENERIC_WRITE | GENERIC_READ,
            0, NULL, CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, NULL,
            hTransaction, NULL, NULL);

        if (hFile != INVALID_HANDLE_VALUE) {
            printf("    [+] Fichier transactionnel cree\n");
            printf("    [*] Ce fichier n'est PAS visible dans l'explorateur\n");

            /* En realite, on ecrirait le payload PE ici */
            printf("    [*] (En reel : ecrire le payload PE dans ce fichier)\n");
            CloseHandle(hFile);
        } else {
            printf("    [-] CreateFileTransacted echoue (err %lu)\n", GetLastError());
        }
    }

    /* Etape 3 : Creer une section image depuis le fichier */
    printf("\n    [Etape 3] Creer une section image (NtCreateSection)\n");
    printf("    [*] NtCreateSection avec SEC_IMAGE cree une section executable\n");
    printf("    [*] depuis le fichier transactionnel (le PE est valide)\n");

    /* Etape 4 : Rollback de la transaction */
    printf("\n    [Etape 4] Rollback de la transaction\n");
    if (RollbackTransaction && hTransaction) {
        RollbackTransaction(hTransaction);
        printf("    [+] Transaction annulee!\n");
        printf("    [*] Le fichier n'existe plus sur disque\n");
        printf("    [*] Mais la section en memoire reste valide\n");
        CloseHandle(hTransaction);
    }

    /* Etape 5 : Creer le processus */
    printf("\n    [Etape 5] Creer le processus depuis la section\n");
    printf("    [*] NtCreateProcessEx(section) -> processus sans fichier sur disque\n");
    printf("    [*] Le processus apparait dans Task Manager mais le binaire\n");
    printf("    [*] sur disque a disparu (rollback de la transaction)\n\n");

    if (ktmw32) FreeLibrary(ktmw32);
}

void explain_detection(void) {
    printf("[2] Detection et contre-mesures\n\n");

    printf("    Avantages :\n");
    printf("    - Le fichier n'existe JAMAIS sur disque (invisible aux scans)\n");
    printf("    - Pas de hollowing (le processus est cree proprement)\n");
    printf("    - Bypass des scans statiques on-disk\n\n");

    printf("    Limitations :\n");
    printf("    - TxF est deprecie depuis Windows 10 v1809\n");
    printf("    - Certains EDR monitent NtCreateSection/NtCreateProcessEx\n");
    printf("    - Le processus a un PEB/TEB normal (analysable)\n\n");

    printf("    Detection :\n");
    printf("    - ETW : evenements de creation de section image\n");
    printf("    - Kernel callbacks : PsSetCreateProcessNotifyRoutine\n");
    printf("    - Analyse du backing file de la section (manquant = suspect)\n");
    printf("    - Sysmon Event ID 1 avec image path introuvable\n\n");
}

int main(void) {
    printf("[*] Demo : Process Doppelganging (injection via TxF)\n");
    printf("[*] ==========================================\n\n");

    demo_doppelganging_steps();
    explain_detection();

    printf("[+] Exemple termine avec succes\n");
    return 0;
}

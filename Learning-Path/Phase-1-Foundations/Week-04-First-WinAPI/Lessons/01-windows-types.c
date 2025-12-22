/*
 * Lesson 01 - Types Windows
 * =========================
 *
 * OBJECTIF :
 * Comprendre les types de données spécifiques à Windows et pourquoi ils existent.
 *
 * CONCEPTS CLÉS :
 * - DWORD : Double Word (32 bits, unsigned int)
 * - HANDLE : Identifiant opaque vers une ressource système
 * - LPVOID : Long Pointer to VOID (void*)
 * - BOOL : Booléen Windows (TRUE/FALSE)
 * - TCHAR : Type caractère (ANSI ou Unicode selon compilation)
 *
 * POURQUOI CES TYPES ?
 * Microsoft a créé ces types pour :
 * 1. Abstraction : Indépendance de la plateforme (16/32/64 bits)
 * 2. Clarté : HANDLE indique clairement qu'on manipule une ressource système
 * 3. Compatibilité : Facilite le portage entre versions Windows
 */

#include <windows.h>
#include <stdio.h>

/*
 * Fonction de démonstration des types Windows
 */
void DemonstrateWindowsTypes(void) {
    printf("=== TYPES WINDOWS ===\n\n");

    // DWORD : Double Word (32 bits non signé)
    // Utilisé pour : PID, TID, codes d'erreur, tailles, flags
    DWORD dwProcessId = GetCurrentProcessId();
    DWORD dwThreadId = GetCurrentThreadId();

    printf("1. DWORD (Double Word - 32 bits)\n");
    printf("   Taille : %zu bytes\n", sizeof(DWORD));
    printf("   Process ID : %lu\n", dwProcessId);
    printf("   Thread ID  : %lu\n\n", dwThreadId);

    // HANDLE : Identifiant opaque vers une ressource
    // Concept fondamental Windows : tout est un objet avec un handle
    HANDLE hProcess = GetCurrentProcess();
    HANDLE hThread = GetCurrentThread();

    printf("2. HANDLE (Identifiant ressource)\n");
    printf("   Taille : %zu bytes\n", sizeof(HANDLE));
    printf("   Process Handle : 0x%p\n", (void*)hProcess);
    printf("   Thread Handle  : 0x%p\n\n", (void*)hThread);

    // LPVOID : Long Pointer to VOID
    // Équivalent de void* en C standard
    // "Long" est historique (Windows 16 bits : near/far pointers)
    LPVOID pMemory = NULL;

    printf("3. LPVOID (Long Pointer to VOID)\n");
    printf("   Taille : %zu bytes\n", sizeof(LPVOID));
    printf("   Équivalent : void*\n");
    printf("   Valeur : %p\n\n", pMemory);

    // BOOL : Booléen Windows
    // ATTENTION : != bool C99 et != BOOLEAN (kernel)
    // TRUE = 1, FALSE = 0
    BOOL bSuccess = TRUE;
    BOOL bFailure = FALSE;

    printf("4. BOOL (Booléen Windows)\n");
    printf("   Taille : %zu bytes (int)\n", sizeof(BOOL));
    printf("   TRUE  = %d\n", TRUE);
    printf("   FALSE = %d\n", FALSE);
    printf("   bSuccess : %d\n\n", bSuccess);

    // SIZE_T : Type pour les tailles
    // Adapté à l'architecture (32/64 bits)
    SIZE_T szMemorySize = 1024;

    printf("5. SIZE_T (Taille adaptative)\n");
    printf("   Taille : %zu bytes\n", sizeof(SIZE_T));
    printf("   Valeur : %zu bytes\n\n", szMemorySize);
}

/*
 * Comparaison types C standard vs types Windows
 */
void CompareTypes(void) {
    printf("=== COMPARAISON C STANDARD <-> WINDOWS ===\n\n");

    printf("%-20s | %-20s | Taille\n", "Type C", "Type Windows", "");
    printf("--------------------------------------------------------\n");
    printf("%-20s | %-20s | %zu bytes\n", "unsigned int", "DWORD", sizeof(DWORD));
    printf("%-20s | %-20s | %zu bytes\n", "unsigned long", "ULONG", sizeof(ULONG));
    printf("%-20s | %-20s | %zu bytes\n", "void*", "LPVOID", sizeof(LPVOID));
    printf("%-20s | %-20s | %zu bytes\n", "int", "BOOL", sizeof(BOOL));
    printf("%-20s | %-20s | %zu bytes\n", "unsigned char", "BYTE", sizeof(BYTE));
    printf("%-20s | %-20s | %zu bytes\n", "unsigned short", "WORD", sizeof(WORD));
    printf("%-20s | %-20s | %zu bytes\n", "size_t", "SIZE_T", sizeof(SIZE_T));
    printf("\n");
}

/*
 * Démonstration des conventions de nommage Hungarian Notation
 * Microsoft utilise cette notation pour indiquer le type des variables
 */
void HungarianNotationExample(void) {
    printf("=== HUNGARIAN NOTATION ===\n\n");
    printf("Préfixes courants :\n");
    printf("  dw  : DWORD       -> dwProcessId\n");
    printf("  h   : HANDLE      -> hFile, hProcess\n");
    printf("  p   : Pointer     -> pBuffer, pData\n");
    printf("  lp  : Long Pointer-> lpFileName\n");
    printf("  b   : BOOL        -> bSuccess\n");
    printf("  sz  : String Zero -> szFileName (chaîne terminée par \\0)\n");
    printf("  n   : Number      -> nCount\n");
    printf("  c   : Count       -> cBytes\n");
    printf("\n");

    // Exemple pratique
    DWORD dwFileSize = 1024;
    HANDLE hFile = NULL;
    LPVOID pBuffer = NULL;
    BOOL bSuccess = FALSE;

    printf("Exemples en code :\n");
    printf("  DWORD dwFileSize = %lu;\n", dwFileSize);
    printf("  HANDLE hFile = %p;\n", (void*)hFile);
    printf("  LPVOID pBuffer = %p;\n", pBuffer);
    printf("  BOOL bSuccess = %d;\n", bSuccess);
    printf("\n");
}

/*
 * Types importants pour le maldev
 */
void MaldevImportantTypes(void) {
    printf("=== TYPES ESSENTIELS POUR LE MALDEV ===\n\n");

    printf("1. HANDLE\n");
    printf("   - Clé de tout sous Windows\n");
    printf("   - Process, Thread, File, Registry, Token...\n");
    printf("   - TOUJOURS fermer avec CloseHandle() (sauf pseudo-handles)\n\n");

    printf("2. DWORD\n");
    printf("   - Codes d'erreur (GetLastError retourne un DWORD)\n");
    printf("   - PID/TID (identifiants processus/thread)\n");
    printf("   - Flags et options (bitwise operations)\n\n");

    printf("3. LPVOID / PVOID\n");
    printf("   - Buffers mémoire\n");
    printf("   - VirtualAlloc, WriteProcessMemory\n");
    printf("   - Shellcode injection points\n\n");

    printf("4. SIZE_T\n");
    printf("   - Tailles mémoire adaptatives (32/64 bits)\n");
    printf("   - VirtualAlloc, memcpy, etc.\n\n");

    printf("5. LPCSTR / LPWSTR\n");
    printf("   - LPCSTR : Long Pointer to Constant STRing (ANSI)\n");
    printf("   - LPWSTR : Long Pointer to Wide STRing (Unicode)\n");
    printf("   - APIs : xxxA (ANSI) vs xxxW (Wide/Unicode)\n\n");
}

/*
 * Pièges courants avec les types Windows
 */
void CommonPitfalls(void) {
    printf("=== PIÈGES COURANTS ===\n\n");

    printf("1. BOOL vs bool vs BOOLEAN\n");
    printf("   - BOOL (Windows) : int, TRUE=1, FALSE=0\n");
    printf("   - bool (C99) : _Bool, true=1, false=0\n");
    printf("   - BOOLEAN (kernel) : unsigned char\n");
    printf("   -> NE PAS MÉLANGER !\n\n");

    printf("2. HANDLE invalide\n");
    printf("   - Pour la plupart des APIs : INVALID_HANDLE_VALUE (-1)\n");
    printf("   - Pour certaines APIs : NULL (0)\n");
    printf("   - TOUJOURS vérifier la doc !\n\n");

    printf("3. Tailles en 64 bits\n");
    printf("   - HANDLE est 8 bytes en 64 bits\n");
    printf("   - SIZE_T aussi\n");
    printf("   - Attention aux casts et aux formats printf\n\n");

    printf("4. ANSI vs Unicode\n");
    printf("   - MessageBoxA : ANSI (char*)\n");
    printf("   - MessageBoxW : Unicode (wchar_t*)\n");
    printf("   - MessageBox : Macro qui résout vers A ou W\n");
    printf("   - En maldev : préférer les versions explicites (A ou W)\n\n");
}

int main(void) {
    printf("===================================================\n");
    printf("  LESSON 01 - TYPES WINDOWS\n");
    printf("===================================================\n\n");

    DemonstrateWindowsTypes();
    CompareTypes();
    HungarianNotationExample();
    MaldevImportantTypes();
    CommonPitfalls();

    printf("===================================================\n");
    printf("  Points clés à retenir :\n");
    printf("  1. Les types Windows sont des abstractions pour portabilité\n");
    printf("  2. HANDLE = concept central (tout est objet)\n");
    printf("  3. Hungarian Notation aide à la lisibilité\n");
    printf("  4. Attention BOOL vs bool, HANDLE invalide\n");
    printf("  5. En 64 bits, HANDLE et SIZE_T = 8 bytes\n");
    printf("===================================================\n");

    return 0;
}

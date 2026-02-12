/*
 * OBJECTIF  : Comprendre la gestion des exceptions Windows (SEH, VEH)
 * PREREQUIS : Bases du C, notions de processus Windows
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Windows gere les exceptions via deux mecanismes :
 * - SEH (Structured Exception Handling) : __try/__except, lie au thread
 * - VEH (Vectored Exception Handling) : callbacks globaux, prioritaire
 * Les red teamers exploitent ces mecanismes pour l'evasion et l'anti-debug.
 */

#include <windows.h>
#include <stdio.h>

/* Compteur global pour la demo */
static int g_veh_called = 0;

/* VEH Handler : intercepte TOUTES les exceptions avant SEH */
LONG CALLBACK veh_handler(PEXCEPTION_POINTERS info) {
    g_veh_called++;
    printf("    [VEH] Exception interceptee!\n");
    printf("    [VEH] Code      : 0x%08lX\n", info->ExceptionRecord->ExceptionCode);
    printf("    [VEH] Adresse   : %p\n", info->ExceptionRecord->ExceptionAddress);

    /* Pour ACCESS_VIOLATION, on peut voir l'adresse fautive */
    if (info->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        ULONG_PTR type = info->ExceptionRecord->ExceptionInformation[0];
        ULONG_PTR addr = info->ExceptionRecord->ExceptionInformation[1];
        printf("    [VEH] Type      : %s a l'adresse %p\n",
               type == 0 ? "Lecture" : "Ecriture", (void*)addr);
    }

    /*
     * EXCEPTION_CONTINUE_SEARCH   = passer au handler suivant (SEH)
     * EXCEPTION_CONTINUE_EXECUTION = reprendre l'execution (dangereux si pas corrige)
     */
    return EXCEPTION_CONTINUE_SEARCH;
}

/* Demo 1 : SEH basique avec __try/__except */
void demo_seh_basic(void) {
    printf("[1] SEH basique (__try / __except)\n\n");

    __try {
        printf("    [*] Tentative de division par zero...\n");
        int a = 42;
        int b = 0;
        int c = a / b; /* Division par zero -> EXCEPTION_INT_DIVIDE_BY_ZERO */
        (void)c;
        printf("    [-] Cette ligne ne devrait jamais s'afficher\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        printf("    [+] Exception attrapee par SEH!\n");
        printf("    [+] Code : 0x%08lX", code);
        if (code == EXCEPTION_INT_DIVIDE_BY_ZERO)
            printf(" (EXCEPTION_INT_DIVIDE_BY_ZERO)");
        printf("\n");
    }
    printf("\n");
}

/* Demo 2 : SEH avec filtre d'exception */
void demo_seh_filter(void) {
    printf("[2] SEH avec filtre d'exception\n\n");

    __try {
        printf("    [*] Tentative d'acces memoire invalide...\n");
        int* ptr = NULL;
        *ptr = 42; /* ACCESS_VIOLATION */
    }
    __except (
        GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ?
        EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH
    ) {
        printf("    [+] Access violation attrapee par le filtre SEH\n");
        printf("    [*] Le filtre permet de n'attraper QUE certaines exceptions\n");
    }
    printf("\n");
}

/* Demo 3 : SEH avec __finally (cleanup garanti) */
void demo_seh_finally(void) {
    printf("[3] SEH avec __try / __finally (cleanup)\n\n");

    HANDLE hFile = INVALID_HANDLE_VALUE;

    __try {
        hFile = CreateFileA("NUL", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
        printf("    [*] Fichier ouvert : handle %p\n", hFile);
        printf("    [*] Simulation d'un return premature...\n");
        /* Le __finally sera execute meme avec un return ou une exception */
        return;
    }
    __finally {
        /* Ce bloc s'execute TOUJOURS, meme en cas d'exception ou return */
        printf("    [+] __finally execute! (cleanup garanti)\n");
        if (hFile != INVALID_HANDLE_VALUE)
            CloseHandle(hFile);
        printf("    [+] Handle ferme proprement\n");
    }
}

/* Demo 4 : VEH (Vectored Exception Handler) */
void demo_veh(void) {
    printf("\n[4] VEH (Vectored Exception Handler)\n\n");

    /* Enregistrer un VEH (premier = prioritaire sur SEH) */
    PVOID handler = AddVectoredExceptionHandler(1, veh_handler);
    printf("    [+] VEH enregistre : %p\n", handler);

    __try {
        printf("    [*] Declenchement d'une exception...\n");
        RaiseException(0xDEADBEEF, 0, 0, NULL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("    [+] SEH a aussi recu l'exception (apres VEH)\n");
    }

    printf("    [*] VEH appele %d fois\n", g_veh_called);

    RemoveVectoredExceptionHandler(handler);
    printf("    [+] VEH desenregistre\n\n");
}

/* Demo 5 : Concept anti-debug via exceptions */
void demo_antidebug_exception(void) {
    printf("[5] Technique anti-debug via exceptions\n\n");

    printf("    [*] Principe : un debugger intercepte les exceptions AVANT le programme\n");
    printf("    [*] Si l'exception n'arrive jamais au handler = debugger present\n\n");

    BOOL debugger_detected = TRUE;

    __try {
        /* INT 2D est une instruction speciale : */
        /* - Sans debugger : genere EXCEPTION_BREAKPOINT */
        /* - Avec debugger : le debugger l'intercepte silencieusement */
        printf("    [*] Test avec RaiseException(EXCEPTION_BREAKPOINT)...\n");
        RaiseException(EXCEPTION_BREAKPOINT, 0, 0, NULL);
        /* Si on arrive ici, le debugger a avale l'exception */
        printf("    [!] DEBUGGER DETECTE (exception non recue)\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        debugger_detected = FALSE;
        printf("    [+] Exception recue normalement -> pas de debugger\n");
    }

    printf("    [*] Resultat : %s\n\n", debugger_detected ? "Debugger!" : "Clean");
}

int main(void) {
    printf("[*] Demo : Exception Handling (SEH / VEH)\n");
    printf("[*] ==========================================\n\n");

    demo_seh_basic();
    demo_seh_filter();
    demo_seh_finally();
    demo_veh();
    demo_antidebug_exception();

    printf("[+] Exemple termine avec succes\n");
    return 0;
}

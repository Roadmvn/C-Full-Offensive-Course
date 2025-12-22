/*
 * Lesson 02 - Premier appel WinAPI : MessageBox
 * ===============================================
 *
 * OBJECTIF :
 * Comprendre la structure d'un appel WinAPI à travers MessageBoxA.
 *
 * CONCEPTS CLÉS :
 * - Anatomie d'un appel WinAPI
 * - Paramètres et valeurs de retour
 * - Flags et constantes
 * - Différence A/W (ANSI/Wide)
 *
 * PROTOTYPE MessageBoxA :
 * int MessageBoxA(
 *     HWND    hWnd,        // Handle de la fenêtre parente (NULL = aucune)
 *     LPCSTR  lpText,      // Texte du message
 *     LPCSTR  lpCaption,   // Titre de la fenêtre
 *     UINT    uType        // Type de boutons et icône
 * );
 *
 * VALEUR DE RETOUR :
 * ID du bouton cliqué (IDOK, IDCANCEL, IDYES, IDNO, etc.)
 */

#include <windows.h>
#include <stdio.h>

/*
 * Exemple 1 : MessageBox basique
 */
void BasicMessageBox(void) {
    printf("\n=== EXEMPLE 1 : MessageBox basique ===\n");
    printf("Affichage d'une MessageBox simple...\n");

    // Premier appel WinAPI !
    // NULL = pas de fenêtre parente
    // MB_OK = un seul bouton OK
    int result = MessageBoxA(
        NULL,                    // Pas de fenêtre parente
        "Bonjour from WinAPI!",  // Texte du message
        "Premier WinAPI",        // Titre
        MB_OK                    // Type : bouton OK uniquement
    );

    printf("Bouton cliqué : %d (IDOK = %d)\n", result, IDOK);
}

/*
 * Exemple 2 : MessageBox avec différents boutons
 */
void MessageBoxWithButtons(void) {
    printf("\n=== EXEMPLE 2 : Différents types de boutons ===\n");

    // MB_YESNO : Boutons Oui et Non
    printf("Affichage MessageBox avec Oui/Non...\n");
    int result = MessageBoxA(
        NULL,
        "Voulez-vous continuer le programme ?",
        "Question",
        MB_YESNO
    );

    if (result == IDYES) {
        printf("L'utilisateur a cliqué sur OUI (ID=%d)\n", result);
    } else if (result == IDNO) {
        printf("L'utilisateur a cliqué sur NON (ID=%d)\n", result);
    }
}

/*
 * Exemple 3 : MessageBox avec icônes
 */
void MessageBoxWithIcons(void) {
    printf("\n=== EXEMPLE 3 : MessageBox avec icônes ===\n");

    // Les icônes se combinent avec les boutons via OR bitwise (|)

    // Icône d'information
    printf("1. Icône Information...\n");
    MessageBoxA(
        NULL,
        "Ceci est une information.",
        "Info",
        MB_OK | MB_ICONINFORMATION
    );

    // Icône d'avertissement
    printf("2. Icône Avertissement...\n");
    MessageBoxA(
        NULL,
        "Attention : ceci est un avertissement !",
        "Warning",
        MB_OK | MB_ICONWARNING
    );

    // Icône d'erreur
    printf("3. Icône Erreur...\n");
    MessageBoxA(
        NULL,
        "Une erreur s'est produite !",
        "Error",
        MB_OK | MB_ICONERROR
    );

    // Icône question
    printf("4. Icône Question...\n");
    MessageBoxA(
        NULL,
        "Est-ce que tout est clair ?",
        "Question",
        MB_YESNO | MB_ICONQUESTION
    );
}

/*
 * Exemple 4 : Combinaisons de flags
 */
void MessageBoxFlagsCombination(void) {
    printf("\n=== EXEMPLE 4 : Combinaisons de flags ===\n");

    // Les flags se combinent avec l'opérateur OR bitwise (|)
    printf("MessageBox : Oui/Non/Annuler + Avertissement...\n");

    int result = MessageBoxA(
        NULL,
        "Sauvegarder les modifications avant de quitter ?",
        "Confirmation",
        MB_YESNOCANCEL | MB_ICONWARNING | MB_DEFBUTTON1
    );

    // MB_DEFBUTTON1 : Le premier bouton est le défaut (Oui)

    switch (result) {
        case IDYES:
            printf("Choix : OUI - Sauvegarde et quitte\n");
            break;
        case IDNO:
            printf("Choix : NON - Quitte sans sauvegarder\n");
            break;
        case IDCANCEL:
            printf("Choix : ANNULER - Reste dans le programme\n");
            break;
    }
}

/*
 * Exemple 5 : MessageBoxA vs MessageBoxW
 */
void MessageBoxAvsW(void) {
    printf("\n=== EXEMPLE 5 : ANSI (A) vs Unicode (W) ===\n");

    // MessageBoxA : ANSI (char*)
    printf("1. MessageBoxA (ANSI)...\n");
    MessageBoxA(
        NULL,
        "Texte ANSI - 1 byte par caractere",
        "ANSI Version",
        MB_OK | MB_ICONINFORMATION
    );

    // MessageBoxW : Unicode (wchar_t*)
    // Préfixe L pour les chaînes Unicode
    printf("2. MessageBoxW (Unicode)...\n");
    MessageBoxW(
        NULL,
        L"Texte Unicode - 2 bytes par caractère : 你好 🔒",
        L"Unicode Version",
        MB_OK | MB_ICONINFORMATION
    );

    printf("\nEn maldev : toujours utiliser la version explicite (A ou W)\n");
    printf("MessageBox sans A/W est une macro qui résout selon la config\n");
}

/*
 * Exemple 6 : Tous les types de boutons disponibles
 */
void AllButtonTypes(void) {
    printf("\n=== EXEMPLE 6 : Tous les types de boutons ===\n");
    printf("Liste des constantes disponibles :\n\n");

    printf("BOUTONS :\n");
    printf("  MB_OK              : OK uniquement\n");
    printf("  MB_OKCANCEL        : OK et Annuler\n");
    printf("  MB_YESNO           : Oui et Non\n");
    printf("  MB_YESNOCANCEL     : Oui, Non et Annuler\n");
    printf("  MB_RETRYCANCEL     : Réessayer et Annuler\n");
    printf("  MB_ABORTRETRYIGNORE: Abandonner, Réessayer, Ignorer\n\n");

    printf("ICÔNES :\n");
    printf("  MB_ICONERROR       : Icône X rouge\n");
    printf("  MB_ICONWARNING     : Icône ! jaune\n");
    printf("  MB_ICONINFORMATION : Icône i bleue\n");
    printf("  MB_ICONQUESTION    : Icône ? bleue\n\n");

    printf("BOUTON PAR DÉFAUT :\n");
    printf("  MB_DEFBUTTON1      : Premier bouton (défaut)\n");
    printf("  MB_DEFBUTTON2      : Deuxième bouton\n");
    printf("  MB_DEFBUTTON3      : Troisième bouton\n\n");

    printf("MODALITÉ :\n");
    printf("  MB_APPLMODAL       : Bloque uniquement l'application (défaut)\n");
    printf("  MB_SYSTEMMODAL     : Bloque tout le système\n");
    printf("  MB_TASKMODAL       : Bloque la tâche\n\n");
}

/*
 * Exemple 7 : Gestion des valeurs de retour
 */
void ReturnValuesHandling(void) {
    printf("\n=== EXEMPLE 7 : Gestion des valeurs de retour ===\n");

    printf("Valeurs de retour possibles :\n");
    printf("  IDOK       = %d\n", IDOK);
    printf("  IDCANCEL   = %d\n", IDCANCEL);
    printf("  IDABORT    = %d\n", IDABORT);
    printf("  IDRETRY    = %d\n", IDRETRY);
    printf("  IDIGNORE   = %d\n", IDIGNORE);
    printf("  IDYES      = %d\n", IDYES);
    printf("  IDNO       = %d\n", IDNO);
    printf("\n");

    printf("Affichage MessageBox Abandonner/Réessayer/Ignorer...\n");
    int result = MessageBoxA(
        NULL,
        "Une erreur s'est produite lors de l'opération.",
        "Erreur",
        MB_ABORTRETRYIGNORE | MB_ICONERROR | MB_DEFBUTTON2
    );

    printf("\nRésultat : %d\n", result);
    switch (result) {
        case IDABORT:
            printf("Action : Abandonner l'opération\n");
            break;
        case IDRETRY:
            printf("Action : Réessayer l'opération\n");
            break;
        case IDIGNORE:
            printf("Action : Ignorer l'erreur et continuer\n");
            break;
    }
}

/*
 * Analyse détaillée d'un appel WinAPI
 */
void AnatomyOfWinAPICall(void) {
    printf("\n=== ANATOMIE D'UN APPEL WINAPI ===\n\n");

    printf("int MessageBoxA(\n");
    printf("    HWND   hWnd,      // [IN] Handle fenêtre parente\n");
    printf("    LPCSTR lpText,    // [IN] Pointeur vers texte (const)\n");
    printf("    LPCSTR lpCaption, // [IN] Pointeur vers titre (const)\n");
    printf("    UINT   uType      // [IN] Flags combinés (OR bitwise)\n");
    printf(");\n\n");

    printf("PATTERN GÉNÉRAL WINAPI :\n");
    printf("1. Types Windows (HWND, LPCSTR, UINT...)\n");
    printf("2. Hungarian notation (h=handle, lp=long pointer, u=unsigned)\n");
    printf("3. Paramètres IN/OUT/INOUT\n");
    printf("4. Flags combinables avec | (OR bitwise)\n");
    printf("5. Valeur de retour à vérifier\n");
    printf("6. En cas d'erreur : appeler GetLastError()\n\n");

    printf("CONVENTION D'APPEL :\n");
    printf("- WinAPI utilise __stdcall (WINAPI macro)\n");
    printf("- Paramètres empilés de droite à gauche\n");
    printf("- Appelé nettoie la pile (vs __cdecl)\n");
    printf("- Important pour le shellcoding !\n\n");
}

int main(void) {
    printf("===================================================\n");
    printf("  LESSON 02 - PREMIER APPEL WINAPI : MessageBoxA\n");
    printf("===================================================\n");

    // Exécuter les exemples progressivement
    BasicMessageBox();

    printf("\nAppuyez sur Entrée pour continuer...");
    getchar();

    MessageBoxWithButtons();

    printf("\nAppuyez sur Entrée pour continuer...");
    getchar();

    MessageBoxWithIcons();

    printf("\nAppuyez sur Entrée pour continuer...");
    getchar();

    MessageBoxFlagsCombination();

    printf("\nAppuyez sur Entrée pour continuer...");
    getchar();

    MessageBoxAvsW();

    AllButtonTypes();
    ReturnValuesHandling();

    printf("\nAppuyez sur Entrée pour continuer...");
    getchar();

    AnatomyOfWinAPICall();

    printf("\n===================================================\n");
    printf("  Points clés à retenir :\n");
    printf("  1. WinAPI = fonctions système Windows\n");
    printf("  2. MessageBoxA : version ANSI, MessageBoxW : Unicode\n");
    printf("  3. Flags se combinent avec OR bitwise (|)\n");
    printf("  4. Toujours vérifier la valeur de retour\n");
    printf("  5. Hungarian notation : convention de nommage Microsoft\n");
    printf("===================================================\n");

    return 0;
}

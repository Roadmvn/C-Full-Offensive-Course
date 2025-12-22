/*
 * Solution Exercise 01 - Hello WinAPI
 * ====================================
 *
 * Solution complète de l'exercice MessageBox.
 */

#include <windows.h>
#include <stdio.h>

int main(void) {
    printf("=== SOLUTION EXERCICE 01 : Hello WinAPI ===\n\n");

    // Étape 1 : Définir le nom
    const char* name = "Alice";

    // Étape 2 : Construire le message
    char message[256];
    sprintf(message, "Bonjour %s, bienvenue dans le monde WinAPI!", name);

    // Étape 3 : Afficher la MessageBox
    printf("Affichage de la première MessageBox...\n");
    int result = MessageBoxA(
        NULL,                           // Pas de fenêtre parente
        message,                         // Message personnalisé
        "Premier WinAPI",                // Titre
        MB_OK | MB_ICONINFORMATION      // Bouton OK + icône info
    );

    // Étape 4 : Vérifier la valeur de retour
    if (result == IDOK) {
        printf("L'utilisateur a cliqué sur OK (valeur = %d)\n\n", result);

        // Étape 5 : Afficher une confirmation
        MessageBoxA(
            NULL,
            "Félicitations! Vous avez complété votre premier exercice WinAPI.",
            "Confirmation",
            MB_OK | MB_ICONINFORMATION
        );
    }

    // BONUS : Boucle interactive
    printf("=== BONUS : Boucle interactive ===\n");
    BOOL continuer = TRUE;
    int count = 0;

    while (continuer) {
        count++;
        char questionMsg[128];
        sprintf(questionMsg, "Itération %d - Voulez-vous continuer ?", count);

        int response = MessageBoxA(
            NULL,
            questionMsg,
            "Boucle interactive",
            MB_YESNO | MB_ICONQUESTION
        );

        if (response == IDYES) {
            printf("L'utilisateur a choisi de continuer (itération %d)\n", count);
        } else if (response == IDNO) {
            printf("L'utilisateur a choisi d'arrêter après %d itération(s)\n", count);
            continuer = FALSE;
        }
    }

    // BONUS 2 : MessageBoxW avec Unicode et emojis
    printf("\n=== BONUS 2 : Unicode et emojis ===\n");
    printf("Affichage MessageBox Unicode...\n");

    MessageBoxW(
        NULL,
        L"Bonjour en Unicode! 🚀\n你好 (Chinois)\nПривет (Russe)\n🔒🛡️",
        L"Unicode Support",
        MB_OK | MB_ICONINFORMATION
    );

    // BONUS 3 : Tester différentes combinaisons
    printf("\n=== BONUS 3 : Différentes combinaisons ===\n");

    // Combinaison 1 : Abandon/Réessayer/Ignorer
    int retryResult = MessageBoxA(
        NULL,
        "Une erreur simulée s'est produite.",
        "Erreur de test",
        MB_ABORTRETRYIGNORE | MB_ICONERROR | MB_DEFBUTTON2
    );

    switch (retryResult) {
        case IDABORT:
            printf("Choix : Abandonner\n");
            break;
        case IDRETRY:
            printf("Choix : Réessayer\n");
            break;
        case IDIGNORE:
            printf("Choix : Ignorer\n");
            break;
    }

    // Combinaison 2 : Oui/Non/Annuler
    int saveResult = MessageBoxA(
        NULL,
        "Voulez-vous sauvegarder les modifications ?",
        "Sauvegarder",
        MB_YESNOCANCEL | MB_ICONWARNING | MB_DEFBUTTON1
    );

    switch (saveResult) {
        case IDYES:
            printf("Choix : Sauvegarder et quitter\n");
            break;
        case IDNO:
            printf("Choix : Quitter sans sauvegarder\n");
            break;
        case IDCANCEL:
            printf("Choix : Annuler et rester\n");
            break;
    }

    printf("\nProgramme terminé avec succès!\n");
    return 0;
}

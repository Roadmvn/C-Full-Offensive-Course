/*
 * Exercise 01 - Hello WinAPI
 * ==========================
 *
 * OBJECTIF :
 * Créer votre premier programme WinAPI avec MessageBox.
 *
 * INSTRUCTIONS :
 * 1. Afficher une MessageBox avec votre nom dans le titre
 * 2. Le message doit dire "Bonjour [VotreNom], bienvenue dans le monde WinAPI!"
 * 3. Utiliser une icône d'information
 * 4. Ajouter un bouton OK
 * 5. Vérifier la valeur de retour
 * 6. Afficher un second MessageBox confirmant que le bouton OK a été cliqué
 *
 * BONUS :
 * - Utiliser MessageBoxW pour supporter les emojis
 * - Essayer différentes combinaisons d'icônes et boutons
 * - Créer une boucle avec MessageBox Oui/Non
 *
 * COMPILATION :
 * cl /W4 ex01-hello-winapi.c /link user32.lib
 */

#include <windows.h>
#include <stdio.h>

int main(void) {
    // TODO : Implémenter votre premier MessageBox

    // Étape 1 : Définir le nom
    const char* name = "VOTRE_NOM";  // Remplacer par votre nom

    // Étape 2 : Construire le message
    char message[256];
    // TODO : Utiliser sprintf pour construire le message

    // Étape 3 : Afficher la MessageBox
    int result;
    // TODO : Appeler MessageBoxA avec les bons paramètres

    // Étape 4 : Vérifier la valeur de retour
    // TODO : if (result == IDOK) { ... }

    // Étape 5 : Afficher une confirmation
    // TODO : Second MessageBox

    // BONUS : Boucle interactive
    // TODO : Créer une boucle qui demande "Continuer ?" avec Oui/Non
    // Tant que l'utilisateur clique Oui, redemander

    printf("Programme terminé avec succès!\n");
    return 0;
}

/*
 * NOTES :
 * - MessageBoxA prend 4 paramètres : HWND, LPCSTR, LPCSTR, UINT
 * - Le premier paramètre peut être NULL
 * - Les flags se combinent avec l'opérateur | (OR bitwise)
 * - Valeurs de retour : IDOK, IDCANCEL, IDYES, IDNO, etc.
 *
 * EXEMPLE DE FLAGS :
 * MB_OK                : Bouton OK uniquement
 * MB_YESNO             : Boutons Oui et Non
 * MB_ICONINFORMATION   : Icône info (i)
 * MB_ICONWARNING       : Icône warning (!)
 * MB_ICONERROR         : Icône erreur (X)
 */

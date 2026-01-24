/*
 * =============================================================================
 * Conventions d'appel
 * =============================================================================
 * 
 * Description : Comprendre les conventions d'appel x64 (System V ABI, Windows x64) et leur importance pour l'exploitation
 * 
 * Compilation :
 *   gcc example.c -o example
 * 
 * Usage :
 *   ./example
 * 
 * =============================================================================
 */

// On inclut stdio.h pour pouvoir utiliser printf()
// printf() permet d'afficher du texte dans la console
#include <stdio.h>

// On inclut stdlib.h pour les fonctions utilitaires standard
// Notamment malloc(), free(), exit(), etc.
#include <stdlib.h>

/*
 * Fonction principale - Point d'entrée du programme
 * 
 * argc : Nombre d'arguments passés au programme (toujours >= 1)
 * argv : Tableau de chaînes contenant les arguments
 *        argv[0] est toujours le nom du programme
 */
int main(int argc, char *argv[]) {
    
    // Affiche un message d'en-tête pour identifier le module
    // Le [*] est une convention pour indiquer une information
    printf("[*] Module : Conventions d'appel\n");
    printf("[*] ==========================================\n\n");
    
    // TODO: Implémenter le code exemple
    // Le code sera ajouté ici avec des commentaires détaillés
    // expliquant chaque étape pour les débutants
    
    printf("[+] Exemple terminé avec succès\n");
    
    // Retourne 0 pour indiquer que le programme s'est terminé sans erreur
    // Par convention : 0 = succès, autre valeur = erreur
    return 0;
}

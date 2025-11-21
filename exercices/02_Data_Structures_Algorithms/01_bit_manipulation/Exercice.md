# EXERCICE : MANIPULATION DE BITS


### OBJECTIF :
Créer un système de gestion de flags et permissions avec des opérations binaires.


### CONTEXTE :
Vous développez un système de contrôle d'accès pour une application sécurisée.
Chaque utilisateur a des permissions stockées sous forme de bits.

PERMISSIONS (Bits 0-7) :
- Bit 0 : READ (Lecture)
- Bit 1 : WRITE (Écriture)
- Bit 2 : EXECUTE (Exécution)
- Bit 3 : DELETE (Suppression)
- Bit 4 : ADMIN (Administrateur)
- Bit 5 : DEBUG (Mode debug)
- Bit 6 : AUDIT (Logs d'audit)
- Bit 7 : SUPER (Super utilisateur)

TÂCHES À IMPLÉMENTER :

1. Fonction grant_permission(permissions, flag)
   - Ajoute une permission (active un bit)
   - Exemple : grant_permission(0, READ) → 1

2. Fonction revoke_permission(permissions, flag)
   - Retire une permission (désactive un bit)
   - Exemple : revoke_permission(7, WRITE) → 5

3. Fonction has_permission(permissions, flag)
   - Vérifie si une permission est active
   - Retourne 1 (vrai) ou 0 (faux)

4. Fonction toggle_permission(permissions, flag)
   - Inverse l'état d'une permission

5. Fonction print_permissions(permissions)
   - Affiche toutes les permissions en format lisible
   - Exemple : "READ WRITE EXECUTE ADMIN"

6. Fonction count_permissions(permissions)
   - Compte le nombre de permissions actives


### EXERCICES BONUS :

7. Extraire le nibble (4 bits) de poids faible et de poids fort

8. Inverser tous les bits d'un byte

9. Vérifier si le nombre de bits à 1 est pair ou impair

10. Compresser 4 permissions (0-15) dans un seul byte


**EXEMPLE D'UTILISATION :**

unsigned char user_perms = 0;

// Donner des permissions
user_perms = grant_permission(user_perms, READ);
user_perms = grant_permission(user_perms, WRITE);
user_perms = grant_permission(user_perms, EXECUTE);

// Vérifier
if (has_permission(user_perms, WRITE)) {
    printf("L'utilisateur peut écrire\n");
}

// Afficher
print_permissions(user_perms);  // "READ WRITE EXECUTE"

// Compter
printf("Nombre de permissions : %d\n", count_permissions(user_perms));  // 3


### CONTRAINTES :
- Utiliser UNIQUEMENT des opérations binaires (&, |, ^, ~, <<, >>)
- PAS de if/else pour les opérations de base
- Optimiser pour la performance
- Gérer les cas limites (bits invalides, etc.)


### CONSEILS :
- Utilisez des #define pour les constantes de bits
- Pensez aux masques pour isoler les bits
- Testez chaque fonction individuellement
- Affichez en binaire pour débugger

FICHIERS À CRÉER :
- main.c : Votre implémentation
- Compilez avec : gcc main.c -o bitflags



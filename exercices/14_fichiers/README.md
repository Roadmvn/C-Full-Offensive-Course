# Manipulation de Fichiers

Lire et écrire des fichiers avec fopen, fread, fwrite, fclose.

```c
#include <stdio.h>

int main() {
    // Écriture dans un fichier
    FILE *fichier = fopen("test.txt", "w");  // "w" = write mode

    if (fichier == NULL) {
        printf("Erreur d'ouverture\n");
        return 1;
    }

    fprintf(fichier, "Bonjour le monde!\n");
    fprintf(fichier, "Ligne 2\n");

    fclose(fichier);  // Toujours fermer

    // Lecture du fichier
    fichier = fopen("test.txt", "r");  // "r" = read mode

    if (fichier == NULL) {
        printf("Erreur de lecture\n");
        return 1;
    }

    char ligne[100];
    while (fgets(ligne, sizeof(ligne), fichier)) {
        printf("%s", ligne);
    }

    fclose(fichier);
    return 0;
}
```

## Compilation
```bash
gcc example.c -o program
./program
```

## Concepts clés
- `fopen(nom, mode)` : ouvre un fichier ("r", "w", "a", "rb", "wb")
- `fclose(fichier)` : ferme le fichier (libère les ressources)
- `fprintf()` : écrit du texte formaté
- `fgets()` : lit une ligne
- `fread/fwrite()` : lecture/écriture binaire
- Toujours vérifier si fopen() retourne NULL

## Application Red Team

Les fichiers sont essentiels pour les droppers et stagers. Un dropper lit un payload chiffré depuis un fichier (ou l'extrait d'une image en stéganographie), le déchiffre en mémoire, puis l'exécute. La manipulation de fichiers binaires avec fread() permet de charger des DLL ou shellcodes complets.

Pour parser les fichiers PE, on ouvre le binaire en mode "rb" (read binary), on lit le DOS header, on saute au PE header avec fseek(), puis on parse les sections une par une. C'est crucial pour l'analyse statique de malware ou pour implémenter du PE injection.

Les techniques de persistence utilisent les fichiers pour écrire des payloads sur disque : copier le malware dans %APPDATA%, créer un fichier .bat dans Startup, ou modifier des fichiers de configuration. Un backdoor peut aussi créer un fichier de log chiffré pour exfiltrer des données progressivement sans connexion réseau constante.

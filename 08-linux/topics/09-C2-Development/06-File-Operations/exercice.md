# Exercice : File Operations Linux - Exfiltrateur de Credentials

## Objectif

Creer un programme qui :
1. Recherche des fichiers de credentials sur le systeme
2. Lit leur contenu
3. Les compresse dans une archive
4. Les chiffre avec XOR
5. Affiche le resultat en base64

## Specifications

### Fonctionnalites requises

1. **Recherche de fichiers**
   - Scanner `/home` et `/root` (si permissions)
   - Chercher : `id_rsa`, `id_dsa`, `id_ecdsa`, `.aws/credentials`, `.docker/config.json`
   - Limiter aux fichiers < 1MB

2. **Lecture**
   - Lire le contenu de chaque fichier trouve
   - Gerer les erreurs de permissions

3. **Archivage**
   - Creer une structure en memoire pour stocker tous les fichiers
   - Format simple : [taille_nom][nom][taille_contenu][contenu]

4. **Chiffrement**
   - XOR avec une cle : "MySecretKey2024"
   - Encoder en base64

5. **Sortie**
   - Afficher la liste des fichiers trouves
   - Afficher le blob base64 final

## Structure suggeree

```c
// Structure pour un fichier
typedef struct {
    char path[256];
    unsigned char *content;
    size_t size;
} FileEntry;

// Liste de fichiers
FileEntry *files = NULL;
int file_count = 0;

// Fonctions a implementer
void search_files(const char *base_path);
void read_file(const char *path);
void create_archive(unsigned char **output, size_t *output_size);
void xor_encrypt(unsigned char *data, size_t size, const char *key);
char* base64_encode(const unsigned char *data, size_t size);
```

## Tests

1. **Test basique**
   ```bash
   # Creer fichiers de test
   mkdir -p /tmp/test/.ssh
   echo "FAKE_PRIVATE_KEY" > /tmp/test/.ssh/id_rsa

   # Executer
   ./exfil /tmp/test
   ```

2. **Test reel (avec precautions)**
   ```bash
   # Scanner home directory
   ./exfil /home/$USER
   ```

## Criteres de reussite

- [ ] Trouve au moins les fichiers SSH si presents
- [ ] Lit correctement le contenu
- [ ] Archive tous les fichiers ensemble
- [ ] Chiffre avec XOR
- [ ] Encode en base64
- [ ] Gere les erreurs de permissions proprement
- [ ] Code bien commente

## Bonus

- Restaurer les timestamps apres lecture (stealth)
- Ajouter compression zlib avant chiffrement
- Implementer une limite de taille totale
- Ajouter un filtre par extension
- Sauvegarder le blob dans un fichier cache

## Conseils

1. Utiliser `stat()` pour verifier taille avant lecture
2. Allouer dynamiquement la memoire pour flexibilite
3. Liberer la memoire correctement (pas de leaks)
4. Tester avec `valgrind` pour verifier les fuites memoire
5. Utiliser `strerror(errno)` pour messages d'erreur explicites

## Solution

Voir `solution.c` pour une implementation complete.

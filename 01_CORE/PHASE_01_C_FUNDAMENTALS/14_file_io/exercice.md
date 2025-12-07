# Module 14 : File I/O - Exercices

## Exercice 1 : Lecture/Écriture Texte (Facile)

Crée un programme qui :
1. Crée un fichier `rapport.txt` en mode écriture
2. Écrit 5 lignes de texte (avec fprintf)
3. Ferme le fichier
4. Réouvre en lecture et affiche le contenu

**Objectif :** Maîtriser fopen, fprintf, fgets, fclose

---

## Exercice 2 : Mode Append (Facile)

Crée un programme qui simule un logger :
1. Ouvre `log.txt` en mode append ("a")
2. Ajoute l'heure actuelle et un message
3. Affiche le contenu complet du fichier

**Objectif :** Comprendre la différence entre "w" et "a"

---

## Exercice 3 : Copie de Fichier (Facile)

Crée une fonction `copy_file(src, dst)` qui :
1. Ouvre le fichier source en lecture
2. Ouvre le fichier destination en écriture
3. Copie tout le contenu caractère par caractère (fgetc/fputc)
4. Retourne le nombre de bytes copiés

**Objectif :** Lecture/écriture caractère par caractère

---

## Exercice 4 : Taille de Fichier (Moyen)

Crée une fonction `get_file_size(filename)` qui :
1. Ouvre le fichier en mode binaire
2. Utilise fseek + ftell pour calculer la taille
3. Retourne la taille en bytes (-1 si erreur)

**Objectif :** Navigation dans un fichier (fseek, ftell)

---

## Exercice 5 : Lecture Fichier Entier (Moyen)

Crée une fonction `read_entire_file(filename)` qui :
1. Calcule la taille du fichier
2. Alloue dynamiquement la mémoire nécessaire
3. Lit tout le contenu d'un coup (fread)
4. Retourne le buffer (appelant doit free)

**Objectif :** Allocation dynamique + lecture binaire

---

## Exercice 6 : Fichier Binaire - Structure (Moyen)

Crée un système de base de données simple :

```c
typedef struct {
    char username[32];
    char password_hash[64];
    int privilege_level;
} UserRecord;
```

1. Fonction `save_users(UserRecord *users, int count, const char *file)`
2. Fonction `load_users(const char *file, int *count)` qui retourne le tableau

**Objectif :** Sérialisation de structures

---

## Exercice 7 : Parser de Logs (Moyen)

Crée un programme qui parse un fichier de logs et extrait les lignes contenant "ERROR" ou "FAILED":

1. Ouvre `/var/log/syslog` (ou un fichier de test)
2. Lit ligne par ligne
3. Filtre et affiche les lignes suspectes
4. Compte le nombre d'occurrences

**Application Offensive :** Surveillance de logs

---

## Exercice 8 : Extraction de Payload (Avancé)

Crée un programme qui :
1. Lit un fichier binaire (ex: `payload.bin`)
2. Trouve un "magic marker" (ex: 0xDEADBEEF)
3. Extrait les bytes qui suivent le marker
4. Sauvegarde dans un nouveau fichier

```
payload.bin:
[...garbage...][0xDE 0xAD 0xBE 0xEF][SHELLCODE][0x00 0x00]
                      ↑                   ↑
               Magic marker          Data to extract
```

**Application Offensive :** Extraction de shellcode depuis un fichier

---

## Exercice 9 : Patching d'Exécutable (Avancé)

Crée un programme qui modifie un byte spécifique dans un fichier :

```c
int patch_file(const char *filename, long offset, unsigned char new_byte);
```

1. Ouvre le fichier en mode "r+b"
2. Se positionne à l'offset donné
3. Écrit le nouveau byte
4. Vérifie que l'écriture a réussi

**Application Offensive :** Patching binaire (bypass de vérifications)

---

## Exercice 10 : Exfiltration Config (Avancé)

Crée un programme d'exfiltration qui :
1. Lit plusieurs fichiers de configuration système
2. Compile les informations dans un seul fichier de rapport
3. Chiffre le rapport avec XOR simple

Fichiers à lire (si accessibles) :
- `/etc/passwd`
- `/etc/hostname`
- Variables d'environnement importantes

**Application Offensive :** Collecte d'informations système

---

## Exercice 11 : Stéganographie Basique (Challenge)

Crée un programme qui cache des données dans un fichier PNG :

1. Lit un fichier PNG
2. Trouve la fin des données PNG (IEND chunk)
3. Ajoute des données après la fin légitime
4. Crée une fonction pour extraire les données cachées

**Application Offensive :** Dissimulation de payload

---

## Exercice 12 : Implant Persistence (Challenge)

Crée un programme qui :
1. Lit son propre exécutable
2. Copie le fichier vers un emplacement persistant
3. Crée un script de démarrage automatique
4. Vérifie si déjà installé pour éviter les doublons

**Application Offensive :** Mécanisme de persistance

---

## Critères de Validation

Pour chaque exercice, vérifie :
- [ ] Gestion correcte des erreurs (fopen == NULL)
- [ ] Fermeture systématique des fichiers (fclose)
- [ ] Libération de la mémoire allouée
- [ ] Aucun buffer overflow
- [ ] Retour de valeurs cohérentes

---

## Conseils

```c
// TOUJOURS vérifier le retour de fopen
FILE *fp = fopen(filename, mode);
if (fp == NULL) {
    perror("fopen");
    return -1;
}

// TOUJOURS fermer les fichiers
fclose(fp);

// Pour fichiers binaires, utiliser "rb" ou "wb"
FILE *fp = fopen("data.bin", "rb");

// Pour modifier un fichier existant, utiliser "r+b"
FILE *fp = fopen("program.exe", "r+b");
```

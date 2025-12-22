# Week 3 - Structures & File I/O

## Vue d'ensemble

Cette semaine marque une étape cruciale dans ton apprentissage du C pour le maldev. Tu vas apprendre à manipuler des structures de données complexes et à lire/écrire des fichiers, deux compétences ESSENTIELLES pour analyser des PE, charger des shellcodes, et parser des headers.

## Objectifs de la semaine

À la fin de cette semaine, tu seras capable de :

- ✅ Créer et manipuler des structures (structs)
- ✅ Comprendre les unions et leur utilisation en maldev
- ✅ Utiliser les enums pour des constantes typées
- ✅ Lire et écrire des fichiers texte
- ✅ Manipuler des fichiers binaires
- ✅ Parser des headers de fichiers (préparation pour les PE)
- ✅ Valider des signatures et checksums

## Structure du contenu

### 📚 Lessons/

1. **01-structures.c** - Les bases des structures
   - Déclarer et initialiser des structs
   - Accès aux membres (. vs ->)
   - Pointeurs vers structures
   - Tableaux de structures
   - typedef pour simplifier
   - Preview : PROCESS_INFORMATION, STARTUPINFO

2. **02-unions-enums.c** - Unions, énumérations et bitfields
   - Différence struct vs union
   - Voir la même mémoire sous différents angles
   - Enums pour les constantes
   - Bitfields pour économiser la mémoire
   - Preview : PE Characteristics, Memory Protection

3. **03-file-io.c** - Entrées/sorties fichiers
   - fopen, fclose, fread, fwrite
   - Modes d'ouverture (r, w, a, rb, wb)
   - Lecture ligne par ligne (fgets)
   - Navigation (fseek, ftell, rewind)
   - Obtenir la taille d'un fichier
   - Preview : Charger un shellcode depuis un fichier

4. **04-binary-files.c** - Fichiers binaires et parsing
   - Différence texte vs binaire
   - Structures pour les headers
   - Signatures magiques (magic numbers)
   - Checksums et validation
   - Pattern matching dans les binaires
   - Patching de fichiers
   - Preview : DOS Header, PE parsing

### 💪 Exercises/

1. **ex01-person-struct.c** - Créer et manipuler une structure Person
   - Définir une structure avec plusieurs membres
   - Fonctions d'affichage et de modification
   - Tableaux de structures
   - Recherche et tri

2. **ex02-config-parser.c** - Parser un fichier de configuration
   - Format key=value
   - Gestion des commentaires
   - Manipulation de strings (strchr, strcmp, atoi)
   - Parsing ligne par ligne
   - Simulation d'une config C2

3. **ex03-binary-header.c** - Parser un header binaire (style maldev)
   - Créer un format de fichier custom
   - Header avec signature magique
   - Calcul et validation de checksum
   - Extraction de payload
   - Hex dump
   - Détection de corruption

### ✅ Solutions/

Les trois exercices avec solutions complètes et commentées.

### 📝 Quiz

10 questions pour tester ta compréhension :
- Structs vs unions
- File I/O
- Binary parsing
- Concepts maldev

Score minimum : 7/10

## Parcours d'apprentissage recommandé

### Jour 1-2 : Structures
1. Lis `Lessons/01-structures.c`
2. Compile et exécute pour voir les exemples
3. Fais `Exercises/ex01-person-struct.c`
4. Compare avec la solution

### Jour 3-4 : Unions, Enums et File I/O
1. Lis `Lessons/02-unions-enums.c`
2. Lis `Lessons/03-file-io.c`
3. Fais `Exercises/ex02-config-parser.c`
4. Expérimente avec différents formats de fichiers

### Jour 5-6 : Binary Parsing
1. Lis `Lessons/04-binary-files.c`
2. Fais `Exercises/ex03-binary-header.c`
3. Essaie de parser un vrai fichier PE (optionnel, avancé)

### Jour 7 : Révision et quiz
1. Relis les concepts clés
2. Fais le quiz
3. Reviens sur les points faibles

## Compilation

Tous les fichiers peuvent être compilés avec MSVC (cl.exe) sur Windows :

```batch
# Lessons
cl Lessons\01-structures.c
cl Lessons\02-unions-enums.c
cl Lessons\03-file-io.c
cl Lessons\04-binary-files.c

# Exercises
cl Exercises\ex01-person-struct.c
cl Exercises\ex02-config-parser.c
cl Exercises\ex03-binary-header.c

# Solutions
cl Solutions\sol01-person-struct.c
cl Solutions\sol02-config-parser.c
cl Solutions\sol03-binary-header.c
```

Ou utilise le script fourni :
```batch
build.bat
```

## Concepts clés

### Structures
```c
typedef struct {
    char nom[50];
    int age;
    float taille;
} Personne;

Personne p = {"Alice", 25, 1.65f};
printf("%s a %d ans\n", p.nom, p.age);

Personne* ptr = &p;
ptr->age = 26;  // Équivalent à (*ptr).age = 26
```

### Unions
```c
typedef union {
    unsigned int valeur;     // 4 bytes
    unsigned char bytes[4];  // 4 bytes (même mémoire!)
} DWORD_UNION;

DWORD_UNION dw;
dw.valeur = 0x12345678;
printf("%02X %02X %02X %02X\n",
       dw.bytes[0], dw.bytes[1], dw.bytes[2], dw.bytes[3]);
// Affiche: 78 56 34 12 (little-endian)
```

### File I/O
```c
// Écrire
FILE* f = fopen("data.bin", "wb");
fwrite(buffer, 1, size, f);
fclose(f);

// Lire
FILE* f = fopen("data.bin", "rb");
fseek(f, 0, SEEK_END);
long size = ftell(f);
rewind(f);
unsigned char* buf = malloc(size);
fread(buf, 1, size, f);
fclose(f);
```

### Binary Parsing
```c
typedef struct {
    unsigned int magic;      // Signature
    unsigned int size;       // Taille
    unsigned int checksum;   // Vérification
} Header;

FILE* f = fopen("file.bin", "rb");
Header h;
fread(&h, sizeof(Header), 1, f);

if (h.magic != 0xDEADBEEF) {
    printf("Signature invalide!\n");
}
```

## Lien avec le Maldev

### Cette semaine te prépare pour :

1. **PE Parsing** (Week 4+)
   - Les PE Windows sont des fichiers binaires avec headers
   - DOS Header, PE Header, Sections
   - Exactement ce que tu pratiques cette semaine !

2. **Process Injection**
   - Utilisation de structures Windows (PROCESS_INFORMATION, etc.)
   - Lecture de shellcodes depuis des fichiers
   - Manipulation de mémoire via structures

3. **Shellcoding**
   - Sauvegarder/charger des shellcodes binaires
   - Parser des opcodes
   - Analyse de payloads

4. **C2 Development**
   - Fichiers de configuration
   - Parsing de commandes
   - Exfiltration de données

## Ressources supplémentaires

### Documentation Microsoft
- [PE Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [File I/O Functions](https://docs.microsoft.com/en-us/cpp/c-runtime-library/stream-i-o)

### Outils utiles
- **HxD** : Éditeur hexadécimal pour visualiser les fichiers binaires
- **PE-bear** : Analyseur de PE pour voir les headers
- **010 Editor** : Éditeur hex avec templates pour les formats de fichiers

## Défis bonus

Si tu veux aller plus loin :

1. **Parser un vrai PE** : Ouvre notepad.exe et parse son DOS Header
2. **Créer un crypteur simple** : Chiffre un fichier avec XOR et crée un header
3. **Implémenter CRC32** : Checksum plus robuste que la simple somme
4. **Multi-section file** : Format de fichier avec plusieurs sections

## Points de contrôle

Avant de passer à la Week 4, assure-toi de :

- [ ] Comprendre la différence struct vs union
- [ ] Savoir utiliser l'opérateur -> avec les pointeurs
- [ ] Pouvoir lire/écrire des fichiers binaires
- [ ] Comprendre le concept de magic number
- [ ] Savoir calculer et vérifier un checksum
- [ ] Avoir réussi les 3 exercices
- [ ] Score ≥ 7/10 au quiz

## Notes importantes

1. **Toujours initialiser les structures** : `Config c = {0};`
2. **Toujours vérifier fopen()** : `if (f == NULL) { ... }`
3. **Toujours fermer les fichiers** : `fclose(f);`
4. **Validation is key** : Magic numbers, checksums, tailles
5. **Little-endian matters** : Sur x86/x64, les bytes sont inversés

## Prochaine étape

Week 4 - First WinAPI : Tu vas commencer à utiliser les vraies API Windows !

---

**Bon courage et bon parsing !** 🚀

*Cette semaine est intensive mais CRUCIALE. Les structures et le file I/O sont utilisés PARTOUT en maldev. Prends ton temps pour bien comprendre.*

# EXERCICE : HASH TABLES


### OBJECTIF :
Implémenter des applications pratiques de tables de hachage.

═══════════════════════════════════════════════════════════════

### PARTIE 1 : DICTIONNAIRE ANGLAIS-FRANÇAIS
═══════════════════════════════════════════════════════════════

Créer un dictionnaire de traduction avec hash table.


### FONCTIONS :
1. add_translation(dict, english, french)
2. translate(dict, english) → retourne traduction
3. print_dictionary(dict)
4. load_from_file(dict, filename)


### EXEMPLE :
add_translation(dict, "hello", "bonjour");
add_translation(dict, "world", "monde");
translate(dict, "hello") → "bonjour"

═══════════════════════════════════════════════════════════════

### PARTIE 2 : COMPTEUR DE MOTS
═══════════════════════════════════════════════════════════════

Compter la fréquence des mots dans un texte.


### FONCTIONS :
1. count_words(text) → crée hash table avec compteurs
2. get_count(table, word) → retourne fréquence
3. get_top_n_words(table, n) → top n mots les plus fréquents
4. print_statistics(table)


### EXEMPLE :
"the cat and the dog" → {the:2, cat:1, and:1, dog:1}

═══════════════════════════════════════════════════════════════

### PARTIE 3 : CACHE LRU
═══════════════════════════════════════════════════════════════

Implémenter un cache avec éviction LRU (Least Recently Used).


### STRUCTURE :
- Hash table pour accès O(1)
- Liste doublement chaînée pour ordre d'utilisation


### FONCTIONS :
1. cache_put(cache, key, value) - ajoute/met à jour
2. cache_get(cache, key) - récupère et marque comme récent
3. Si cache plein → éviction du LRU

═══════════════════════════════════════════════════════════════

### PARTIE 4 : DÉTECTION DE DOUBLONS
═══════════════════════════════════════════════════════════════

Utiliser un set (hash table) pour détecter les doublons.


### FONCTIONS :
1. has_duplicates(array, size) → retourne 1 si doublons
2. remove_duplicates(array, size) → retourne nouveau tableau
3. find_first_duplicate(array, size) → retourne valeur

═══════════════════════════════════════════════════════════════

### PARTIE 5 : ANAGRAMMES
═══════════════════════════════════════════════════════════════

Grouper les anagrammes ensemble.


### FONCTION :
group_anagrams(words[], count)


### EXEMPLE :
["eat", "tea", "tan", "ate", "nat", "bat"]
→ {
    "aet": ["eat", "tea", "ate"],
    "ant": ["tan", "nat"],
    "abt": ["bat"]
  }

ASTUCE : Clé = mot trié alphabétiquement

FICHIERS À CRÉER :
- main.c : Implémentation complète
- test_data.txt : Données de test
- Compilation : gcc main.c -o hashtable -Wall



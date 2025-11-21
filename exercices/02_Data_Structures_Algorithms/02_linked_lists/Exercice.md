# EXERCICE : LISTE CHAÎNÉE


### OBJECTIF :
Implémenter une liste chaînée complète avec des opérations avancées.


### CONTEXTE :
Vous créez un gestionnaire de playlist musicale où chaque chanson est
un nœud dans une liste chaînée.

STRUCTURE DES DONNÉES :

typedef struct Song {
    char title[100];       // Titre de la chanson
    char artist[100];      // Artiste
    int duration;          // Durée en secondes
    struct Song *next;     // Chanson suivante
} Song;

TÂCHES À IMPLÉMENTER :


## FONCTIONS DE BASE

1. create_song(title, artist, duration)
   - Alloue et initialise un nouveau nœud Song
   - Retourne le pointeur vers la chanson

2. add_song_at_end(playlist, song)
   - Ajoute une chanson à la fin de la playlist
   - Si playlist vide, devient le premier élément

3. add_song_at_beginning(playlist, song)
   - Ajoute une chanson au début de la playlist

4. print_playlist(playlist)
   - Affiche toutes les chansons avec leur durée
   - Format : "1. Title - Artist (3:45)"

5. count_songs(playlist)
   - Retourne le nombre total de chansons

6. total_duration(playlist)
   - Calcule et retourne la durée totale en secondes
   - Affiche au format HH:MM:SS


## FONCTIONS DE RECHERCHE

7. find_song_by_title(playlist, title)
   - Recherche une chanson par son titre
   - Retourne le pointeur ou NULL

8. find_song_by_artist(playlist, artist)
   - Retourne la première chanson de cet artiste

9. get_song_at_position(playlist, position)
   - Retourne la chanson à la position N (indexé à 1)


## FONCTIONS DE MODIFICATION

10. remove_song(playlist, title)
    - Supprime une chanson de la playlist
    - Libère la mémoire

11. remove_at_position(playlist, position)
    - Supprime la chanson à la position donnée

12. swap_songs(playlist, pos1, pos2)
    - Échange deux chansons de position

13. move_song(playlist, from, to)
    - Déplace une chanson d'une position à une autre


## FONCTIONS AVANCÉES

14. reverse_playlist(playlist)
    - Inverse l'ordre de toute la playlist

15. shuffle_playlist(playlist)
    - Mélange aléatoirement la playlist
    - Utilisez rand() pour la randomisation

16. sort_by_title(playlist)
    - Trie la playlist par ordre alphabétique de titre
    - Utilisez bubble sort ou insertion sort

17. sort_by_duration(playlist)
    - Trie du plus court au plus long

18. split_playlist(playlist, position)
    - Coupe la playlist en deux à la position donnée
    - Retourne un pointeur vers la deuxième partie

19. merge_playlists(playlist1, playlist2)
    - Fusionne deux playlists (ajoute playlist2 à la fin de playlist1)

20. duplicate_playlist(playlist)
    - Crée une copie complète de la playlist
    - Alloue de nouveaux nœuds


## FONCTIONS UTILITAIRES

21. save_playlist(playlist, filename)
    - Sauvegarde la playlist dans un fichier texte

22. load_playlist(filename)
    - Charge une playlist depuis un fichier
    - Retourne le pointeur vers la playlist créée

23. free_playlist(playlist)
    - Libère toute la mémoire de la playlist


**EXEMPLE D'UTILISATION :**

Song *playlist = NULL;

// Ajouter des chansons
add_song_at_end(&playlist, create_song("Bohemian Rhapsody", "Queen", 354));
add_song_at_end(&playlist, create_song("Imagine", "John Lennon", 183));
add_song_at_end(&playlist, create_song("Hotel California", "Eagles", 391));

// Afficher
print_playlist(playlist);
printf("Total : %d chansons, Durée : ", count_songs(playlist));
print_duration(total_duration(playlist));

// Rechercher
Song *found = find_song_by_title(playlist, "Imagine");
if (found) {
    printf("Trouvé : %s par %s\n", found->title, found->artist);
}

// Modifier
reverse_playlist(&playlist);
sort_by_title(&playlist);

// Libérer
free_playlist(&playlist);

BONUS - PLAYLIST CIRCULAIRE :

24. make_circular(playlist)
    - Transforme la liste en liste circulaire (dernier → premier)

25. play_song_n_times(playlist, n)
    - Joue toute la playlist n fois (avec liste circulaire)


### CONTRAINTES :
- Gérer tous les cas limites (liste vide, un seul élément, etc.)
- Vérifier tous les malloc() (retour NULL = échec)
- Libérer TOUTE la mémoire allouée
- Pas de memory leaks (vérifier avec valgrind)


### CONSEILS :
- Dessinez les pointeurs sur papier avant de coder
- Testez chaque fonction individuellement
- Utilisez print_playlist() pour débugger
- Attention aux cas spéciaux (head, tail, milieu)

FICHIERS À CRÉER :
- main.c : Votre implémentation complète
- Compilez avec : gcc main.c -o playlist -Wall -Wextra
- Testez avec : valgrind ./playlist (pour vérifier les leaks)



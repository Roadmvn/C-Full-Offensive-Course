# SOLUTION : LISTE CHAÎNÉE - PLAYLIST MUSICALE

Voici une implémentation complète d'un gestionnaire de playlist avec listes chaînées.


---
FICHIER : main.c

---


```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
```


```c
// Structure Song (Chanson)
typedef struct Song {
    char title[100];
    char artist[100];
    int duration;        // En secondes
```
    struct Song *next;
} Song;


```c
// ============= FONCTIONS DE BASE =============
```


```c
// 1. Créer une chanson
```
Song* create_song(const char *title, const char *artist, int duration) {
    Song *new_song = malloc(sizeof(Song));
    if (new_song == NULL) {
        fprintf(stderr, "Erreur allocation mémoire\n");
        exit(1);
    }
    strncpy(new_song->title, title, 99);
    new_song->title[99] = '\0';
    strncpy(new_song->artist, artist, 99);
    new_song->artist[99] = '\0';
    new_song->duration = duration;
    new_song->next = NULL;
    return new_song;
}


```c
// 2. Ajouter à la fin
void add_song_at_end(Song **playlist, Song *song) {
```
    if (*playlist == NULL) {
        *playlist = song;
        return;
    }
    
    Song *current = *playlist;
    while (current->next != NULL) {
        current = current->next;
    }
    current->next = song;
}


```c
// 3. Ajouter au début
void add_song_at_beginning(Song **playlist, Song *song) {
```
    song->next = *playlist;
    *playlist = song;
}


```c
// 4. Afficher la playlist
void print_playlist(Song *playlist) {
```
    if (playlist == NULL) {
        printf("Playlist vide\n");
        return;
    }
    
    int i = 1;
    Song *current = playlist;
    while (current != NULL) {
        int min = current->duration / 60;
        int sec = current->duration % 60;
        printf("%d. %s - %s (%d:%02d)\n", i, current->title, 
               current->artist, min, sec);
        current = current->next;
        i++;
    }
}


```c
// 5. Compter les chansons
int count_songs(Song *playlist) {
    int count = 0;
```
    Song *current = playlist;
    while (current != NULL) {
        count++;
        current = current->next;
    }
    return count;
}


```c
// 6. Durée totale
int total_duration(Song *playlist) {
    int total = 0;
```
    Song *current = playlist;
    while (current != NULL) {
        total += current->duration;
        current = current->next;
    }
    return total;
}


```c
void print_duration(int seconds) {
    int h = seconds / 3600;
    int m = (seconds % 3600) / 60;
    int s = seconds % 60;
```
    printf("%02d:%02d:%02d\n", h, m, s);
}


```c
// ============= RECHERCHE =============
```


```c
// 7. Trouver par titre
```
Song* find_song_by_title(Song *playlist, const char *title) {
    Song *current = playlist;
    while (current != NULL) {
        if (strcmp(current->title, title) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}


```c
// 8. Trouver par artiste
```
Song* find_song_by_artist(Song *playlist, const char *artist) {
    Song *current = playlist;
    while (current != NULL) {
        if (strcmp(current->artist, artist) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}


```c
// 9. Obtenir à la position
```
Song* get_song_at_position(Song *playlist, int position) {
    if (position < 1) return NULL;
    
    Song *current = playlist;
    int i = 1;
    while (current != NULL && i < position) {
        current = current->next;
        i++;
    }
    return current;
}


```c
// ============= MODIFICATION =============
```


```c
// 10. Supprimer par titre
void remove_song(Song **playlist, const char *title) {
```
    if (*playlist == NULL) return;
    

```c
    // Cas spécial : le premier
```
    if (strcmp((*playlist)->title, title) == 0) {
        Song *temp = *playlist;
        *playlist = (*playlist)->next;
        free(temp);
        return;
    }
    
    Song *current = *playlist;
    while (current->next != NULL) {
        if (strcmp(current->next->title, title) == 0) {
            Song *temp = current->next;
            current->next = current->next->next;
            free(temp);
            return;
        }
        current = current->next;
    }
}


```c
// 11. Supprimer à la position
void remove_at_position(Song **playlist, int position) {
```
    if (*playlist == NULL || position < 1) return;
    

```c
    // Cas spécial : position 1
```
    if (position == 1) {
        Song *temp = *playlist;
        *playlist = (*playlist)->next;
        free(temp);
        return;
    }
    
    Song *current = *playlist;
    int i = 1;
    while (current->next != NULL && i < position - 1) {
        current = current->next;
        i++;
    }
    
    if (current->next != NULL) {
        Song *temp = current->next;
        current->next = current->next->next;
        free(temp);
    }
}


```c
// ============= AVANCÉES =============
```


```c
// 14. Inverser la playlist
void reverse_playlist(Song **playlist) {
```
    Song *prev = NULL;
    Song *current = *playlist;
    Song *next = NULL;
    
    while (current != NULL) {
        next = current->next;
        current->next = prev;
        prev = current;
        current = next;
    }
    *playlist = prev;
}


```c
// 16. Trier par titre (Bubble Sort)
void sort_by_title(Song **playlist) {
```
    if (*playlist == NULL || (*playlist)->next == NULL) return;
    
    int swapped;
    Song *current;
    Song *last = NULL;
    
    do {
        swapped = 0;
        current = *playlist;
        
        while (current->next != last) {
            if (strcmp(current->title, current->next->title) > 0) {

```c
                // Swap les données (pas les pointeurs)
                char temp_title[100], temp_artist[100];
                int temp_duration;
```

                strcpy(temp_title, current->title);
                strcpy(temp_artist, current->artist);
                temp_duration = current->duration;
                
                strcpy(current->title, current->next->title);
                strcpy(current->artist, current->next->artist);
                current->duration = current->next->duration;
                
                strcpy(current->next->title, temp_title);
                strcpy(current->next->artist, temp_artist);
                current->next->duration = temp_duration;
                
                swapped = 1;
            }
            current = current->next;
        }
        last = current;
    } while (swapped);
}


```c
// 17. Trier par durée
void sort_by_duration(Song **playlist) {
```
    if (*playlist == NULL || (*playlist)->next == NULL) return;
    
    int swapped;
    Song *current;
    Song *last = NULL;
    
    do {
        swapped = 0;
        current = *playlist;
        
        while (current->next != last) {
            if (current->duration > current->next->duration) {

```c
                // Swap
                char temp_title[100], temp_artist[100];
                int temp_duration;
```

                strcpy(temp_title, current->title);
                strcpy(temp_artist, current->artist);
                temp_duration = current->duration;
                
                strcpy(current->title, current->next->title);
                strcpy(current->artist, current->next->artist);
                current->duration = current->next->duration;
                
                strcpy(current->next->title, temp_title);
                strcpy(current->next->artist, temp_artist);
                current->next->duration = temp_duration;
                
                swapped = 1;
            }
            current = current->next;
        }
        last = current;
    } while (swapped);
}


```c
// 19. Fusionner deux playlists
void merge_playlists(Song **playlist1, Song *playlist2) {
```
    if (*playlist1 == NULL) {
        *playlist1 = playlist2;
        return;
    }
    
    Song *current = *playlist1;
    while (current->next != NULL) {
        current = current->next;
    }
    current->next = playlist2;
}


```c
// 20. Dupliquer la playlist
```
Song* duplicate_playlist(Song *playlist) {
    if (playlist == NULL) return NULL;
    
    Song *new_playlist = NULL;
    Song *current = playlist;
    
    while (current != NULL) {
        Song *new_song = create_song(current->title, current->artist, 
                                      current->duration);
        add_song_at_end(&new_playlist, new_song);
        current = current->next;
    }
    
    return new_playlist;
}


```c
// 23. Libérer la playlist
void free_playlist(Song **playlist) {
```
    Song *current = *playlist;
    while (current != NULL) {
        Song *temp = current;
        current = current->next;
        free(temp);
    }
    *playlist = NULL;
}


```c
// ============= MAIN - DÉMONSTRATION =============
```


```c
int main() {
```
    printf("╔═══════════════════════════════════════╗\n");
    printf("║    GESTIONNAIRE DE PLAYLIST MUSICALE  ║\n");
    printf("╚═══════════════════════════════════════╝\n\n");
    
    Song *playlist = NULL;
    

```c
    // Ajouter des chansons
```
    printf("1. AJOUT DE CHANSONS\n");
    add_song_at_end(&playlist, create_song("Bohemian Rhapsody", "Queen", 354));
    add_song_at_end(&playlist, create_song("Imagine", "John Lennon", 183));
    add_song_at_end(&playlist, create_song("Hotel California", "Eagles", 391));
    add_song_at_end(&playlist, create_song("Smells Like Teen Spirit", "Nirvana", 301));
    add_song_at_end(&playlist, create_song("Billie Jean", "Michael Jackson", 294));
    
    print_playlist(playlist);
    printf("\nTotal : %d chansons, Durée : ", count_songs(playlist));
    print_duration(total_duration(playlist));
    

```c
    // Recherche
```
    printf("\n2. RECHERCHE\n");
    Song *found = find_song_by_title(playlist, "Imagine");
    if (found) {
        printf("Trouvé : '%s' par %s\n", found->title, found->artist);
    }
    

```c
    // Position
```
    Song *third = get_song_at_position(playlist, 3);
    if (third) {
        printf("Chanson #3 : %s\n", third->title);
    }
    

```c
    // Suppression
```
    printf("\n3. SUPPRESSION\n");
    remove_song(&playlist, "Imagine");
    printf("Après suppression de 'Imagine' :\n");
    print_playlist(playlist);
    

```c
    // Inversion
```
    printf("\n4. INVERSION\n");
    reverse_playlist(&playlist);
    print_playlist(playlist);
    

```c
    // Tri par titre
```
    printf("\n5. TRI PAR TITRE\n");
    sort_by_title(&playlist);
    print_playlist(playlist);
    

```c
    // Tri par durée
```
    printf("\n6. TRI PAR DURÉE\n");
    sort_by_duration(&playlist);
    print_playlist(playlist);
    

```c
    // Duplication
```
    printf("\n7. DUPLICATION\n");
    Song *playlist2 = duplicate_playlist(playlist);
    printf("Playlist originale :\n");
    print_playlist(playlist);
    printf("\nPlaylist dupliquée :\n");
    print_playlist(playlist2);
    

```c
    // Fusion
```
    printf("\n8. FUSION\n");
    Song *playlist3 = NULL;
    add_song_at_end(&playlist3, create_song("Stairway to Heaven", "Led Zeppelin", 482));
    add_song_at_end(&playlist3, create_song("November Rain", "Guns N' Roses", 537));
    
    printf("Playlist 3 :\n");
    print_playlist(playlist3);
    
    merge_playlists(&playlist, playlist3);
    printf("\nAprès fusion :\n");
    print_playlist(playlist);
    

```c
    // Libération
```
    printf("\n9. LIBÉRATION MÉMOIRE\n");
    free_playlist(&playlist);
    free_playlist(&playlist2);
    
    printf("Playlists libérées.\n");
    printf("\n═══════════════════════════════════════\n");
    printf("Programme terminé avec succès.\n");
    
    return 0;
}


---
COMPILATION ET EXÉCUTION

---

gcc main.c -o playlist -Wall -Wextra
./playlist


```bash
# Vérifier les memory leaks
```
valgrind --leak-check=full ./playlist


---
COMPLEXITÉ DES OPÉRATIONS

---

add_song_at_beginning  : O(1)
add_song_at_end        : O(n)
find_song_by_title     : O(n)
remove_song            : O(n)
reverse_playlist       : O(n)
sort_by_title          : O(n²) - Bubble Sort
duplicate_playlist     : O(n)
merge_playlists        : O(n)
free_playlist          : O(n)


---
FIN DE LA SOLUTION

---



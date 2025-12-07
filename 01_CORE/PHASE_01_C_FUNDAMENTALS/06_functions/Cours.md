# 07 - Boucles (Loops)

## 🎯 Ce que tu vas apprendre

- Ce qu'est une boucle et pourquoi elle existe
- Les trois types de boucles : for, while, do-while
- Les instructions break et continue
- Les boucles imbriquées
- Comment éviter les boucles infinies

## 📚 Théorie

### Concept 1 : C'est quoi une boucle ?

**C'est quoi ?**
Une boucle permet de répéter un bloc de code plusieurs fois, tant qu'une condition est vraie.

**Pourquoi ça existe ?**
Sans boucles, tu devrais copier-coller le même code des centaines de fois. Les boucles automatisent la répétition.

**Comment ça marche ?**

Le processeur exécute le code, teste une condition, et recommence si la condition est vraie.

```c
// Sans boucle (répétitif) :
printf("0\n");
printf("1\n");
printf("2\n");
printf("3\n");
printf("4\n");

// Avec boucle (automatique) :
for (int i = 0; i < 5; i++) {
    printf("%d\n", i);
}
```

### Concept 2 : Boucle for

**C'est quoi ?**
La boucle `for` est utilisée quand tu connais le nombre d'itérations à l'avance.

**Syntaxe** :
```c
for (initialisation; condition; incrémentation) {
    // Code à répéter
}
```

**Décomposition** :
```c
for (int i = 0; i < 10; i++) {
    printf("%d\n", i);
}
```

**Processus d'exécution** :
```
1. Initialisation : int i = 0 (exécutée UNE SEULE FOIS)
2. Test condition : i < 10 ? (si faux → sort de la boucle)
3. Exécute le bloc : printf("%d\n", i);
4. Incrémentation : i++
5. Retour à l'étape 2
```

**Schéma** :
```
┌─────────────────────────────────┐
│ 1. Initialisation : i = 0       │
└──────────┬──────────────────────┘
           ↓
┌──────────▼──────────────────────┐
│ 2. Test : i < 10 ?              │
└──────────┬──────────────────────┘
           │ Vrai
           ↓
┌──────────▼──────────────────────┐
│ 3. Exécute le bloc              │
└──────────┬──────────────────────┘
           ↓
┌──────────▼──────────────────────┐
│ 4. Incrémentation : i++         │
└──────────┬──────────────────────┘
           │
           └──> Retour à l'étape 2

           Faux → Sort de la boucle
```

**Exemple avec trace** :
```c
for (int i = 0; i < 3; i++) {
    printf("i = %d\n", i);
}

Itération 1 : i=0, test 0<3 (vrai), affiche "i = 0", i++ → i=1
Itération 2 : i=1, test 1<3 (vrai), affiche "i = 1", i++ → i=2
Itération 3 : i=2, test 2<3 (vrai), affiche "i = 2", i++ → i=3
Itération 4 : i=3, test 3<3 (faux) → Sort

Output :
i = 0
i = 1
i = 2
```

**Variations** :
```c
// Compter à l'envers
for (int i = 10; i > 0; i--) {
    printf("%d\n", i);
}

// Incrémenter de 2
for (int i = 0; i < 10; i += 2) {
    printf("%d\n", i);  // 0, 2, 4, 6, 8
}

// Multiple variables
for (int i = 0, j = 10; i < 10; i++, j--) {
    printf("i=%d, j=%d\n", i, j);
}
```

### Concept 3 : Boucle while

**C'est quoi ?**
La boucle `while` est utilisée quand tu ne connais pas le nombre d'itérations à l'avance.

**Syntaxe** :
```c
while (condition) {
    // Code à répéter
}
```

**La condition est testée AVANT chaque itération.**

**Exemple** :
```c
int i = 0;
while (i < 5) {
    printf("%d\n", i);
    i++;
}
```

**Processus** :
```
1. Test condition : i < 5 ?
2. Si vrai : exécute le bloc
3. Retour à l'étape 1
4. Si faux : sort de la boucle
```

**Cas d'usage** :
```c
// Lire jusqu'à EOF
char c;
while ((c = getchar()) != EOF) {
    process(c);
}

// Boucle de serveur
while (server_running) {
    handle_request();
}
```

### Concept 4 : Boucle do-while

**C'est quoi ?**
Similaire à `while`, MAIS la condition est testée APRÈS le bloc. Garantit AU MOINS UNE exécution.

**Syntaxe** :
```c
do {
    // Code exécuté au moins une fois
} while (condition);
```

**Différence clé** :

```c
// while : peut ne jamais s'exécuter
int x = 10;
while (x < 5) {
    printf("Jamais affiché\n");
}

// do-while : s'exécute AU MOINS une fois
int x = 10;
do {
    printf("Affiché une fois\n");
} while (x < 5);
```

**Cas d'usage** :
```c
// Menu qui doit s'afficher au moins une fois
int choice;
do {
    printf("1. Option 1\n");
    printf("2. Option 2\n");
    printf("0. Quit\n");
    scanf("%d", &choice);
} while (choice != 0);
```

### Concept 5 : break - Sortir d'une boucle

**C'est quoi ?**
`break` sort immédiatement de la boucle, peu importe la condition.

**Exemple** :
```c
for (int i = 0; i < 100; i++) {
    if (i == 5) {
        break;  // Sort quand i == 5
    }
    printf("%d\n", i);
}
// Affiche : 0, 1, 2, 3, 4
```

**Schéma** :
```
i=0 : test, affiche, i++
i=1 : test, affiche, i++
i=2 : test, affiche, i++
i=3 : test, affiche, i++
i=4 : test, affiche, i++
i=5 : test, break → SORT DE LA BOUCLE
```

**Cas d'usage** :
```c
// Recherche dans un tableau
int found = 0;
for (int i = 0; i < size; i++) {
    if (array[i] == target) {
        found = 1;
        break;  // Trouvé, pas besoin de continuer
    }
}
```

### Concept 6 : continue - Passer à l'itération suivante

**C'est quoi ?**
`continue` saute le reste du bloc et passe immédiatement à l'itération suivante.

**Exemple** :
```c
for (int i = 0; i < 10; i++) {
    if (i % 2 == 0) {
        continue;  // Saute les pairs
    }
    printf("%d\n", i);  // Affiche seulement les impairs
}
// Output : 1, 3, 5, 7, 9
```

**Schéma** :
```
i=0 : pair → continue → passe au suivant
i=1 : impair → affiche 1
i=2 : pair → continue → passe au suivant
i=3 : impair → affiche 3
...
```

**Différence break vs continue** :
```c
// break : SORT de la boucle
for (int i = 0; i < 10; i++) {
    if (i == 5) break;
    printf("%d ", i);  // 0 1 2 3 4
}

// continue : PASSE au suivant
for (int i = 0; i < 10; i++) {
    if (i == 5) continue;
    printf("%d ", i);  // 0 1 2 3 4 6 7 8 9 (pas de 5)
}
```

### Concept 7 : Boucles imbriquées

**C'est quoi ?**
Une boucle à l'intérieur d'une autre boucle.

**Exemple** :
```c
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        printf("(%d, %d) ", i, j);
    }
    printf("\n");
}
```

**Output** :
```
(0, 0) (0, 1) (0, 2)
(1, 0) (1, 1) (1, 2)
(2, 0) (2, 1) (2, 2)
```

**Processus** :
```
i=0 : j=0,1,2 → affiche (0,0), (0,1), (0,2)
i=1 : j=0,1,2 → affiche (1,0), (1,1), (1,2)
i=2 : j=0,1,2 → affiche (2,0), (2,1), (2,2)
```

**Complexité** : Si 2 boucles de N itérations → N*N = N² opérations.

### Concept 8 : Boucle infinie

**C'est quoi ?**
Une boucle qui ne se termine jamais.

**Volontaire** :
```c
// Serveur qui tourne en continu
while (1) {  // ou for(;;)
    handle_request();
}
```

**Accidentelle (BUG)** :
```c
int i = 0;
while (i < 10) {
    printf("%d\n", i);
    // OUBLI : pas de i++
    // Boucle infinie : i reste à 0
}
```

**Pour l'arrêter** :
- Ctrl+C dans le terminal
- Utiliser break avec une condition

```c
while (1) {
    if (should_stop()) {
        break;  // Sortie propre
    }
    // ...
}
```

### Concept 9 : Parcourir un tableau

**Méthode classique** :
```c
int numbers[] = {10, 20, 30, 40, 50};
int size = 5;

for (int i = 0; i < size; i++) {
    printf("numbers[%d] = %d\n", i, numbers[i]);
}
```

**Avec sizeof** :
```c
int numbers[] = {10, 20, 30, 40, 50};
int size = sizeof(numbers) / sizeof(numbers[0]);

for (int i = 0; i < size; i++) {
    printf("%d\n", numbers[i]);
}
```

### Concept 10 : Compteurs et accumulateurs

**Compteur (count)** :
```c
int count = 0;
for (int i = 0; i < 100; i++) {
    if (i % 2 == 0) {
        count++;  // Compte les pairs
    }
}
printf("Pairs : %d\n", count);  // 50
```

**Accumulateur (sum)** :
```c
int sum = 0;
for (int i = 1; i <= 10; i++) {
    sum += i;  // Somme : 1+2+3+...+10
}
printf("Somme : %d\n", sum);  // 55
```

## 🔍 Visualisation : Trace d'exécution

```c
int factorial = 1;
for (int i = 1; i <= 4; i++) {
    factorial *= i;
}
```

**Trace** :
```
Initialisation : i=1, factorial=1

Itération 1 :
   Test : 1 <= 4 ? Vrai
   factorial = 1 * 1 = 1
   i++ → i=2

Itération 2 :
   Test : 2 <= 4 ? Vrai
   factorial = 1 * 2 = 2
   i++ → i=3

Itération 3 :
   Test : 3 <= 4 ? Vrai
   factorial = 2 * 3 = 6
   i++ → i=4

Itération 4 :
   Test : 4 <= 4 ? Vrai
   factorial = 6 * 4 = 24
   i++ → i=5

Itération 5 :
   Test : 5 <= 4 ? Faux
   → Sort de la boucle

Résultat : factorial = 24
```

## 🎯 Application Red Team

### 1. Scanner de ports

```c
char* ip = "192.168.1.1";
for (int port = 1; port <= 1024; port++) {
    if (can_connect(ip, port)) {
        printf("Port %d : OPEN\n", port);
    }
}
```

### 2. Brute force

```c
char* passwords[] = {"admin", "password", "123456", "root"};
int size = 4;

for (int i = 0; i < size; i++) {
    if (try_login(username, passwords[i])) {
        printf("Password found: %s\n", passwords[i]);
        break;  // Arrête dès qu'on trouve
    }
}
```

### 3. XOR Encoder/Decoder

```c
unsigned char shellcode[] = {0x90, 0x90, 0x31, 0xc0, 0x50};
unsigned char key = 0xAA;
int size = sizeof(shellcode);

// Encoder
for (int i = 0; i < size; i++) {
    shellcode[i] ^= key;
}

// Décoder (même opération)
for (int i = 0; i < size; i++) {
    shellcode[i] ^= key;
}
```

### 4. Parsing de données binaires

```c
unsigned char packet[1500];
int packet_len = recv_packet(packet);

for (int i = 0; i < packet_len; i++) {
    if (packet[i] == 0xFF && packet[i+1] == 0xD9) {
        printf("JPEG end marker at offset %d\n", i);
        break;
    }
}
```

### 5. Reconnaissance réseau

```c
// Scanner un sous-réseau
char base_ip[] = "192.168.1.";
for (int i = 1; i < 255; i++) {
    char ip[16];
    sprintf(ip, "%s%d", base_ip, i);
    if (ping(ip)) {
        printf("Host %s is UP\n", ip);
    }
}
```

### 6. Event loop (C2 beacon)

```c
while (1) {
    char* command = check_for_command();
    if (command != NULL) {
        execute_command(command);
        send_result();
    }
    sleep(60);  // Attendre 1 minute
}
```

### 7. Recherche de pattern en mémoire

```c
unsigned char pattern[] = {0x48, 0x8B, 0x05};  // mov rax, [rip+...]
int pattern_len = 3;

for (int i = 0; i < mem_size - pattern_len; i++) {
    int found = 1;
    for (int j = 0; j < pattern_len; j++) {
        if (memory[i+j] != pattern[j]) {
            found = 0;
            break;
        }
    }
    if (found) {
        printf("Pattern found at 0x%lx\n", base_addr + i);
    }
}
```

### 8. ROPgadgets finder

```c
unsigned char* binary = load_binary("program");
int size = get_size("program");

// Chercher "pop rdi; ret" (0x5f 0xc3)
for (int i = 0; i < size - 1; i++) {
    if (binary[i] == 0x5f && binary[i+1] == 0xc3) {
        printf("pop rdi; ret @ 0x%lx\n", base_addr + i);
    }
}
```

## 📝 Points clés à retenir

- `for` : nombre d'itérations connu à l'avance
- `while` : condition testée AVANT le bloc
- `do-while` : condition testée APRÈS (au moins 1 exécution)
- `break` : sort immédiatement de la boucle
- `continue` : passe à l'itération suivante
- Boucles imbriquées : complexité N*M
- Toujours incrémenter la variable de boucle (sinon boucle infinie)
- Les boucles sont essentielles pour scanner, brute-force, parser
- Utiliser break pour optimiser (arrêter dès qu'on trouve)

## ➡️ Prochaine étape

Maintenant que tu sais répéter des actions, tu vas apprendre à stocker des collections de données avec les [tableaux (arrays)](../08_arrays/)

---

**Exercices** : Voir [exercice.txt](exercice.txt)
**Code exemple** : Voir [example.c](example.c)

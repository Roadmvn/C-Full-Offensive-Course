# Module 27 : Networking et Sockets

## Objectifs d'apprentissage

Ce module explore la programmation réseau en C avec focus sur les techniques de communication pour le red teaming. Vous apprendrez :

- **Raw Sockets** : Création de paquets réseau personnalisés
- **TCP/UDP** : Communication client-serveur
- **C2 Communication** : Channels de Command & Control
- **DNS Tunneling** : Exfiltration de données via DNS

## Concepts clés

### Sockets Windows (Winsock)
- Initialisation avec WSAStartup
- Création de sockets (socket())
- Connexion (connect()) et écoute (listen())
- Envoi/réception de données

### Raw Sockets
- Accès direct à la couche IP
- Construction manuelle de headers
- ICMP, TCP SYN scanning
- Nécessite privilèges administrateur

### C2 Communication
- Beacon/callback périodique
- Commandes encodées/chiffrées
- Multiple channels (HTTP, DNS, ICMP)
- Évasion de détection réseau

### DNS Tunneling
- Encapsulation de données dans des requêtes DNS
- Bypass de firewalls (port 53 rarement bloqué)
- Exfiltration furtive
- Subdomains comme canal de données

## Architecture C2

```
┌─────────────────────────────────────────────────┐
│           C2 Communication Flow                 │
├─────────────────────────────────────────────────┤
│                                                 │
│  [Implant/Agent]                                │
│       │                                         │
│       ├─→ HTTP Beacon (User-Agent: legit)       │
│       │   GET /legit-looking-path               │
│       │                                         │
│       ├─→ DNS Query (data.evil.com)             │
│       │   TXT record response                   │
│       │                                         │
│       └─→ ICMP Echo Request (data in payload)   │
│                  │                              │
│                  ▼                              │
│          [C2 Server]                            │
│                  │                              │
│                  ├─→ Parse command              │
│                  ├─→ Execute                    │
│                  └─→ Send results               │
│                                                 │
└─────────────────────────────────────────────────┘
```

## Compilation

```bash
# Windows (MinGW)
gcc -o net_client client.c -lws2_32

# Linux
gcc -o net_client client.c

# Raw sockets (nécessite admin/root)
gcc -o raw_socket raw.c -lws2_32
```

## ⚠️ AVERTISSEMENT LÉGAL

**UTILISATION RÉSEAU MALVEILLANTE EST ILLÉGALE**

### Autorisé :
- Lab personnel isolé
- Environnements de test autorisés
- Red team engagements légitimes
- CTF et challenges

### INTERDIT :
- Scan de réseaux non autorisés
- C2 non autorisé sur infrastructure
- Exfiltration de données sans permission
- DDoS ou attaques réseau

**USAGE ÉDUCATIF UNIQUEMENT**

## Exercices

Consultez `exercice.txt` pour 8 défis progressifs.

## Prérequis

- Connaissance des protocoles TCP/IP
- Bases de la programmation réseau
- Compréhension des headers réseau

---

**RAPPEL** : Tests uniquement sur vos propres réseaux/systèmes autorisés.

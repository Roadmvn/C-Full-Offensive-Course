# Phase 3 : Network Communication

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                         PHASE 3                                     │   │
│   │                    NETWORK COMMUNICATION                            │   │
│   │                                                                     │   │
│   │    Semaines 8-9 : TCP, HTTP et Callbacks                           │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   "Un implant sans reseau n'est qu'un programme local."                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Vue d'Ensemble

Cette phase vous apprend a **communiquer sur le reseau**. C'est une competence essentielle : tout implant doit pouvoir recevoir des commandes et envoyer des resultats.

```
┌─────────────────────────────────────────────────────────────────┐
│                    ARCHITECTURE C2                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────┐                      ┌─────────────┐          │
│   │   IMPLANT   │                      │  SERVEUR C2 │          │
│   │   (Beacon)  │                      │  (Control)  │          │
│   └──────┬──────┘                      └──────┬──────┘          │
│          │                                    │                 │
│          │  1. Check-in (HTTP GET)           │                 │
│          │──────────────────────────────────→│                 │
│          │                                    │                 │
│          │  2. Commande (reponse JSON)       │                 │
│          │←──────────────────────────────────│                 │
│          │                                    │                 │
│          │  3. Resultat (HTTP POST)          │                 │
│          │──────────────────────────────────→│                 │
│          │                                    │                 │
│          │  4. Sleep / Repeat                │                 │
│          │                                    │                 │
│                                                                 │
│   TCP = Transport     HTTP = Application                       │
│   Winsock = API       WinHTTP = API                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Objectifs d'Apprentissage

A la fin de cette phase, vous serez capable de :

- [ ] Creer des connexions TCP avec Winsock
- [ ] Implementer un client/serveur basique
- [ ] Envoyer des requetes HTTP (GET/POST)
- [ ] Parser des reponses HTTP
- [ ] Creer un reverse shell TCP fonctionnel
- [ ] Implementer un callback HTTP simple

## Prerequis

- **Phase 2 completee** (Windows internals)
- Comprehension des processus et threads
- Notions basiques de reseau (IP, ports, TCP)

## Contenu Detaille

### Semaine 8 : Winsock & TCP
```
┌─────────────────────────────────────────────────────────────────┐
│                    WINSOCK WORKFLOW                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   CLIENT                              SERVER                    │
│   ──────                              ──────                    │
│                                                                 │
│   WSAStartup()                        WSAStartup()              │
│       │                                   │                     │
│       ▼                                   ▼                     │
│   socket()                            socket()                  │
│       │                                   │                     │
│       │                                   ▼                     │
│       │                               bind()                    │
│       │                                   │                     │
│       │                                   ▼                     │
│       │                               listen()                  │
│       │                                   │                     │
│       │        connect()                  ▼                     │
│       └────────────────────────────→ accept()                  │
│                                           │                     │
│       ←─────── Connexion etablie ────────→│                    │
│                                           │                     │
│   send() / recv()                    send() / recv()            │
│       │                                   │                     │
│       ▼                                   ▼                     │
│   closesocket()                      closesocket()              │
│       │                                   │                     │
│       ▼                                   ▼                     │
│   WSACleanup()                       WSACleanup()               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

| Jour | Sujet | Livrable |
|------|-------|----------|
| 1-2 | Initialisation Winsock | Socket creation |
| 3-4 | Client TCP | Connect to server |
| 5-6 | Server TCP | Accept connections |
| 7 | Bidirectionnel | **Reverse Shell TCP** |

### Semaine 9 : HTTP & WinHTTP
```
┌─────────────────────────────────────────────────────────────────┐
│                    HTTP REQUEST/RESPONSE                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   REQUEST (Client → Serveur)                                    │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │ GET /tasks HTTP/1.1                                     │   │
│   │ Host: c2.example.com                                    │   │
│   │ User-Agent: Mozilla/5.0                                 │   │
│   │ Accept: application/json                                │   │
│   │                                                         │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│   RESPONSE (Serveur → Client)                                   │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │ HTTP/1.1 200 OK                                         │   │
│   │ Content-Type: application/json                          │   │
│   │                                                         │   │
│   │ {"command": "whoami", "args": []}                       │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│   WinHTTP Functions:                                            │
│   WinHttpOpen → WinHttpConnect → WinHttpOpenRequest            │
│   → WinHttpSendRequest → WinHttpReceiveResponse                │
│   → WinHttpReadData                                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

| Jour | Sujet | Livrable |
|------|-------|----------|
| 1-2 | WinHTTP basics | GET request |
| 3-4 | POST requests | Data upload |
| 5-6 | Response parsing | JSON handling |
| 7 | Callback loop | **HTTP Callback** |

## Schema Conceptuel

```
┌─────────────────────────────────────────────────────────────────┐
│                 LAYERS RESEAU SIMPLIFIES                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   APPLICATION    │  HTTP, DNS, FTP                              │
│   ───────────────┼──────────────────────────                    │
│   TRANSPORT      │  TCP, UDP                                    │
│   ───────────────┼──────────────────────────                    │
│   NETWORK        │  IP                                          │
│   ───────────────┼──────────────────────────                    │
│   LINK           │  Ethernet, WiFi                              │
│                                                                 │
│   ┌──────────────────────────────────────────────────────────┐  │
│   │  WINSOCK opere au niveau TRANSPORT (TCP/UDP)             │  │
│   │  WinHTTP opere au niveau APPLICATION (HTTP)              │  │
│   └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Pourquoi HTTP est Prefere

| Critere | TCP Raw | HTTP |
|---------|---------|------|
| Firewall | Souvent bloque | Port 80/443 ouvert |
| Detection | Trafic suspect | Ressemble a navigation |
| Proxy | Non supporte | Support natif |
| Encryption | Manuel | HTTPS integre |
| Debugging | Difficile | Outils disponibles |

## Applications Offensives

Cette phase vous prepare pour :

| Technique | Description |
|-----------|-------------|
| Reverse Shell | Connexion sortante vers C2 |
| HTTP Beacon | Check-in periodique via HTTP |
| DNS Tunneling | Exfiltration via requetes DNS |
| Domain Fronting | Masquage du vrai C2 |

## Validation de Phase

Avant de passer a la Phase 4, verifiez que vous pouvez :

- [ ] Creer un socket TCP et vous connecter
- [ ] Envoyer et recevoir des donnees en TCP
- [ ] Faire une requete HTTP GET avec WinHTTP
- [ ] Envoyer des donnees en POST
- [ ] Parser une reponse HTTP
- [ ] Creer un reverse shell fonctionnel

## Navigation

| Precedent | Suivant |
|-----------|---------|
| [Phase 2 : Windows](../Phase-2-Windows-Fundamentals/) | [Phase 4 : Beacon](../Phase-4-Beacon-Assembly/) |

---

**Pret a commencer ?**

```bash
cd Week-08-Winsock-Basics
```

# Module 06 : Network Programming

```
+-------------------------------------------------------------------+
|                                                                     |
|   "Pas de C2 sans reseau. Pas de beacon sans sockets."             |
|                                                                     |
|   Ce module t'apprend la programmation reseau en C :               |
|   Winsock, TCP, HTTP, reverse shell. Les briques de base          |
|   pour toute communication offensive.                              |
|                                                                     |
+-------------------------------------------------------------------+
```

## Objectifs d'apprentissage

A la fin de ce module, tu sauras :

- Initialiser et utiliser Winsock (WSAStartup, socket, connect, send, recv)
- Creer un client/serveur TCP complet
- Faire des requetes HTTP GET et POST depuis du C pur
- Implementer un callback HTTP pour un beacon
- Ecrire un reverse shell fonctionnel

## Prerequis

- Module 01-02 (C, Pointeurs) valides
- Module 04 (Windows Fundamentals) recommande
- Comprendre les bases du reseau (TCP/IP, ports, HTTP)

## Contenu du module

### Lessons (dans `lessons/`)

Deux parcours en parallele : Winsock bas-niveau et WinHTTP haut-niveau.

**Parcours Winsock (TCP brut)**

| Fichier | Sujet |
|---------|-------|
| `01-winsock-init.c` | Initialisation Winsock, creation de socket |
| `02-tcp-client.c` | Client TCP : connexion, envoi, reception |
| `03-tcp-server.c` | Serveur TCP : bind, listen, accept |
| `04-reverse-shell.c` | Reverse shell complet via TCP |

**Parcours WinHTTP (HTTP/HTTPS)**

| Fichier | Sujet |
|---------|-------|
| `01-winhttp-intro.c` | Introduction a WinHTTP |
| `02-http-get.c` | Requete HTTP GET |
| `03-http-post.c` | Requete HTTP POST avec donnees |
| `04-http-callback.c` | Callback HTTP (base d'un beacon) |

### Exercices (dans `exercises/`)

**Exercices Winsock**

| Fichier | Difficulte | Description |
|---------|------------|-------------|
| `ex01-connect-server.c` | * | Se connecter a un serveur TCP |
| `ex02-echo-client.c` | ** | Client echo (envoie et recoit) |
| `ex03-simple-revshell.c` | *** | Reverse shell simplifie |

**Exercices WinHTTP**

| Fichier | Difficulte | Description |
|---------|------------|-------------|
| `ex01-fetch-page.c` | * | Telecharger une page web |
| `ex02-post-data.c` | ** | Envoyer des donnees en POST |
| `ex03-beacon-checkin.c` | *** | Premier check-in d'un beacon |

### Solutions (dans `solutions/`)

Ne regarde qu'apres avoir essaye !

## Comment travailler

```
1. Commence par le parcours Winsock (01 -> 04)
2. Fais les exercices Winsock correspondants
3. Passe au parcours WinHTTP (01 -> 04)
4. Fais les exercices WinHTTP
5. Le reverse shell et le beacon-checkin sont les boss de fin
```

## Compilation

```batch
REM Fichiers Winsock
cl fichier.c /link ws2_32.lib

REM Fichiers WinHTTP
cl fichier.c /link winhttp.lib

REM Reverse shell (les deux libs)
cl 04-reverse-shell.c /link ws2_32.lib
```

## Lien avec le maldev

| Concept | Usage offensif |
|---------|---------------|
| Winsock TCP | Reverse shell, bind shell |
| WinHTTP GET | Beacon check-in, telechargement de payload |
| WinHTTP POST | Exfiltration de donnees, envoi de resultats |
| HTTP Callback | Architecture de base d'un C2 |
| Reverse shell | Acces distant a une machine compromise |

## Checklist

- [ ] J'ai initialise Winsock et cree un socket
- [ ] J'ai ecrit un client et un serveur TCP
- [ ] J'ai fait une requete HTTP GET en C
- [ ] J'ai envoye des donnees en HTTP POST
- [ ] J'ai implemente un reverse shell
- [ ] J'ai fait un premier beacon check-in

---

Temps estime : **8-12 heures**

Prochain module : [07 - Beacon Development](../07-beacon-dev/)

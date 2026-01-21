# Exercices - L06 Networking Linux

## Objectifs

Maîtriser les sockets raw, packet crafting, sniffing réseau et techniques offensives.

---

## Exercice 1 : ICMP Ping (Facile)

**Objectif** : Implémenter un ping complet avec calcul du RTT

**Instructions** :
1. Créer un raw socket ICMP
2. Envoyer un ICMP Echo Request
3. Recevoir l'Echo Reply
4. Calculer le Round Trip Time (RTT)
5. Afficher le résultat comme la commande `ping`

**Résultat attendu** :
```
$ sudo ./my_ping 8.8.8.8
PING 8.8.8.8: 64 bytes
64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=12.4 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=117 time=11.8 ms
```

**Indice** : Utiliser `gettimeofday()` pour le timestamp

---

## Exercice 2 : HTTP Password Sniffer (Moyen)

**Objectif** : Capturer les mots de passe HTTP en clair

**Instructions** :
1. Créer un sniffer AF_PACKET
2. Filtrer seulement les paquets TCP port 80
3. Chercher "Authorization:" dans le payload
4. Extraire et décoder Base64
5. Afficher username:password

**Résultat attendu** :
```
[HTTP Credentials Captured]
Host: example.com
Authorization: Basic YWRtaW46cGFzc3dvcmQ=
Decoded: admin:password
```

**Critères de réussite** :
- [ ] Capture seulement HTTP (port 80)
- [ ] Détecte l'header Authorization
- [ ] Décode correctement Base64
- [ ] Affiche de manière lisible

---

## Exercice 3 : SYN Port Scanner (Moyen)

**Objectif** : Scanner 1000 ports en <5 secondes

**Instructions** :
1. Implémenter un SYN scanner multithread
2. Scanner les ports 1-1000
3. Utiliser 100 threads simultanés
4. Timeout de 1 seconde par port
5. Afficher seulement les ports ouverts

**Résultat attendu** :
```
$ sudo ./syn_scanner 192.168.1.1 1 1000
Scanning 192.168.1.1...
[+] Port 22 OPEN (SSH)
[+] Port 80 OPEN (HTTP)
[+] Port 443 OPEN (HTTPS)
Scan completed in 3.2 seconds
```

**Bonus** :
- Identifier les services (22=SSH, 80=HTTP, etc.)
- Ajouter une barre de progression

---

## Exercice 4 : ARP Spoof Detector (Difficile)

**Objectif** : Détecter les attaques ARP poisoning

**Instructions** :
1. Maintenir une table ARP (IP → MAC)
2. Sniffer tous les paquets ARP
3. Détecter si une IP change de MAC
4. Alerter l'utilisateur
5. Logger les attaques dans un fichier

**Résultat attendu** :
```
[ARP Table]
192.168.1.1 → aa:bb:cc:dd:ee:ff

[!] ARP SPOOFING DETECTED!
IP: 192.168.1.1
Old MAC: aa:bb:cc:dd:ee:ff
New MAC: 11:22:33:44:55:66
Time: 2025-12-07 14:30:00
```

**Critères de réussite** :
- [ ] Maintient une table ARP en mémoire
- [ ] Détecte les changements de MAC
- [ ] Logue dans un fichier
- [ ] Timestamp précis

---

## Exercice 5 : DNS Query Forger (Difficile)

**Objectif** : Forger une requête DNS manuelle

**Instructions** :
1. Créer un socket UDP
2. Construire un header DNS complet
3. Ajouter une question DNS (type A)
4. Envoyer à 8.8.8.8:53
5. Parser la réponse DNS

**Structure DNS** :
```
DNS Header (12 bytes):
- Transaction ID (2)
- Flags (2)
- Questions (2)
- Answer RRs (2)
- Authority RRs (2)
- Additional RRs (2)

Question:
- Name (variable)
- Type (2) - 0x0001 = A
- Class (2) - 0x0001 = IN
```

**Résultat attendu** :
```
$ ./dns_query google.com
Querying google.com (A record)...
Response: 142.250.185.46
```

---

## Exercice 6 : TCP SYN Flooder (Très difficile)

**Objectif** : Implémenter un SYN flood (éducatif uniquement)

**Instructions** :
1. Créer un raw socket TCP
2. Forger des paquets SYN avec IP source aléatoire (spoofing)
3. Envoyer 1000 paquets/seconde
4. Utiliser plusieurs threads
5. **ATTENTION** : Tester UNIQUEMENT sur ton propre réseau local !

**Résultat attendu** :
```
$ sudo ./syn_flood 192.168.1.100 80
[WARNING] This is for educational purposes only!
Flooding 192.168.1.100:80...
Sent 1000 SYN packets
Sent 2000 SYN packets
...
```

**Points de sécurité** :
- Ne JAMAIS utiliser contre des cibles réelles
- Tester sur une VM isolée
- Comprendre les implications légales

---

## Exercice 7 : Reverse Traceroute (Très difficile)

**Objectif** : Implémenter traceroute avec ICMP

**Instructions** :
1. Envoyer des paquets ICMP avec TTL incrémental (1, 2, 3...)
2. Capturer les réponses ICMP Time Exceeded
3. Extraire l'IP du routeur intermédiaire
4. Répéter jusqu'à atteindre la destination
5. Afficher le chemin complet

**Résultat attendu** :
```
$ sudo ./traceroute 8.8.8.8
Traceroute to 8.8.8.8:
 1  192.168.1.1      1.2 ms
 2  10.0.0.1         3.4 ms
 3  172.16.5.10      8.7 ms
 4  8.8.8.8          12.3 ms
```

---

## Exercice 8 : Network Bandwidth Monitor (Difficile)

**Objectif** : Monitorer la bande passante en temps réel

**Instructions** :
1. Capturer tous les paquets réseau
2. Compter les bytes par seconde
3. Séparer upload/download
4. Afficher en temps réel (rafraîchi chaque seconde)
5. Convertir en KB/s, MB/s

**Résultat attendu** :
```
=== Network Monitor ===
Interface: eth0
Upload:   125.3 KB/s
Download: 842.1 KB/s
Total:    967.4 KB/s
===========================
```

---

## Challenge Final : Custom Protocol Backdoor

**Objectif** : Créer un backdoor qui communique avec un protocole custom

**Specifications** :
1. Utiliser un raw socket (pas TCP/UDP standard)
2. Protocole propriétaire sur IP (protocol number 253)
3. Format des paquets :
   ```
   [Magic: 0xDEADBEEF][Command: 1 byte][Data length: 2 bytes][Data: variable]
   ```
4. Commandes :
   - 0x01 : Execute shell command
   - 0x02 : List files
   - 0x03 : Download file
5. Chiffrement XOR simple avec clé

**Difficultés** :
- Forge complètement les paquets IP
- Parse les réponses
- Gère les erreurs
- Reste furtif (pas de port standard)

---

## Auto-évaluation

Avant de passer au module suivant :
- [ ] Je comprends TCP vs UDP vs Raw sockets
- [ ] Je peux créer un packet sniffer
- [ ] Je sais calculer des checksums IP/TCP
- [ ] Je peux forger des paquets custom
- [ ] Je comprends les headers réseau (Ethernet, IP, TCP)
- [ ] Je sais utiliser AF_PACKET et SOCK_RAW
- [ ] Je connais les implications OPSEC du network scanning

---

## Testing Lab

Créer un environnement de test sécurisé :

```bash
# 1. Créer un namespace réseau isolé
sudo ip netns add lab

# 2. Créer une paire veth
sudo ip link add veth0 type veth peer name veth1

# 3. Déplacer veth1 dans le namespace
sudo ip link set veth1 netns lab

# 4. Configurer les IPs
sudo ip addr add 10.0.0.1/24 dev veth0
sudo ip netns exec lab ip addr add 10.0.0.2/24 dev veth1

# 5. Activer les interfaces
sudo ip link set veth0 up
sudo ip netns exec lab ip link set veth1 up
sudo ip netns exec lab ip link set lo up

# 6. Tester
ping -c 1 10.0.0.2

# 7. Lancer ton sniffer
sudo ./sniffer veth0

# 8. Dans un autre terminal, générer du trafic
ping 10.0.0.2
```

---

## Solutions

Voir `solution.md` pour les solutions complètes et commentées.

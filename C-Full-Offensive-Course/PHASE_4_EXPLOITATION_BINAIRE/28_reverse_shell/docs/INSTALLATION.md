# Guide d'Installation - Reverse Shell Project

## 📋 Prérequis

### Système d'Exploitation

- ✅ Linux (Ubuntu, Debian, Kali, etc.)
- ✅ macOS (avec Xcode Command Line Tools)
- ⚠️ Windows (avec MinGW ou WSL)

### Outils Nécessaires

```bash
# Vérifier gcc
gcc --version

# Vérifier make
make --version

# Installer si manquant (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install build-essential

# macOS
xcode-select --install
```

---

## 🔧 Installation

### Étape 1 : Cloner/Télécharger le Projet

```bash
cd /path/to/Learning-C/exercices/04_Security_Exploitation/03_reverse_shell
```

### Étape 2 : Compiler

```bash
make all
```

**Sortie attendue** :
```
📦 Compiling src/utils/crypto.c...
📦 Compiling src/utils/logger.c...
📦 Compiling src/client/connection.c...
📦 Compiling src/client/commands.c...
📦 Compiling src/client/main_client.c...
🔨 Linking client...
✅ Client compilé : build/client

📦 Compiling src/server/listener.c...
📦 Compiling src/server/handler.c...
📦 Compiling src/server/main_server.c...
🔨 Linking server...
✅ Server compilé : build/server
```

### Étape 3 : Vérifier

```bash
ls -lh build/
```

Vous devriez voir :
```
-rwxr-xr-x  client
-rwxr-xr-x  server
```

---

## 🧪 Test d'Installation

### Test Basique (Local)

**Terminal 1** :
```bash
./build/server 4444
```

**Terminal 2** :
```bash
./build/client 127.0.0.1 4444
```

Si tout fonctionne, vous obtenez un shell dans Terminal 1 !

---

## ⚠️ Avertissement Légal

```
┌────────────────────────────────────────────────┐
│  ⚠️  USAGE STRICTEMENT ÉDUCATIF                │
├────────────────────────────────────────────────┤
│                                                │
│  - Tests UNIQUEMENT sur VOS machines          │
│  - Environnement isolé recommandé (VM)        │
│  - JAMAIS sur systèmes tiers sans             │
│    autorisation ÉCRITE                        │
│  - Usage malveillant = ILLÉGAL                │
│                                                │
│  Apprentissage de la sécurité ≠ Piratage     │
│                                                │
└────────────────────────────────────────────────┘
```

---

## 🐛 Dépannage

### Erreur : "Cannot bind to port 4444"

**Cause** : Port déjà utilisé

**Solution** :
```bash
# Trouver processus utilisant le port
sudo lsof -i :4444

# Tuer le processus OU utiliser autre port
./build/server 5555
```

### Erreur : "Permission denied"

**Cause** : Binaire pas exécutable

**Solution** :
```bash
chmod +x build/client build/server
```

### Erreur de Compilation

**Cause** : Headers manquants

**Solution Ubuntu** :
```bash
sudo apt-get install libc6-dev
```

**Solution macOS** :
```bash
xcode-select --install
```

---

## 📚 Documentation Complète

Consultez également :
- `USAGE.md` - Exemples d'utilisation
- `PROTOCOL.md` - Spécifications du protocole
- `SECURITY.md` - Bonnes pratiques sécurité


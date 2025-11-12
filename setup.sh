#!/bin/bash

# ═══════════════════════════════════════════════════════════════════
# Script d'installation - Learning C pour Red Teaming
# ═══════════════════════════════════════════════════════════════════
#
# Ce script installe les outils nécessaires pour compiler et debugger
# les programmes C de ce projet.
#
# Usage : ./setup.sh
#
# ═══════════════════════════════════════════════════════════════════

echo "═══════════════════════════════════════════════════════════════════"
echo "  Installation des outils pour Learning C - Red Teaming"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

# Détection de l'OS
OS="$(uname -s)"

case "$OS" in
    Linux*)
        echo "[*] Système détecté : Linux"
        echo "[*] Installation de gcc, make, gdb, valgrind..."

        # Détection de la distribution
        if [ -f /etc/debian_version ]; then
            # Debian/Ubuntu
            echo "[*] Distribution : Debian/Ubuntu"
            sudo apt-get update
            sudo apt-get install -y build-essential gdb valgrind
        elif [ -f /etc/redhat-release ]; then
            # RedHat/CentOS/Fedora
            echo "[*] Distribution : RedHat/CentOS/Fedora"
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y gdb valgrind
        elif [ -f /etc/arch-release ]; then
            # Arch Linux
            echo "[*] Distribution : Arch Linux"
            sudo pacman -S --noconfirm base-devel gdb valgrind
        else
            echo "[!] Distribution non reconnue"
            echo "[!] Installe manuellement : gcc, make, gdb, valgrind"
            exit 1
        fi
        ;;

    Darwin*)
        echo "[*] Système détecté : macOS"
        echo "[*] Installation de gcc, make, gdb via Homebrew..."

        # Vérifier si Homebrew est installé
        if ! command -v brew &> /dev/null; then
            echo "[!] Homebrew n'est pas installé"
            echo "[*] Installation de Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi

        # Installer les outils
        brew install gcc make gdb

        echo "[!] Note : Sur macOS, gdb nécessite des droits spéciaux"
        echo "[!] Consulte : https://sourceware.org/gdb/wiki/PermissionsDarwin"
        ;;

    CYGWIN*|MINGW*|MSYS*)
        echo "[*] Système détecté : Windows"
        echo "[!] Sur Windows, installe MinGW ou WSL (Windows Subsystem for Linux)"
        echo "[!] Recommandation : Utilise WSL pour une meilleure compatibilité"
        echo ""
        echo "Installation WSL :"
        echo "  1. Ouvre PowerShell en administrateur"
        echo "  2. Exécute : wsl --install"
        echo "  3. Redémarre ton PC"
        echo "  4. Lance Ubuntu depuis le menu Démarrer"
        echo "  5. Re-exécute ce script dans WSL"
        exit 1
        ;;

    *)
        echo "[!] Système d'exploitation non reconnu : $OS"
        exit 1
        ;;
esac

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  Vérification des installations"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

# Vérifier gcc
if command -v gcc &> /dev/null; then
    echo "[✓] gcc est installé"
    gcc --version | head -n 1
else
    echo "[✗] gcc n'est pas installé"
    exit 1
fi

# Vérifier make
if command -v make &> /dev/null; then
    echo "[✓] make est installé"
    make --version | head -n 1
else
    echo "[✗] make n'est pas installé"
    exit 1
fi

# Vérifier gdb
if command -v gdb &> /dev/null; then
    echo "[✓] gdb est installé"
    gdb --version | head -n 1
else
    echo "[✗] gdb n'est pas installé (optionnel mais recommandé)"
fi

# Vérifier valgrind (Linux seulement)
if [ "$OS" == "Linux" ]; then
    if command -v valgrind &> /dev/null; then
        echo "[✓] valgrind est installé"
        valgrind --version
    else
        echo "[✗] valgrind n'est pas installé (optionnel mais recommandé)"
    fi
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  Test de compilation"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

# Créer un fichier de test
TEST_FILE="/tmp/test_learning_c.c"
cat > "$TEST_FILE" << 'EOF'
#include <stdio.h>

int main() {
    printf("Hello from Learning C!\n");
    return 0;
}
EOF

# Compiler
echo "[*] Compilation d'un programme de test..."
if gcc -o /tmp/test_learning_c "$TEST_FILE" 2>&1; then
    echo "[✓] Compilation réussie"

    # Exécuter
    echo "[*] Exécution du programme de test..."
    if /tmp/test_learning_c; then
        echo "[✓] Exécution réussie"
    else
        echo "[✗] Erreur lors de l'exécution"
    fi

    # Nettoyer
    rm -f /tmp/test_learning_c "$TEST_FILE"
else
    echo "[✗] Erreur de compilation"
    rm -f "$TEST_FILE"
    exit 1
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  Configuration des permissions"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

# Désactiver ASLR pour les exercices d'exploitation (Linux seulement)
if [ "$OS" == "Linux" ]; then
    echo "[*] Pour les exercices d'exploitation, ASLR peut être désactivé"
    echo "[*] Commande : echo 0 | sudo tee /proc/sys/kernel/randomize_va_space"
    echo "[!] À faire manuellement avant les exercices 16-20"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  Installation terminée !"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo "Tu es prêt à commencer !"
echo ""
echo "Prochaine étape :"
echo "  cd exercices/01_hello_world/"
echo "  cat README.md"
echo ""
echo "Bon apprentissage ! 🔥"
echo ""

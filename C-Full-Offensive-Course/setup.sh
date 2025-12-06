#!/bin/bash

# =========================================================
# Script d'installation automatique multi-plateforme
# C Full Offensive Course
# =========================================================

set -e  # Arrêt en cas d'erreur

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction pour afficher les messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Détection de l'OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        print_info "Système détecté : Linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        print_info "Système détecté : macOS"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "win32" ]]; then
        OS="windows"
        print_info "Système détecté : Windows"
    else
        print_error "OS non supporté : $OSTYPE"
        exit 1
    fi
}

# Installation pour Linux
install_linux() {
    print_info "Installation des outils pour Linux..."

    # Mise à jour des paquets
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y gcc g++ make gdb binutils valgrind nasm git curl
        print_success "Outils installés via apt-get"
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y gcc g++ make gdb binutils valgrind nasm git curl
        print_success "Outils installés via dnf"
    elif command -v pacman &> /dev/null; then
        sudo pacman -Sy --noconfirm gcc make gdb binutils valgrind nasm git curl
        print_success "Outils installés via pacman"
    else
        print_error "Gestionnaire de paquets non supporté"
        exit 1
    fi

    # Installation optionnelle de pwntools
    if command -v python3 &> /dev/null; then
        print_info "Installation de pwntools (optionnel)..."
        python3 -m pip install --user pwntools 2>/dev/null || print_warning "Échec de l'installation de pwntools"
    fi
}

# Installation pour macOS
install_macos() {
    print_info "Installation des outils pour macOS..."

    # Vérification de Homebrew
    if ! command -v brew &> /dev/null; then
        print_warning "Homebrew non trouvé. Installation..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi

    # Installation des outils de développement
    xcode-select --install 2>/dev/null || print_info "Xcode Command Line Tools déjà installés"

    # Installation via Homebrew
    brew install gcc make llvm nasm binutils git
    print_success "Outils installés via Homebrew"

    # Installation optionnelle de pwntools
    if command -v python3 &> /dev/null; then
        print_info "Installation de pwntools (optionnel)..."
        python3 -m pip install --user pwntools 2>/dev/null || print_warning "Échec de l'installation de pwntools"
    fi
}

# Installation pour Windows (via MSYS2/MinGW)
install_windows() {
    print_info "Installation des outils pour Windows..."

    if command -v pacman &> /dev/null; then
        # MSYS2 détecté
        pacman -Sy --noconfirm mingw-w64-x86_64-gcc mingw-w64-x86_64-gdb mingw-w64-x86_64-make git
        print_success "Outils installés via MSYS2"
    else
        print_warning "MSYS2 non détecté."
        print_info "Pour Windows, installez manuellement :"
        print_info "  1. MSYS2 : https://www.msys2.org/"
        print_info "  2. Visual Studio Build Tools : https://visualstudio.microsoft.com/downloads/"
        print_info "  3. x64dbg : https://x64dbg.com/"
        exit 1
    fi
}

# Vérification des installations
check_installations() {
    print_info "Vérification des installations..."

    TOOLS=("gcc" "make" "git")

    if [[ "$OS" == "macos" ]]; then
        TOOLS+=("lldb")
    else
        TOOLS+=("gdb")
    fi

    for tool in "${TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null; then
            VERSION=$($tool --version 2>/dev/null | head -n1)
            print_success "$tool : $VERSION"
        else
            print_warning "$tool : non trouvé"
        fi
    done
}

# Test de compilation
test_compilation() {
    print_info "Test de compilation..."

    TEST_FILE=$(mktemp).c
    cat > "$TEST_FILE" << 'EOF'
#include <stdio.h>

int main() {
    printf("Setup réussi ! Prêt pour le C offensif.\n");
    return 0;
}
EOF

    if gcc "$TEST_FILE" -o /tmp/test_setup 2>/dev/null; then
        /tmp/test_setup
        print_success "Compilation fonctionnelle !"
        rm -f "$TEST_FILE" /tmp/test_setup
    else
        print_error "Erreur de compilation"
        rm -f "$TEST_FILE"
        exit 1
    fi
}

# Banner
echo "═════════════════════════════════════════════════════"
echo "  C Full Offensive Course - Setup Script"
echo "═════════════════════════════════════════════════════"
echo ""

# Exécution
detect_os

case "$OS" in
    linux)
        install_linux
        ;;
    macos)
        install_macos
        ;;
    windows)
        install_windows
        ;;
esac

check_installations
test_compilation

echo ""
print_success "Installation terminée avec succès !"
echo ""
print_info "Prochaine étape : cd PHASE_1_FONDAMENTAUX/01_hello_world"
echo "═════════════════════════════════════════════════════"

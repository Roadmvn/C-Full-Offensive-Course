# ═══════════════════════════════════════════════════════════════════════════
#                   MAKEFILE - MODULE 24 : PROCESS INJECTION
# ═══════════════════════════════════════════════════════════════════════════
#
# AVERTISSEMENT : Ce code est à usage ÉDUCATIF uniquement
# Nécessite des privilèges administrateur pour fonctionner
# ═══════════════════════════════════════════════════════════════════════════

# Compilateur
CC = gcc

# Nom de l'exécutable
TARGET = process_injection.exe

# Fichiers source
SRC = main.c

# Flags de compilation
CFLAGS = -Wall -Wextra -O2 -DUNICODE -D_UNICODE

# Bibliothèques Windows nécessaires
LDFLAGS = -lpsapi

# Architecture (décommenter selon besoin)
# Pour x64 (64-bit)
# CFLAGS += -m64
# Pour x86 (32-bit)
# CFLAGS += -m32

# ═══════════════════════════════════════════════════════════════════════════
#                               RÈGLES
# ═══════════════════════════════════════════════════════════════════════════

all: $(TARGET)

$(TARGET): $(SRC)
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "    Compilation du module Process Injection"
	@echo "═══════════════════════════════════════════════════════════════"
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)
	@echo ""
	@echo "[+] Compilation terminée: $(TARGET)"
	@echo ""
	@echo "⚠️  ATTENTION ⚠️"
	@echo "Ce programme nécessite des privilèges ADMINISTRATEUR"
	@echo "Exécutez en tant qu'administrateur pour utiliser les fonctions d'injection"
	@echo ""
	@echo "Usage éducatif uniquement - Environnements de test isolés"
	@echo ""

clean:
	@echo "Nettoyage des fichiers compilés..."
	rm -f $(TARGET) *.o
	@echo "[+] Nettoyage terminé"

run: $(TARGET)
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "⚠️  Exécution avec privilèges administrateur requis ⚠️"
	@echo "═══════════════════════════════════════════════════════════════"
	./$(TARGET)

help:
	@echo "Makefile - Module 24 : Process Injection"
	@echo ""
	@echo "Cibles disponibles:"
	@echo "  make         - Compiler le programme"
	@echo "  make clean   - Supprimer les fichiers compilés"
	@echo "  make run     - Compiler et exécuter (nécessite admin)"
	@echo "  make help    - Afficher cette aide"
	@echo ""
	@echo "Notes:"
	@echo "  - Nécessite MinGW-w64 ou MSVC sur Windows"
	@echo "  - Privilèges administrateur REQUIS pour l'exécution"
	@echo "  - Usage éducatif UNIQUEMENT"

.PHONY: all clean run help

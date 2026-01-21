# ═══════════════════════════════════════════════════════════════════
# Makefile - Module 34 : Token Manipulation
# ═══════════════════════════════════════════════════════════════════

CC = gcc
CFLAGS = -Wall -Wextra -std=c11
LDFLAGS = -ladvapi32

# Nom du programme
TARGET = token_manipulation

# Fichiers source
SRC = main.c

# ═══════════════════════════════════════════════════════════════════
# Règles de compilation
# ═══════════════════════════════════════════════════════════════════

all: $(TARGET)

$(TARGET): $(SRC)
	@echo "Compilation de $(TARGET)..."
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)
	@echo "Compilation terminée !"
	@echo ""
	@echo "⚠️  AVERTISSEMENT : Ce programme nécessite des droits administrateur"
	@echo "Pour exécuter : Clic droit → Exécuter en tant qu'administrateur"
	@echo ""

clean:
	@echo "Nettoyage des fichiers générés..."
	rm -f $(TARGET) $(TARGET).exe
	@echo "Nettoyage terminé !"

run: $(TARGET)
	@echo "⚠️  Ce programme doit être exécuté avec des droits administrateur"
	@echo "Tentative de lancement..."
	./$(TARGET)

help:
	@echo "Makefile - Module 34 : Token Manipulation"
	@echo ""
	@echo "Cibles disponibles :"
	@echo "  make          - Compile le programme"
	@echo "  make clean    - Supprime les fichiers générés"
	@echo "  make run      - Compile et exécute (nécessite admin)"
	@echo "  make help     - Affiche cette aide"
	@echo ""
	@echo "Notes :"
	@echo "  - Ce programme nécessite Windows"
	@echo "  - Droits administrateur REQUIS"
	@echo "  - Utilise advapi32.dll pour les APIs de sécurité"

.PHONY: all clean run help

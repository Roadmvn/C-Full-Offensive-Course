# ═══════════════════════════════════════════════════════════════════
# Makefile - Module 35 : Registry Manipulation
# ═══════════════════════════════════════════════════════════════════

CC = gcc
CFLAGS = -Wall -Wextra -std=c11
LDFLAGS = -ladvapi32

# Nom du programme
TARGET = registry_manipulation

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
	@echo "⚠️  AVERTISSEMENT : Ce programme modifie le registre Windows"
	@echo "Créez un backup AVANT exécution :"
	@echo "  reg export HKCU backup_hkcu.reg"
	@echo ""

clean:
	@echo "Nettoyage des fichiers générés..."
	rm -f $(TARGET) $(TARGET).exe
	@echo "Nettoyage terminé !"

run: $(TARGET)
	@echo "⚠️  ATTENTION : Modification du registre Windows"
	@echo "Assurez-vous d'avoir créé un backup"
	@echo ""
	./$(TARGET)

backup:
	@echo "Création d'un backup du registre utilisateur..."
	reg export HKCU backup_hkcu_$(shell date +%Y%m%d_%H%M%S).reg
	@echo "Backup créé avec succès !"

restore:
	@echo "Liste des backups disponibles :"
	@ls -1 backup_*.reg 2>/dev/null || echo "Aucun backup trouvé"
	@echo ""
	@echo "Pour restaurer : reg import <fichier_backup.reg>"

help:
	@echo "Makefile - Module 35 : Registry Manipulation"
	@echo ""
	@echo "Cibles disponibles :"
	@echo "  make          - Compile le programme"
	@echo "  make clean    - Supprime les fichiers générés"
	@echo "  make run      - Compile et exécute"
	@echo "  make backup   - Crée un backup du registre HKCU"
	@echo "  make restore  - Liste les backups disponibles"
	@echo "  make help     - Affiche cette aide"
	@echo ""
	@echo "Notes :"
	@echo "  - Ce programme nécessite Windows"
	@echo "  - TOUJOURS créer un backup avant exécution"
	@echo "  - Utilise advapi32.dll pour les APIs de registre"

.PHONY: all clean run backup restore help

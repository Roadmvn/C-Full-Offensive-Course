# ═══════════════════════════════════════════════════════════════════════════
# Makefile - Module 23 : APIs Windows Avancées
# ═══════════════════════════════════════════════════════════════════════════

CC = gcc
CFLAGS = -Wall -Wextra -std=c11
TARGET = main

ifeq ($(OS),Windows_NT)
    PLATFORM = windows
    EXT = .exe
    LDFLAGS =
    RM = del /Q
else
    PLATFORM = unsupported
    EXT =
    LDFLAGS =
    RM = rm -f
endif

# ═══════════════════════════════════════════════════════════════════════════
# RÈGLES PRINCIPALES
# ═══════════════════════════════════════════════════════════════════════════

all: check_platform $(TARGET)$(EXT)

check_platform:
ifeq ($(PLATFORM),unsupported)
	@echo "AVERTISSEMENT : Ce module nécessite Windows"
	@echo "Le code sera compilé mais non fonctionnel sur cette plateforme"
endif

$(TARGET)$(EXT): main.c
	$(CC) $(CFLAGS) main.c -o $(TARGET)$(EXT) $(LDFLAGS)
	@echo "Compilation terminée pour $(PLATFORM)"

# ═══════════════════════════════════════════════════════════════════════════
# RÈGLES SPÉCIFIQUES
# ═══════════════════════════════════════════════════════════════════════════

windows: CFLAGS += -D_WIN64
windows: $(TARGET).exe
	@echo "Compilation Windows x64"

# Version avec symboles de debug
debug: CFLAGS += -g -O0
debug: $(TARGET)$(EXT)
	@echo "Compilation en mode debug"

# Version optimisée
release: CFLAGS += -O2
release: $(TARGET)$(EXT)
	@echo "Compilation en mode release"

# ═══════════════════════════════════════════════════════════════════════════
# RÈGLES UTILITAIRES
# ═══════════════════════════════════════════════════════════════════════════

clean:
	$(RM) $(TARGET)$(EXT)
	@echo "Nettoyage effectué"

run: $(TARGET)$(EXT)
	./$(TARGET)$(EXT)

help:
	@echo "Makefile - Module 23 : APIs Windows Avancées"
	@echo ""
	@echo "Cibles disponibles :"
	@echo "  make          - Compile pour la plateforme détectée"
	@echo "  make windows  - Compile pour Windows (requis)"
	@echo "  make debug    - Compile avec symboles de debug"
	@echo "  make release  - Compile en mode optimisé"
	@echo "  make clean    - Supprime les fichiers compilés"
	@echo "  make run      - Compile et exécute"
	@echo "  make help     - Affiche cette aide"
	@echo ""
	@echo "Plateforme détectée : $(PLATFORM)"
	@echo ""
	@echo "NOTE : Ce module nécessite Windows"
	@echo "       Utilisez MinGW-w64 pour la compilation"

.PHONY: all check_platform windows debug release clean run help

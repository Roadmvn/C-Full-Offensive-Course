# ═══════════════════════════════════════════════════════════════════════════
# Makefile - Module 21 : Processus et Threads
# ═══════════════════════════════════════════════════════════════════════════

CC = gcc
CFLAGS = -Wall -Wextra -std=c11
TARGET = main

# Détection du système d'exploitation
ifeq ($(OS),Windows_NT)
    PLATFORM = windows
    EXT = .exe
    LDFLAGS =
    RM = del /Q
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        PLATFORM = linux
    else ifeq ($(UNAME_S),Darwin)
        PLATFORM = macos
    endif
    EXT =
    LDFLAGS = -pthread -lrt
    RM = rm -f
endif

# ═══════════════════════════════════════════════════════════════════════════
# RÈGLES PRINCIPALES
# ═══════════════════════════════════════════════════════════════════════════

all: $(TARGET)$(EXT)
	@echo "Compilation terminée pour $(PLATFORM)"

$(TARGET)$(EXT): main.c
	$(CC) $(CFLAGS) main.c -o $(TARGET)$(EXT) $(LDFLAGS)

# ═══════════════════════════════════════════════════════════════════════════
# RÈGLES SPÉCIFIQUES PLATEFORMES
# ═══════════════════════════════════════════════════════════════════════════

linux: LDFLAGS = -pthread -lrt
linux: $(TARGET)
	@echo "Compilation Linux avec support threads et shared memory"

windows: LDFLAGS =
windows: $(TARGET).exe
	@echo "Compilation Windows avec support threads natifs"

macos: LDFLAGS = -pthread
macos: $(TARGET)
	@echo "Compilation macOS (shared memory POSIX limitée)"

# ═══════════════════════════════════════════════════════════════════════════
# RÈGLES UTILITAIRES
# ═══════════════════════════════════════════════════════════════════════════

clean:
	$(RM) $(TARGET)$(EXT)
	@echo "Nettoyage effectué"

run: $(TARGET)$(EXT)
	./$(TARGET)$(EXT)

help:
	@echo "Makefile - Module 21 : Processus et Threads"
	@echo ""
	@echo "Cibles disponibles :"
	@echo "  make          - Compile pour la plateforme détectée"
	@echo "  make linux    - Compile pour Linux"
	@echo "  make windows  - Compile pour Windows"
	@echo "  make macos    - Compile pour macOS"
	@echo "  make clean    - Supprime les fichiers compilés"
	@echo "  make run      - Compile et exécute"
	@echo "  make help     - Affiche cette aide"
	@echo ""
	@echo "Plateforme détectée : $(PLATFORM)"

.PHONY: all linux windows macos clean run help

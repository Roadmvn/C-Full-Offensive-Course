# ═══════════════════════════════════════════════════════════════════
# Makefile - Module 36 : Memory Mapping
# ═══════════════════════════════════════════════════════════════════

CC = gcc
CFLAGS = -Wall -Wextra -std=c11

# Détection de la plateforme
UNAME := $(shell uname -s 2>/dev/null || echo Windows)

ifeq ($(UNAME),Linux)
    LDFLAGS = -lrt
    PLATFORM = Linux
else ifeq ($(UNAME),Darwin)
    LDFLAGS =
    PLATFORM = macOS
else
    LDFLAGS =
    PLATFORM = Windows
endif

TARGET = memory_mapping
SRC = main.c

# ═══════════════════════════════════════════════════════════════════
# Règles de compilation
# ═══════════════════════════════════════════════════════════════════

all: $(TARGET)
	@echo "Compilation réussie pour $(PLATFORM)"

$(TARGET): $(SRC)
	@echo "Compilation pour $(PLATFORM)..."
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	@echo "Nettoyage..."
	rm -f $(TARGET) $(TARGET).exe test_mapping.dat
	@echo "Nettoyage terminé !"

run: $(TARGET)
	./$(TARGET)

help:
	@echo "Makefile - Module 36 : Memory Mapping"
	@echo ""
	@echo "Plateforme détectée : $(PLATFORM)"
	@echo ""
	@echo "Cibles disponibles :"
	@echo "  make        - Compile le programme"
	@echo "  make clean  - Supprime les fichiers générés"
	@echo "  make run    - Compile et exécute"
	@echo "  make help   - Affiche cette aide"

.PHONY: all clean run help

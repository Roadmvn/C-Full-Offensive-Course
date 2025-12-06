# ═══════════════════════════════════════════════════════════════════════
# Makefile pour le Module 29 : Obfuscation de Code
# ═══════════════════════════════════════════════════════════════════════

CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O0
TARGET = obfuscation

# Note: -O0 est important pour préserver l'obfuscation visible
# Les optimisations pourraient éliminer le code mort et simplifier le flux

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)

# Règle pour analyser le binaire
analyze: $(TARGET)
	@echo "═══════════════════════════════════════════════════════════"
	@echo "Analyse du binaire obfusqué"
	@echo "═══════════════════════════════════════════════════════════"
	@echo "\n1. Taille du binaire:"
	@size $(TARGET)
	@echo "\n2. Strings dans le binaire (premières 20 lignes):"
	@strings $(TARGET) | head -20
	@echo "\n3. Symboles (fonctions dead):"
	@nm $(TARGET) | grep dead || echo "Symboles dead non trouvés (stripped?)"

# Règle pour désassembler
disasm: $(TARGET)
	objdump -d $(TARGET) > $(TARGET).asm
	@echo "Désassemblage créé dans $(TARGET).asm"

.PHONY: all clean analyze disasm

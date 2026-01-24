# ═══════════════════════════════════════════════════════════════════
# Makefile - Module 38 : ROP Chains
# ═══════════════════════════════════════════════════════════════════

CC = gcc
CFLAGS = -Wall -Wextra -std=c11
# Pour compilation SANS protections (apprentissage uniquement) :
CFLAGS_VULN = -fno-stack-protector -z execstack -no-pie

TARGET = rop_chains
SRC = main.c

all: $(TARGET)

$(TARGET): $(SRC)
	@echo "Compilation..."
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)
	@echo "⚠️  Technique d'exploitation - Usage éducatif uniquement"

clean:
	rm -f $(TARGET) $(TARGET).exe

run: $(TARGET)
	./$(TARGET)

help:
	@echo "Module 38 : ROP Chains"
	@echo "Cibles : all, clean, run, help"

.PHONY: all clean run help

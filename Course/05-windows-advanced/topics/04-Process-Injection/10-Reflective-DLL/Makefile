# ═══════════════════════════════════════════════════════════════════
# Makefile - Module 37 : Reflective Loading
# ═══════════════════════════════════════════════════════════════════

CC = gcc
CFLAGS = -Wall -Wextra -std=c11
LDFLAGS =

TARGET = reflective_loading
SRC = main.c

all: $(TARGET)

$(TARGET): $(SRC)
	@echo "Compilation..."
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)
	@echo "⚠️  ATTENTION : Technique sensible - Usage éducatif uniquement"

clean:
	rm -f $(TARGET) $(TARGET).exe

run: $(TARGET)
	./$(TARGET)

help:
	@echo "Module 37 : Reflective Loading"
	@echo "Cibles : all, clean, run, help"

.PHONY: all clean run help

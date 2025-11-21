# ═══════════════════════════════════════════════════════════════════════════
#                   MAKEFILE - MODULE 27 : NETWORKING
# ═══════════════════════════════════════════════════════════════════════════

CC = gcc
TARGET = networking.exe
SRC = main.c
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lws2_32

all: $(TARGET)

$(TARGET): $(SRC)
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "    Compilation du module Networking"
	@echo "═══════════════════════════════════════════════════════════════"
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)
	@echo "[+] Compilé: $(TARGET)"

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean

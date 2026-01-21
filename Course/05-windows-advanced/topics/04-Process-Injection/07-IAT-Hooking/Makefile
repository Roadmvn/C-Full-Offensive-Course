# ═══════════════════════════════════════════════════════════════════════════
#                   MAKEFILE - MODULE 26 : API HOOKING
# ═══════════════════════════════════════════════════════════════════════════

CC = gcc
TARGET = api_hooking.exe
SRC = main.c
CFLAGS = -Wall -Wextra -O2

all: $(TARGET)

$(TARGET): $(SRC)
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "    Compilation du module API Hooking"
	@echo "═══════════════════════════════════════════════════════════════"
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)
	@echo "[+] Compilé: $(TARGET)"
	@echo ""

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean

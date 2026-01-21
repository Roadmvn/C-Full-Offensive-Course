# ═══════════════════════════════════════════════════════════════════════════
#                   MAKEFILE - MODULE 28 : CRYPTOGRAPHIE
# ═══════════════════════════════════════════════════════════════════════════

CC = gcc
TARGET = crypto.exe
SRC = main.c
CFLAGS = -Wall -Wextra -O2

# Décommenter si OpenSSL est installé
# LDFLAGS = -lcrypto -lssl

all: $(TARGET)

$(TARGET): $(SRC)
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "    Compilation du module Cryptographie"
	@echo "═══════════════════════════════════════════════════════════════"
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)
	@echo "[+] Compilé: $(TARGET)"
	@echo ""
	@echo "Note: Pour AES/RSA avec OpenSSL, installez OpenSSL et ajoutez -lcrypto -lssl"
	@echo ""

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean

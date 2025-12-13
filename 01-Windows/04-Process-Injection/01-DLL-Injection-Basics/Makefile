# ═══════════════════════════════════════════════════════════════════════════
#                   MAKEFILE - MODULE 25 : DLL INJECTION
# ═══════════════════════════════════════════════════════════════════════════

CC = gcc
TARGET = dll_injector.exe
TEST_DLL = test.dll
SRC = main.c
DLL_SRC = test_dll.c

CFLAGS = -Wall -Wextra -O2 -DUNICODE -D_UNICODE
LDFLAGS = -lpsapi

# Flags pour la DLL
DLL_CFLAGS = -shared -Wall -Wextra -O2
DLL_LDFLAGS = -luser32

# ═══════════════════════════════════════════════════════════════════════════

all: $(TARGET) $(TEST_DLL)

$(TARGET): $(SRC)
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "    Compilation de l'injecteur DLL"
	@echo "═══════════════════════════════════════════════════════════════"
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)
	@echo "[+] Injecteur compilé: $(TARGET)"

$(TEST_DLL): $(DLL_SRC)
	@echo ""
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "    Compilation de la DLL de test"
	@echo "═══════════════════════════════════════════════════════════════"
	$(CC) $(DLL_CFLAGS) -o $(TEST_DLL) $(DLL_SRC) $(DLL_LDFLAGS)
	@echo "[+] DLL de test compilée: $(TEST_DLL)"
	@echo ""
	@echo "⚠️  Privilèges administrateur REQUIS pour l'injection"
	@echo "Usage: ./$(TARGET)"
	@echo ""

clean:
	rm -f $(TARGET) $(TEST_DLL) *.o

.PHONY: all clean

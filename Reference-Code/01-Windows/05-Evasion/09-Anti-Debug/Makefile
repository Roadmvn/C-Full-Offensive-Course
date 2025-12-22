# ═══════════════════════════════════════════════════════════════════════
# Makefile pour le Module 30 : Anti-Debugging
# ═══════════════════════════════════════════════════════════════════════

CC = gcc
CFLAGS = -Wall -Wextra -std=c11
TARGET = anti_debug

# Détection de la plateforme
ifeq ($(OS),Windows_NT)
    # Windows
    LDFLAGS = -lntdll
    RM = del /Q
else
    # Linux/Unix
    LDFLAGS =
    RM = rm -f
endif

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c $(LDFLAGS)

clean:
	$(RM) $(TARGET)

# Test sous débogueur (ne fonctionne que si gdb/x64dbg est disponible)
test-debug:
ifeq ($(OS),Windows_NT)
	@echo "Lancez le programme sous x64dbg ou WinDbg pour tester"
else
	@echo "Test sous GDB (les techniques anti-debug devraient détecter)"
	gdb -batch -ex run ./$(TARGET)
endif

.PHONY: all clean test-debug

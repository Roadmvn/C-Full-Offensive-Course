# Makefile pour Reverse Shell Project

CC = gcc
CFLAGS = -Wall -Wextra -Isrc -O2
LDFLAGS =

# Dossiers
SRC_DIR = src
BUILD_DIR = build
UTILS_DIR = $(SRC_DIR)/utils
CLIENT_DIR = $(SRC_DIR)/client
SERVER_DIR = $(SRC_DIR)/server
EXAMPLES_DIR = examples

# Fichiers utils (partagés)
UTILS_SRC = $(UTILS_DIR)/crypto.c $(UTILS_DIR)/logger.c
UTILS_OBJ = $(BUILD_DIR)/crypto.o $(BUILD_DIR)/logger.o

# Fichiers client
CLIENT_SRC = $(CLIENT_DIR)/connection.c $(CLIENT_DIR)/commands.c $(CLIENT_DIR)/main_client.c
CLIENT_OBJ = $(BUILD_DIR)/connection.o $(BUILD_DIR)/commands.o $(BUILD_DIR)/main_client.o

# Fichiers server
SERVER_SRC = $(SERVER_DIR)/listener.c $(SERVER_DIR)/handler.c $(SERVER_DIR)/main_server.c
SERVER_OBJ = $(BUILD_DIR)/listener.o $(BUILD_DIR)/handler.o $(BUILD_DIR)/main_server.o

# Binaires finaux
CLIENT_BIN = $(BUILD_DIR)/client
SERVER_BIN = $(BUILD_DIR)/server

# Cible par défaut
all: $(BUILD_DIR) $(CLIENT_BIN) $(SERVER_BIN)

# Créer dossier build
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(BUILD_DIR)/examples

# Client
$(CLIENT_BIN): $(CLIENT_OBJ) $(UTILS_OBJ)
	@echo "🔨 Linking client..."
	$(CC) $^ -o $@ $(LDFLAGS)
	@echo "✅ Client compilé : $@"

# Server
$(SERVER_BIN): $(SERVER_OBJ) $(UTILS_OBJ)
	@echo "🔨 Linking server..."
	$(CC) $^ -o $@ $(LDFLAGS)
	@echo "✅ Server compilé : $@"

# Compilation fichiers objets
$(BUILD_DIR)/%.o: $(UTILS_DIR)/%.c
	@echo "📦 Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(CLIENT_DIR)/%.c
	@echo "📦 Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(SERVER_DIR)/%.c
	@echo "📦 Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# Exemples
examples: $(BUILD_DIR)
	@echo "🔨 Compiling examples..."
	$(CC) $(CFLAGS) $(EXAMPLES_DIR)/basic_shell.c $(UTILS_SRC) -o $(BUILD_DIR)/examples/basic_shell
	@echo "✅ Examples compiled"

# Tests
test: $(BUILD_DIR)
	@echo "🧪 Running tests..."
	$(CC) $(CFLAGS) tests/test_connection.c $(UTILS_SRC) -o $(BUILD_DIR)/test_connection
	$(BUILD_DIR)/test_connection

# Nettoyage
clean:
	@echo "🧹 Cleaning..."
	@rm -rf $(BUILD_DIR)
	@echo "✅ Clean done"

# Rebuild complet
rebuild: clean all

# Installation (optionnel)
install: all
	@echo "📦 Installing binaries..."
	@cp $(CLIENT_BIN) /usr/local/bin/rshell_client
	@cp $(SERVER_BIN) /usr/local/bin/rshell_server
	@echo "✅ Installed to /usr/local/bin/"

# Aide
help:
	@echo "╔════════════════════════════════════════════════╗"
	@echo "║      REVERSE SHELL PROJECT - MAKEFILE          ║"
	@echo "╚════════════════════════════════════════════════╝"
	@echo ""
	@echo "Targets disponibles :"
	@echo "  make all       - Compile client et server"
	@echo "  make client    - Compile seulement client"
	@echo "  make server    - Compile seulement server"
	@echo "  make examples  - Compile les exemples"
	@echo "  make test      - Lance les tests"
	@echo "  make clean     - Nettoie les binaires"
	@echo "  make rebuild   - Clean + compile"
	@echo "  make install   - Installe dans /usr/local/bin"
	@echo ""

.PHONY: all clean rebuild examples test install help


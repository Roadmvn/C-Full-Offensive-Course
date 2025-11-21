# Makefile pour le Module 32 : Persistence Windows

CC = gcc
CFLAGS = -Wall -Wextra -std=c11
LDFLAGS = -ladvapi32
TARGET = persistence_windows

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET).exe main.c $(LDFLAGS)

clean:
	del /Q $(TARGET).exe

.PHONY: all clean

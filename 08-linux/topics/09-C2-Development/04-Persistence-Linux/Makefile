# Makefile pour le Module 33 : Persistence Linux

CC = gcc
CFLAGS = -Wall -Wextra -std=c11
TARGET = persistence_linux

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)

.PHONY: all clean

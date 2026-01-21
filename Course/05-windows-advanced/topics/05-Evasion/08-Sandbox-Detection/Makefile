# Makefile pour le Module 31 : Anti-VM et Anti-Sandbox

CC = gcc
CFLAGS = -Wall -Wextra -std=c11
TARGET = anti_vm_sandbox

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)

.PHONY: all clean

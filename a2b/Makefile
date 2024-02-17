# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -Iinclude -lm -g

# Source dirs
SRC_DIRS = ./src/

# Source files
SRC_FILES = $(shell find $(SRC_DIRS) -name '*.c')

# Object files
OBJ_FILES = $(SRC_FILES:.c=.o)

# Target executable
TARGET = a2b

# Default rule
all: $(TARGET)

# Rule for linking object files
$(TARGET): $(OBJ_FILES)
	$(CC) -o $@ $^ $(CFLAGS)

# Rule for compiling C src files to object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Cleanup
clean:
	rm -f $(TARGET) $(OBJ_FILES)

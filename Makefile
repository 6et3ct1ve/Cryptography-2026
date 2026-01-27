# ============================================================================
# Cryptography Library - Minimal Makefile (Linux/macOS)
# ============================================================================

# Compiler and tools
CC := gcc
AR := ar

# Directories
SRC_DIR := src
OBJ_DIR := obj
LIB_DIR := lib
INC_DIR := include
DEMO_DIR := demo
TEST_DIR := tests

# Compiler flags
CFLAGS := -Wall -Wextra -Werror -std=c17 -pedantic -g -I$(INC_DIR)
ASAN_FLAGS := -fsanitize=address -fno-omit-frame-pointer

# Library settings
LIB_NAME := libcryptography.a
LIB_PATH := $(LIB_DIR)/$(LIB_NAME)

# Source files
LIB_SRC := $(wildcard $(SRC_DIR)/*.c)
LIB_OBJ := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(LIB_SRC))

# Demo
DEMO_SRC := $(DEMO_DIR)/main.c
DEMO_BIN := cryptodemo

# Tests
TEST_SRC := $(wildcard $(TEST_DIR)/test_*.c)
TEST_BINS := $(patsubst $(TEST_DIR)/test_%.c,test_%,$(TEST_SRC))

# Check framework
CHECK_CFLAGS := $(shell pkg-config --cflags check 2>/dev/null)
CHECK_LIBS := $(shell pkg-config --libs check 2>/dev/null || echo "-lcheck -lm -lpthread -lrt -lsubunit")

# ============================================================================
# Main targets
# ============================================================================

.DEFAULT_GOAL := all

all: lib demo

lib: $(LIB_PATH)

demo: $(DEMO_BIN)

test: $(TEST_BINS)
	@echo "=== Running unit tests ==="
	@for test in $(TEST_BINS); do \
		echo "→ $$test"; \
		./$$test || exit 1; \
	done
	@echo "✓ All tests passed"

# Memory leak testing with AddressSanitizer
test-asan:
	@echo "=== Building with AddressSanitizer ==="
	@$(MAKE) clean --no-print-directory
	@$(MAKE) CFLAGS="$(CFLAGS) $(ASAN_FLAGS)" $(TEST_BINS) --no-print-directory
	@echo "=== Running tests with AddressSanitizer ==="
	@for test in $(TEST_BINS); do \
		echo "→ $$test"; \
		./$$test || exit 1; \
	done
	@echo "✓ No memory leaks detected (ASAN)"

# Memory leak testing with Valgrind
test-valgrind: $(TEST_BINS)
	@echo "=== Running tests with Valgrind ==="
	@for test in $(TEST_BINS); do \
		echo "→ $$test"; \
		valgrind --leak-check=full --error-exitcode=1 --quiet ./$$test || exit 1; \
	done
	@echo "✓ No memory leaks detected (Valgrind)"

# ============================================================================
# Build rules
# ============================================================================

# Library
$(LIB_PATH): $(LIB_OBJ)
	@mkdir -p $(LIB_DIR)
	@echo "AR  $@"
	@$(AR) rcs $@ $^

# Library objects
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	@echo "CC  $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Demo
$(DEMO_BIN): $(DEMO_SRC) $(LIB_PATH)
	@echo "LD  $@"
	@$(CC) $(CFLAGS) $< -L$(LIB_DIR) -lcryptography -o $@

# Tests - compile
$(OBJ_DIR)/test_%.o: $(TEST_DIR)/test_%.c
	@mkdir -p $(OBJ_DIR)
	@echo "CC  $< (test)"
	@$(CC) $(CFLAGS) $(CHECK_CFLAGS) -c $< -o $@

# Tests - link
test_%: $(OBJ_DIR)/test_%.o $(LIB_PATH)
	@echo "LD  $@ (test)"
	@$(CC) $(CFLAGS) $< -L$(LIB_DIR) -lcryptography $(CHECK_LIBS) -o $@

# ============================================================================
# Clean targets
# ============================================================================

clean:
	@echo "Cleaning..."
	@rm -rf $(OBJ_DIR) $(LIB_DIR)
	@rm -f $(DEMO_BIN) $(TEST_BINS)
	@echo "✓ Clean complete"

# ============================================================================
# Utility targets
# ============================================================================

info:
	@echo "=== Configuration ==="
	@echo "CC:         $(CC)"
	@echo "Library:    $(LIB_PATH)"
	@echo "Demo:       $(DEMO_BIN)"
	@echo "Tests:      $(TEST_BINS)"
	@echo "Check libs: $(CHECK_LIBS)"

help:
	@echo "Cryptography Library - Available targets:"
	@echo ""
	@echo "  make              - Build library and demo"
	@echo "  make lib          - Build library only"
	@echo "  make demo         - Build demo program"
	@echo "  make test         - Run unit tests"
	@echo "  make test-asan    - Run tests with AddressSanitizer (memory leaks)"
	@echo "  make test-valgrind- Run tests with Valgrind (memory leaks)"
	@echo "  make clean        - Remove all build artifacts"
	@echo "  make info         - Show configuration"
	@echo "  make help         - Show this help"

.PHONY: all lib demo test test-asan test-valgrind clean info help
#Bin
GCC_BIN ?= $(shell which gcc)
CARGO_BIN ?= $(shell which cargo)

# Compilation flags
RUST_BINDING_BINARY = -lfd_chacha20_rust_lib
RUST_LIB = -L./rust-lib/target/release

# Config
FILES_TO_INCLUDE = test_fd_chacha20.c
OUTPUT_BINARY = test_fd_chacha20

default: test_fd_chacha20

test_fd_chacha20: $(FILES_TO_INCLUDE)
	$(CARGO_BIN) build --release --manifest-path=./rust-lib/Cargo.toml
	$(GCC_BIN) -o $(OUTPUT_BINARY) $(FILES_TO_INCLUDE) $(RUST_LIB) $(RUST_BINDING_BINARY)

clean:
	$(CARGO_BIN) clean --manifest-path=./rust-lib/Cargo.toml
	rm -rf test_fd_chacha20 *.o
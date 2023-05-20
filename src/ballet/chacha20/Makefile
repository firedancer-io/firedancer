#Bin
GCC_BIN ?= $(shell which gcc)
CARGO_BIN ?= $(shell which cargo)

# Compilation flags
RUST_BINDING_BINARY = -lfd_chacha20_rust_lib
RUST_LIB = -L./rust-lib/target/release
RUST_MANIFEST = --manifest-path=./rust-lib/Cargo.toml
OPENSSL_INCLUDE = -I/usr/local/opt/openssl/include
OPENSSL_LIB = -L/usr/local/opt/openssl/lib
LCRYPTO = -lcrypto

# Config
FILES_TO_INCLUDE = fd_chacha20.c test_fd_chacha20.c
OUTPUT_BINARY = test_fd_chacha20

default: test_fd_chacha20

test_fd_chacha20: $(FILES_TO_INCLUDE)
	$(CARGO_BIN) build --release $(RUST_MANIFEST)
	$(GCC_BIN) -o $(OUTPUT_BINARY) $(FILES_TO_INCLUDE) $(RUST_LIB) $(RUST_BINDING_BINARY) $(OPENSSL_INCLUDE) $(OPENSSL_LIB) $(LCRYPTO)

clean:
	$(CARGO_BIN) clean $(RUST_MANIFEST)
	rm -rf $(OUTPUT_BINARY) *.o
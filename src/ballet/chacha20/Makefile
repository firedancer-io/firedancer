# Compilation flags
RUST_BINDING_BINARY = -lfd_chacha20_rust_lib
RUST_LIB = -L./rust-lib/target/release

# Config
FILES_TO_INCLUDE = test_fd_chacha20.c
OUTPUT_BINARY = test_fd_chacha20

default: test_fd_chacha20

test_fd_chacha20: $(FILES_TO_INCLUDE)
	gcc -o $(OUTPUT_BINARY) $(FILES_TO_INCLUDE) $(RUST_LIB) $(RUST_BINDING_BINARY)

clean:
	rm -rf test_fd_chacha20 *.o
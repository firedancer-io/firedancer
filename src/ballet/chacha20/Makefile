# Compilation flags
OPENSSL_INCLUDE = -I/usr/local/opt/openssl/include
OPENSSL_LIB = -L/usr/local/opt/openssl/lib
LCRYPTO = -lcrypto

# Config
FILES_TO_INCLUDE = fd_chacha20.o test_fd_chacha20.o
OUTPUT_BINARY = test_fd_chacha20

default: test_fd_chacha20

test_fd_chacha20: $(FILES_TO_INCLUDE)
	gcc -o $(OUTPUT_BINARY) $(FILES_TO_INCLUDE) $(OPENSSL_INCLUDE) $(OPENSSL_LIB) $(LCRYPTO)

fd_chacha20.o: fd_chacha20.c
test_fd_chacha20.o: test_fd_chacha20.c

clean:
	rm -rf test_fd_chacha20 *.o
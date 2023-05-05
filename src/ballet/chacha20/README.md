# fd_chacha20_rng

## Testing (MacOS)

Build binary by using the following command

```
gcc -o test_fd_chacha20_rng test_fd_chacha20_rng.c fd_chacha20_rng.c -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lcrypto
```

Then, run test to generate random numbers (displayed on console output)

```
./test_fd_chacha20_rng
```

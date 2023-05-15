# fd_chacha20_rng

This module depends directly on [rand_chacha::ChaCha20Rng](https://docs.rs/rand_chacha/latest/rand_chacha/struct.ChaCha20Rng.html) Rust binaries. Documentation regarding calling Rust binaries from C code is available [here](https://docs.rust-embedded.org/book/interoperability/rust-with-c.html).

Therefore, `rust-lib` implements a local rust library that consumes `rand_chacha::ChaCha20Rng` to generate cryptographically secure random numbers using chacha20 cipher.

This implementation is intended to be the same as other parts of the Solana protocol (Gossip, Turbine, leader schedule), as it uses the same rust crate.

## Testing Rust implementation

In order to test the rust implementation, you can run the following command:

```
cargo test --manifest-path ./rust-lib/Cargo.toml
```

## Testing C implementation

Regarding testing the C implementation, a `Makefile` has been created to compile both Rust and C code into a test executable binary (`test_fd_chacha20`).

Therefore, to build this test binary you need to run the following command:

```
make
```

Then, run binary to generate random numbers (displayed on console output)

```
./test_fd_chacha20
```

To clean previous binaries & object files, you can run the following:

```
make clean
```

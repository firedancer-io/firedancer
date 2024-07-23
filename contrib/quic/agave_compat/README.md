This directory contains a fd_quic <> solana-streamer integration test.

Usage:

```
sudo apt install -y libclang-dev # Debian like
sudo dnf install -y clang-devel  # Fedora like

cargo build --release
./target/release/firedancer-agave-quic-test server
./target/release/firedancer-agave-quic-test client
```

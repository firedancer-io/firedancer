This directory contains a fd_quic <> quinn integration test.

The quinn_test program provides a stub client and server using the "quinn"
QUIC implementation.  It also depends on rustls, ring, and tokio.

To build quinn_test, use a standard Rust toolchain and run:

  cd quinn_test
  cargo build --release
  ./target/release/quinn_test

Usage:

  quinn_test client 192.168.1.1:9090 connects to the given IP address
  and UDP port.  If the connection suceeds, closes the connection
  gracefully and exits with code 0.  Otherwise, exits with non-zero exit
  code.

  quinn_test server 9090 indefinitely listens on any address and the
  given UDP port.  If a client successfully connects, closes the server
  and exits with code 0.  If a connection attempt was made, but that
  attempt failed, exits with non-zero exit code.

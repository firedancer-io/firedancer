# HTTPS client

Firedancer uses a small embedded TLS library (`fd_tls`) for creating HTTPS
connections (approx ~5000 lines of C code as of August 2026, excluding
assembly code for cryptographic algorithms).

`fd_tls` supports only the exact HTTPS client functionality needed for
Firedancer to connect to modern web servers (e.g. a self-hosted NGINX
server or Cloudflare).

## Motivation

Firedancer does not use external TLS libraries as they introduce hundreds
of thousands of lines of code and complexity to support legacy and exotic
deployments.

`fd_tls` ...
- is entirely contained in the Firedancer repo (less supply-chain risk)
- does not dynamically load code (sandbox)
- does not issue syscalls (sandbox)
- does not do dynamic memory allocation (making it less error prone)
- uses the same modern cryptographic algorithms Solana already uses

## Protocol compatibility

Firedancer's HTTPS client can connect to web servers matching the following
parameters.

- Version: **TLS 1.3**
- Cipher suite; `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`
- Key change group: `X25519`
- Signature algorithms:
  - `Ed25519` (modern, fastest)
  - `ECDSA-P256-SHA256`
  - `ECDSA-P384-SHA384`

## System compatibility

Firedancer loads CA certificates on startup from the following paths:

- `/etc/ssl/certs/ca-certificates.crt`
- `/etc/pki/tls/certs/ca-bundle.crt`
- `/etc/ssl/cert.pem`

Up to 512 CA certs are loaded.

## Usage

Firedancer runs HTTPS clients for the following tasks:

- receiving transactions (bundle tile)
- downloading snapshots (snapld tile)
- sending telemetry data (event tile)

## Limitations

### Missing protocol features

- no RSA certificate support
- no CRL support
- no OCSP support
- no session resumption support (`NewSessionTicket` messages ignored)
- no IP address SAN support
- up to 4 SANs per cert

### Post-quantum support

`fd_tls` does not yet implement post-quantum key exchange and signature
algorithms.

See our work on post-quantum security research here:
[Falcon Verify on AVX-512: Speed Records](https://eprint.iacr.org/2026/1539).

# HTTPS client

Firedancer uses a small embedded TLS library (`fd_tls`) for creating HTTPS
connections.

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
- Cipher suite: `TLS_AES_128_GCM_SHA256`
- Key exchange group: `X25519`
- Signature algorithms:
  - `Ed25519` (modern, fastest)
  - `ECDSA-P256-SHA256`
  - `ECDSA-P384-SHA384` (certificate chains only, not as a client)

## System compatibility

Firedancer loads CA certificates on startup from the first of the
following paths:

- `/etc/ssl/certs/ca-certificates.crt`
- `/etc/pki/tls/certs/ca-bundle.crt`
- `/etc/ssl/ca-bundle.pem`
- `/etc/ssl/cert.pem`

Up to 512 CA certs are loaded.  Certificates with unsupported keys
(e.g. RSA) are skipped.

## Usage

Firedancer runs HTTPS clients for the following tasks:

- receiving transactions (bundle tile)
- downloading snapshots (snapld tile)
- sending telemetry data (event tile)

## Limitations

- No RSA certs
- No FFDHE key exchange (only ECDH)
- No revocation checking (no CRL, no OCSP)
- No session resumption

## Spec deviations

Firedancer intentionally violates the TLS and X.509 IETF RFCs in certain
select areas to improve robustness and system compatibility.  (So do
popular TLS libraries in some of these areas.)

- fd_tls accepts popular root CA certs that violate specs
- No IPv6 SANs (subject alternative names)
- No e-mail CA certificate constraints (extremely rare in the wild)
- No distinguished name Unicode normalization
- Lax checks for duplicate extensions (more permissive validation of TLS
  messages to bound CPU usage)

### Post-quantum support

`fd_tls` does not yet implement post-quantum key exchange and signature
algorithms.

See our work on post-quantum security research here:
[Falcon Verify on AVX-512: Speed Records](https://eprint.iacr.org/2026/1539).

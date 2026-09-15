# HTTPS client

Firedancer uses a small embedded TLS library (`fd_tls`), a TCP record
layer (`fd_tlsrec`), and an X.509 verifier (`fd_x509`) for creating HTTPS
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
  - `ECDSA-P384-SHA384` (certificates only)

## System compatibility

Firedancer loads CA certificates on startup from the first of the
following paths that contains a usable certificate:

- `/etc/ssl/certs/ca-certificates.crt`
- `/etc/pki/tls/certs/ca-bundle.crt`
- `/etc/ssl/cert.pem`

Up to 512 CA certs are loaded.  Certificates with unsupported keys
(e.g. RSA) are skipped.

## Usage

Firedancer runs HTTPS clients for the following tasks:

- receiving transactions (bundle tile)
- downloading snapshots (snapld tile)
- sending telemetry data (event tile)

## Deviations from RFCs

`fd_tls` implements [RFC 8446][tls] (TLS 1.3) and `fd_x509` implements
[RFC 5280][x509] (certificate path validation) and [RFC 6125][identity]
(hostname matching) only as far as the use cases above require.  All
known deviations are listed here.

### Certificates

- Only Ed25519, ECDSA P-256 and ECDSA P-384 keys and signatures are
  supported.  RSA certificates and CAs are rejected.
- No revocation checking (no CRL, no OCSP).
- No certificate policy processing.  Policy extensions are ignored, or
  rejected if marked critical.
- Trust anchors are not checked for expiry or a valid self-signature.
- Three non-compliant roots in the Mozilla root store are accepted:
  serial number zero (HARICA ECC RootCA 2015) and a key usage BIT
  STRING with a trailing zero octet (Trustwave Global ECC P256 and P384).
  Both exceptions apply to every certificate, not just to those roots.
- Hostnames are matched against `dNSName` and IPv4 `iPAddress` SANs
  only.  No fallback to the subject common name and no IPv6 matching.
  Internationalized hostnames must be given as A-labels.
- Wildcards must be the entire leftmost label (`*.example.com`).  No
  public suffix list is consulted.
- Name constraints on DNS names, IP addresses and directory names are
  enforced.  A CA that constrains email addresses is rejected.
- Distinguished names are compared with ASCII case folding and whitespace
  normalization only, not the full string preparation of RFC 5280
  section 7.1.
- `GeneralizedTime` is accepted for dates before 2050.
- Limits: 8 certificates per chain, 64 KiB per certificate, 64 extensions
  per certificate.

### Handshake

- Only the cipher suite, group and signature algorithms listed above.
  P-384 is accepted for certificate signatures but not for
  `CertificateVerify`.
- No pre-shared keys, session resumption or 0-RTT.  `NewSessionTicket`
  messages are ignored.
- The client does not handle `HelloRetryRequest`.  Since it offers a
  key share for the only group it supports, a compliant server never
  sends one.
- Client certificates must be Ed25519.  If the server does not accept
  Ed25519 signatures, an empty `Certificate` is sent instead.
  `certificate_authorities` and `oid_filters` in `CertificateRequest`
  are ignored.  No post-handshake authentication.
- Handshake messages larger than 64 KiB are rejected (the protocol allows
  up to 16 MiB).

### Record layer

- Outgoing records are never padded, so record sizes reveal plaintext
  sizes.
- The server accepts unencrypted alerts from the client until the
  client's `Finished` arrives, matching OpenSSL.  RFC 8446 requires
  alerts after `ServerHello` to be encrypted.
- The final record sequence number (2^64-1) is treated as exhausted
  rather than used.  Sending keys are rotated after 2^24 records, so
  this is unreachable in practice.
- Fatal alerts are sent best effort.  If the TCP send buffer is full the
  connection is closed without one.

### Post-quantum support

`fd_tls` does not yet implement post-quantum key exchange and signature
algorithms.

See our work on post-quantum security research here:
[Falcon Verify on AVX-512: Speed Records](https://eprint.iacr.org/2026/1539).

[tls]: https://www.rfc-editor.org/rfc/rfc8446
[x509]: https://www.rfc-editor.org/rfc/rfc5280
[identity]: https://www.rfc-editor.org/rfc/rfc6125

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

This is a deliberately restricted implementation, **not a general-purpose
RFC-compliant TLS/PKI library**.  In particular, it does not implement the
full mandatory algorithm set of [RFC 8446 section 9.1][tls].
The compliance profile and known exceptions below describe HTTPS clients,
not the separate trust model for Solana QUIC peer identities.

## System compatibility

Firedancer loads CA certificates on startup from the following paths:

- `/etc/ssl/certs/ca-certificates.crt`
- `/etc/pki/tls/certs/ca-bundle.crt`
- `/etc/ssl/cert.pem`

The first bundle containing usable anchors is used; bundles are not
merged.  Unsupported or unusable certificates are skipped.  In particular,
RSA roots cannot be loaded, even if the server leaf uses ECDSA.
Up to 512 CA certs are loaded.

## Usage

Firedancer runs HTTPS clients for the following tasks:

- receiving transactions (bundle tile)
- downloading snapshots (snapld tile)
- sending telemetry data (event tile)

## X.509 validation profile

The verifier implements a bounded TLS-server-authentication profile of
[RFC 5280][x509], with SAN identity matching following [RFC 6125][identity].
Parsing a certificate alone does not authenticate it.

### Enforced checks

- The leaf must chain through supplied issuers to a locally configured
  trust anchor.  Issuers after the leaf may arrive out of order, and
  alternative cross-signed paths are tried.  Certificates beyond a
  successfully reached anchor need not be used or validated.
- Every certificate used on the path has its signature, issuer name,
  validity period (including both endpoints), and applicable usages
  checked.  A self-issued intermediate is not automatically trusted:
  only its path-length counting and inherited name-constraint checks
  receive the exceptions specified in RFC 5280 section 6.1.
- Issuers require critical `basicConstraints` with `cA=TRUE`.
  `keyUsage`, when present, must allow certificate signing for issuers
  and digital signatures for the leaf.  `keyCertSign` without `cA` is
  rejected.  An explicit key usage inconsistent with `pathLenConstraint`
  is rejected regardless of extension order.  Absent key usage remains
  unconstrained, including for CAs with a path-length constraint.
- `extendedKeyUsage`, when present, must contain `serverAuth` or
  `anyExtendedKeyUsage`; this policy also applies to intermediate CAs
  and imported trust anchors.
- Intermediate and anchor path-length and name constraints are enforced.
  DNS, IPv4/IPv6 address, and directory-name subtrees are supported.
  Excluded DNS subtrees reject overlapping wildcard expansions; permitted
  subtrees must contain the whole wildcard scope.
- Issuer names and CA subject names must be nonempty.  An empty leaf
  subject requires a nonempty critical SAN.  Name constraints must be
  critical and belong to a CA.
- Extension OIDs must be unique, including ignored noncritical extensions.
  Unknown critical extensions are rejected.  Supported extensions and
  their enclosing DER structures must be completely consumed.
  DNS SAN syntax is checked even for entries not used for identity
  matching.  Empty DNS, email, and URI SAN entries are rejected.
- UTF-8, BMPString, UniversalString, IA5String and PrintableString
  encodings in distinguished names are checked before comparison.

### Deliberate restrictions and compatibility choices

- **Algorithms:** no RSA, DSA, other curves, or compressed EC public
  points.  Certificate signature verification supports Ed25519,
  P-256/SHA-256 and P-384/SHA-384, not arbitrary curve/hash combinations.
  A P-256 leaf signed by a P-384/SHA-384 issuer is supported; P-384
  `CertificateVerify` handshake signatures are not.
- **Identities:** SAN-only DNS and IPv4 matching; no common-name fallback,
  IPv6 reference-address matching, URI-ID, or SRV-ID.  IPv6 SANs can be
  parsed and constrained even though they cannot match a reference
  hostname.  Callers must supply ASCII names (IDNA A-labels where
  appropriate); no Unicode-to-IDNA conversion is performed.
  DNS matching folds ASCII case and removes one trailing dot from the
  reference hostname.  Underscores are accepted for compatibility.
  For identity matching, wildcards must occupy the complete leftmost
  label, match one label, and have at least two suffix labels.
  There is no public-suffix lookup.
- **Name constraints:** email constraints are deliberately unsupported.
  A CA constraining `rfc822Name` is rejected, rather than ignoring
  constraints on legacy subject `emailAddress` attributes.  Other
  unsupported constraint forms reject certificates carrying a SAN of
  that form.  Explicit subtree `minimum` or `maximum` is rejected
  (the supported RFC 5280 profile uses omitted default zero and no
  maximum).  IP masks are matched bitwise, without a contiguous-prefix
  check.
- **Distinguished names:** matching handles RDN sets, selected
  case-insensitive attribute OIDs, ASCII case folding and ASCII-space
  normalization.  TeletexString is interpreted as Latin-1.  Other
  attributes compare exactly.  Full Unicode preparation, normalization
  and case folding from RFC 5280 section 7.1 are not implemented.
  Attribute-specific string types/lengths and canonical DER ordering
  within RDN sets are not comprehensively enforced.
- **Certificate policies:** no policy tree, policy mappings, or
  explicit-policy processing.  Unsupported critical policy extensions
  reject the certificate; noncritical policy extensions are ignored.
  AKI/SKI, AIA, CRL distribution points, and other unknown noncritical
  extensions are not interpreted.  No missing issuers are fetched.
  Opaque `otherName`, `x400Address` and `ediPartyName` SAN contents
  receive only outer framing/nonempty checks.  Email and URI SANs receive
  nonempty/ASCII checks, not mailbox or absolute-URI syntax validation;
  ASCII control characters in those unused identity forms are not rejected.
- **Time:** UTC `Z`, seconds, and valid calendar dates are required;
  leap seconds are rejected.  GeneralizedTime before 2050 is accepted,
  despite the issuance profile's requirement for UTCTime in that range.
- **TLS-specific CA profile:** `cA=TRUE` requires critical basic
  constraints even for CRL-only CAs, which this verifier does not use.
  Absent key usage and EKU are allowed; this is not an implementation
  of all CA/Browser Forum certificate-issuance requirements.

### Trust anchors and grandfathered certificates

A local trust anchor is an input to path validation, not an additional
certificate on the path (RFC 5280 sections 6.1 and 6.2).  Its self-signature
and expiration are not checked.  Import still requires a supported key,
CA status, and compatible KU/EKU, and retains its path-length and name
constraints.  Manually populated stores must preserve this import policy.

Two compatibility exceptions in the shared certificate parser are retained:

| Exception | Known affected roots (SHA-256 of DER certificate) |
| --- | --- |
| Serial number zero | Hellenic Academic and Research Institutions ECC RootCA 2015: `44b545aa8a25e65a73ca15dc27fc36d24c1cb9953a066539b11582dc487b4833` |
| Nonminimal key-usage BIT STRING with a trailing zero octet (`07 06 00`, rather than `01 06`) | Trustwave Global ECC P256 Certification Authority: `945bbc825ea554f489d1fd51a73ddf2ea624ac7019a05205225c22a78ccfa8b4`; Trustwave Global ECC P384 Certification Authority: `55903859c8c0c3ebb8759ece4e2557225ff5758bbd38ebd48276601e1bd58097` |

These are **parser-wide allowances**, not fingerprint allowlists limited
to root import.  Serial zero is deliberately tolerated; RFC 5280
section 4.1.2.2 also recommends gracefully handling nonconforming serials.
Negative, oversized, and nonminimal serial encodings are rejected.
The key-usage exception permits a trailing zero octet after a nonzero
octet, not just the two roots' exact values.  Restricting that DER
exception to anchor import is deferred.  Signed bytes are never
rewritten or normalized before signature verification.

## TLS 1.3 over TCP

The handshake follows [RFC 8446][tls] within the negotiated profile above.
Extension framing and uniqueness are checked, including unknown extension
types.  Required version/key-share/signature extensions must be present;
recognized extensions in the wrong handshake message and unsolicited
server extensions are rejected.  Unknown ClientHello offers can still be
ignored, and a server's supported-groups list in EncryptedExtensions is
permitted.  Certificate message framing is checked independently of
whether CA verification is enabled.  TCP ClientHello advertises separate
handshake and certificate signature capabilities.

Record behavior follows sections 5 and 6:

- TCP reads can fragment or coalesce records and handshake messages.
  Handshake messages cannot be interleaved with other content types
  except permitted compatibility CCS; messages changing keys must end
  their record.
- Legacy record-version fields are ignored on receive, but the actual
  received header remains authenticated as AEAD additional data.
  Outgoing records use the prescribed TLS 1.3 legacy version.
- Valid unencrypted compatibility CCS messages are discarded after the
  first ClientHello and before the peer's Finished, including duplicates
  and messages between handshake fragments.  Malformed, encrypted, or
  out-of-window CCS is rejected.  No compatibility CCS is generated.
- Plaintext content is limited to 16,384 bytes.  The complete decrypted
  inner plaintext, including content type and padding, is limited to
  16,385 bytes.  Empty handshake fragments are rejected; empty
  application-data records are allowed.  Received padding is removed;
  outgoing records are not padded and reveal their plaintext length.
- Read and write key transitions are independent.  Application
  `KeyUpdate` is supported, requested updates are answered before more
  application data is sent, and write keys rotate before the next
  application-data send once the write counter reaches `2^24` records.
  Sequence numbers must not wrap.
- `close_notify` closes the receive direction without closing the write
  direction.  Data after peer closure is discarded.  No records are
  sent after local closure.  `user_canceled` is ignored; other error
  alerts terminate the connection.

### Deliberately unsupported TLS features

- No older TLS versions, alternative cipher suites/groups, PSK,
  resumption, 0-RTT, or RFC 7250 raw-public-key negotiation.  Client-side
  `NewSessionTicket` messages are discarded without interpreting their
  bodies.
- No post-handshake client authentication.  Initial CertificateRequest
  must use an empty context and advertise signature algorithms.  A
  client without a suitable configured Ed25519 credential responds with
  an empty Certificate, not an unrequested signature scheme.
  Rich credential selection using CA names and OID filters is not
  implemented; those request-extension bodies are treated as opaque
  rather than fully validated or used to filter the local certificate.
  CertificateRequest `signature_algorithms_cert` syntax is checked, but
  that list does not currently filter the configured client certificate.
- One configured ALPN protocol; TCP permits a server to omit ALPN.
  QUIC integrations must configure ALPN: the handshake's ALPN requirement
  is conditional on a configured protocol.  QUIC uses a separate
  transport, not TCP TLS records.
- QUIC identity certificates are not Web-PKI credentials: extracting
  their Ed25519 keys and checking TLS proof of possession does not imply
  CA-chain, expiration, or hostname validation.  TLS message framing
  checks still apply.

## Deferred work and integration caveats

These are known gaps, not claims of complete RFC conformance:

- **Revocation:** CRL and OCSP validation are not implemented.  A revoked
  but otherwise valid chain may be accepted.
- **HelloRetryRequest:** the client does not support retries, including
  cookie-only retries.  The server retry path does not fully compare
  immutable ClientHello fields across attempts (RFC 8446 section 4.1.2).
- **Path building:** a malformed or unsupported unused issuer candidate
  encountered during search aborts validation instead of trying all
  later candidates.  This differs from trailing unused certificates
  skipped after a trusted path is already complete.
- **Diagnostics:** certificate-verification failures generally map to
  TLS `bad_certificate`, rather than distinguishing every applicable
  certificate alert.  Unsupported root public keys can be logged as
  a parse failure.
- **Socket shutdown:** fatal alerts are best-effort under send-buffer
  backpressure; callers may close before an alert has drained.  The
  socket API uses the same EOF result for TCP EOF and `close_notify`;
  callers must inspect `rx_closed` and application framing to distinguish
  authenticated closure from truncation.  EOF alone is not evidence of
  a complete response.
- **Authentication configuration:** `fd_tls` only performs Web-PKI
  verification when a CA store is configured.  The lower-level X.509
  API skips identity matching for a NULL or empty reference hostname.
  HTTPS integrations must provide both the store and expected identity.

### Resource bounds

These limits deliberately reject some otherwise valid protocol inputs:

- Eight supplied certificates, 64 KiB per certificate, 32 signature
  attempts per path search, and 64 extensions per certificate.
- Distinguished names: 16 attributes per RDN and 512 code units per
  string-typed attribute (UTF-8 is bounded in bytes).
- Trust store: 512 anchors, 512 bytes per encoded subject, 1,024 bytes
  of name constraints per anchor, 8,192 stripped base64 characters per
  PEM certificate, and a 64 MiB bundle limit.
- TCP handshake reassembly: 64 KiB including the handshake header
  (smaller than TLS's theoretical 24-bit message-length limit).
  Outgoing handshake staging is also bounded.
- Local configured certificates are limited to 1,011 bytes.  SNI, ALPN,
  and QUIC transport parameters have fixed-size buffers.

The record/socket APIs require bounded output capacity and caller-driven
polling, flushing, deadlines and transport shutdown.  Insufficient RX
output capacity is a fatal integration error, not a retry indication.
The handshake send staging buffer is thread-local; recursively driving
another connection's handshake on the same thread is unsupported.

### Post-quantum support

`fd_tls` does not yet implement post-quantum key exchange and signature
algorithms.

See our work on post-quantum security research here:
[Falcon Verify on AVX-512: Speed Records](https://eprint.iacr.org/2026/1539).

[tls]: https://www.rfc-editor.org/rfc/rfc8446
[x509]: https://www.rfc-editor.org/rfc/rfc5280
[identity]: https://www.rfc-editor.org/rfc/rfc6125

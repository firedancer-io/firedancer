# TPU-QUIC API

Firedancer block producers expose a TPU-QUIC server which accepts
Solana transactions from any client.

::: info HISTORY

TPU-QUIC is an upgraded version of the original [TPU-UDP](./tpu-udp.md)
protocol featuring latency monitoring, loss detection, retransmission,
fragmentation, and client-side congestion control.

:::

## Protocol

Each signed transaction is sent as a separate unidirectional QUIC stream.

The server does not limit the number of QUIC streams created per
connection.

Clients should limit stream fragmentation and interleaving.
Each QUIC stream should be transmitted in a single QUIC frame.

Clients should immediately transition all streams created to ["Data Sent"](https://www.rfc-editor.org/rfc/rfc9000.html#name-sending-stream-states) state. A client having more than one
stream per connection in "Ready" or "Send" state at any given time is
indicative of data loss.

## Handshake

Clients establish a [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html)
connection using the TLS parameters [below](#tls).

The Firedancer TPU-QUIC server does not support 0-RTT.

By default, servers require a stateless retry to help with path
authentication (mitigates source IP spoofing).

## TLS

Firedancer TPU-QUIC servers support the following TLS parameters.

- TLS version 1.3 (RFC 8446)
- ALPN: `solana-tpu`
- Cipher suites
  - `TLS_AES_128_GCM_SHA256` (0x1301, TLS 1.3)
- Certificate Types
  - X.509
  - Raw Public Keys (RFC 7250)
- Signature schemes
  - `ed25519` (0x0807)
- Key exchange groups
  - `x25519` (29)

### TLS certificate

Firedancer servers advertise a random X.509 certificate with a
randomly generated public key and an invalid certificate signature.

This is a deliberate choice. The QUIC-TPU transport does not aim to be
authenticated nor encrypted: transactions are already inherently
authenticated (signed). The purpose of the TPU-QUIC protocol is to
submit transactions for public global broadcasting, therefore
encryption is not a desired property either.

## Receive acknowledgements

Firedancer's TPU-QUIC server sends periodic ACK frames. ACKs are
randomized delayed up to `[tiles.quic.ack_delay_millis]`. The ACK delay
is advertised to clients via QUIC transport parameters.

ACKs merely confirm receipt of network packets. ACKs are useful to
measure network latency and packet loss rate. ACKs do not imply
acceptance of transaction data.

## Fragmentation

Fragmentation is undeseriable and avoidable client behavior. It occurs
when a client splits a transaction across multiple packets. As of May
2026, the max transaction size is considerably smaller than IPv4 MTU.

The Firedancer TPU server supports fragmentation with a default
reassembly buffer size of ~150 MB. (see `[tiles.quic.txn_reassembly_count]`).

The reassembly buffer uses a robust FIFO cache replacement policy: The
more time passes between the arrival of the first and last fragment of a
transaction, the more likely it is that Firedancer drops/discards the
transaction before all fragments arrive.

As of May 2026, fragmentation-induced drops are extremely rare on
mainnet. They practically only occur when a client disconnects mid-
transmission. Clients typically send all fragments of a transaction in
the same packet burst (<1µs reassembly time).

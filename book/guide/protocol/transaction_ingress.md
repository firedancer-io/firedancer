# Transaction Ingress (TPU)

TPU is the main protocol to submit new transactions to the Solana
network.

Each Firedancer block producer exposes a TPU server accepting
transactions via the TPU-UDP and TPU-QUIC APIs.

Incoming transactions enter the "leader pipeline", where they are
verified, deduplicated, and ordered for inclusion in blocks produced by
the validator.

The TPU APIs are provided by the `quic` tile.

### UDP port numbers

UDP port numbers are configurable by the validator operator.
Clients should use gossip to discover the TPU endpoints of a block
producer.

The default UDP port numbers are 9001 (TPU-UDP), 9007 (TPU-QUIC).

### Connection Table

Firedancer's TPU-QUIC server supports up to one million connections per
`quic` tile.

The network stack automatically load balances connections across
multiple QUIC tiles.

### Receive limits

Firedancer does not apply receive limits for TPU-QUIC nor TPU-UDP.

## API reference

[TPU-QUIC](../../api/tpu-quic.md) uses a connection-oriented
transport featuring loss detection, TCP-like retransmission, and
acknowledgements. This is the recommended transport protocol.

[TPU-UDP](../../api/tpu-udp.md) is a minimal connection-less ingress
protocol. Useful for fire-and-forget clients that optimize for tail
latency.

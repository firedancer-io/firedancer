# TPU-UDP API

Firedancer block producers expose a TPU-UDP server which accepts
Solana transactions from any client.

::: tip TPU-QUIC

[TPU-QUIC](./tpu-quic.md) is an upgraded version of the original TPU-UDP
protocol featuring latency monitoring, loss detection, retransmission,
fragmentation, and client-side congestion control.

:::

## Protocol

The TPU-UDP protocol is unidirectional.

Clients send each signed transaction as a separate UDP datagram.

UDP checksums are optional.

The TPU-UDP protocol provides no further information about what
happened to the submitted transactions.

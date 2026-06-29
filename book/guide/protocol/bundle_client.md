# Bundle Client

Firedancer can optionally receive bundles containing additional
transactions from a bundle server.

::: info BUNDLES

A bundle contains up to 5 transactions that are packed "atomically" into
a block without interleaving with other transactions.

Bundles pay "tips" to the block producer in addition to regular
transaction fees.

:::

## Bundle protocol

::: warning

Only connect to trusted bundle servers.

A malicious bundle server can cause as Firedancer block producer to
create empty or skipped blocks.

:::

Firedancer subscribes to the following feeds provided by a bundle server:
- bundles (groups of transactions)
- raw transactions
- block builder fee info (configures the bundle tip commission to be
  paid back to the bundle server operator)

The `bundle` tile within Firedancer runs the bundle client.
It reconnects with backoff on failure.

It also periodically requests "block builder fee" information, which
instructs Firedancer of the bundle tip commission charged by the bundle
server.

## Transport

The bundle protocol uses gRPC over HTTP/2.

The bundle tile uses regular TCP sockets (does not use Firedancer XDP).

HTTPS (TLS 1.3) is supported using OpenSSL.

### TLS CA certificates

When using to secure gRPC (HTTPS), the bundle tile verifies the server
certificate against CA certificates in `/etc/ssl/certs`. The CA cert path
is hardcoded.

### Packet capture

Bundle gRPC connections are encrypted.

By default, the bundle tile does not log or otherwise export encryption keys.

To decrypt bundle flows captured in a `.pcap` file, an external file
created by `[development.bundle.ssl_key_log_file]` is required.

The Wireshark gRPC dissector, combined with [solana_dissector](https://github.com/firedancer-io/solana_dissector)
helps view and extract transactions in bundle flows.

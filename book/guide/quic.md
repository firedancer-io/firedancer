# QUIC in Firedancer

Certain Solana network protocols are layered on top of QUIC,
a connection-oriented transport layer over UDP.

This page documents specifics of fd_quic, Firedancer's custom QUIC library.

## Overview

QUIC is a complex network protocol with various optional extensions.
It is mainly specified by three documents:
- [RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000)
- [RFC 9001](https://datatracker.ietf.org/doc/html/rfc9001)
- [RFC 9002](https://datatracker.ietf.org/doc/html/rfc9002)

In order to provide maximum performance and reliability, fd_quic
implements as few QUIC components as possible.  These currently include:
- The QUIC-TLS handshake layer
- Header and payload encryption
- Stream multiplexing and fragmentation
- ACKs, loss detection, and retransmission

fd_quic adds various protocol restrictions that are vaguely recommended by
the RFC documents.  These are precisely specified below.

## Performance

fd_quic is entirely single threaded.  Thus, all figures are per core.
fd_quic can be linearly scaled by L4 load balancing ingress to multiple
cores (receive side scaling).

As of 2024-Nov, fd_quic is optimized for use as a Solana TPU server.
It supports up to 1 million concurrent connections.

## QUIC-TLS Handshake

### TLS message fragmentation

fd_quic will fail to establish a connection to peers that fragment a TLS
handshake message (e.g. a ClientHello) across two or more QUIC CRYPTO
frames.  In other words, each TLS message must begin and end within one
QUIC CRYPTO frame, and thus also be entirely contained within the same
packet.  A CRYPTO frame may contain multiple handshake messages
concatenated.

The rationale is that virtually any TLS handshake exchange on the Solana
network only amounts to a few hundred bytes.

### Certificates

fd_quic is primarily designed for use in peer-to-peer networks, which do
not have a concept of certificate authorities.  In Solana's peer-to-peer
protocols, the only useful piece of information in a certificate is the
supposed public key of the peer.

fd_quic/fd_tls understand two certificate types to wrap the Ed25519 public
key: RFC 7250 Raw Public Keys (RPK), and fake X.509 certificates.

RPKs are the preferred certificate type.

Because support for RPK is rare the wild, fd_quic further supports fake
X.509 Solana certificates.  These resemble self-signed certificates, but
may contain an invalid signature.  They are exactly 249 bytes large, and
must match the following hexdump exactly, except for the public key field
(32 bytes at offset 100).

Note that the TLS connection is always authenticated even if the cert
signature is ignored.  (via TLS CertificateVerify signatures, which are
unique per connection)

<details>
<summary>Fake certificate ASN.1 dump</summary>

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 72340172838076673 (0x101010101010101)
    Signature Algorithm: Ed25519
        Issuer: CN=Solana node
        Validity
            Not Before: Jan  1 00:00:00 1970 GMT
            Not After : Jan  1 00:00:00 4096 GMT
        Subject:
        Subject Public Key Info:
            Public Key Algorithm: Ed25519
            [ PUBLIC KEY GOES HERE ]
        X509v3 extensions:
            X509v3 Subject Alternative Name: critical
                DNS:localhost
            X509v3 Basic Constraints: critical
                CA:FALSE
    Signature Algorithm: Ed25519
         ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
         ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
         ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
         ff:ff:ff:ff:ff:ff:ff:ff:ff:ff
```

</details>

<details>
<summary>Fake certificate hex dump</summary>

To construct a fake certificate, copy paste the Ed25519 public key at
offset 0x64.

```
00000000: 3081 f630 81a9 a003 0201 0202 0801 0101  0..0............
00000010: 0101 0101 0130 0506 032b 6570 3016 3114  .....0...+ep0.1.
00000020: 3012 0603 5504 030c 0b53 6f6c 616e 6120  0...U....Solana
00000030: 6e6f 6465 3020 170d 3730 3031 3031 3030  node0 ..70010100
00000040: 3030 3030 5a18 0f34 3039 3630 3130 3130  0000Z..409601010
00000050: 3030 3030 305a 3000 302a 3005 0603 2b65  00000Z0.0*0...+e
00000060: 7003 2100 ffff ffff ffff ffff ffff ffff  p.!.............
00000070: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000080: ffff ffff a329 3027 3017 0603 551d 1101  .....)0'0...U...
00000090: 01ff 040d 300b 8209 6c6f 6361 6c68 6f73  ....0...localhos
000000a0: 7430 0c06 0355 1d13 0101 ff04 0230 0030  t0...U.......0.0
000000b0: 0506 032b 6570 0341 00ff ffff ffff ffff  ...+ep.A........
000000c0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
000000d0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
000000e0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
000000f0: ffff ffff ffff ffff ff                   .........
```

</details>

### Raw Public Keys

Raw Public Keys are an alternative certificate type specified in
[RFC 7250](https://datatracker.ietf.org/doc/html/rfc7250).

fd_quic/fd_tls support Ed25519 raw public keys.

<details>
<summary>Raw Public Key ASN.1 dump</summary>

```
    0:d=0  hl=2 l=  42 cons: SEQUENCE
    2:d=1  hl=2 l=   5 cons: SEQUENCE
    4:d=2  hl=2 l=   3 prim: OBJECT            :Ed25519
    9:d=1  hl=2 l=  33 prim: BIT STRING
```

</details>

<details>
<summary>Raw Public Key Hexdump</summary>

To construct a raw public key, paste the Ed25519 public key at offset 0x0c.


```
00000000: 302a 3005 0603 2b65 7003 2100 ffff ffff  0*0...+ep.!.....
00000010: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000020: ffff ffff ffff ffff ffff ffff            ............
```

</details>

### Next Protocol Selection

fd_quic/fd_tls uses the ALPN TLS extension (RFC 7301) to verify that
both endpoints of a connection talk the same protocol over QUIC.

## ACK timing

fd_quic delays outgoing acknowledgements (ACK frames) of application
traffic to reduce TX rate.  fd_quic specifies the maximum artificial ACK
delay in the `max_ack_delay` QUIC transport parameter.  `max_ack_delay`
does not include network and processing delays.

The delay logic is as follows:
- ACKs for handshake traffic and exceptional events are always sent without
  artificial delay.
- Each connection has an ACK delay buffer.
- ACKs for other traffic (e.g. application traffic / STREAM frames) are
  merged into the ACK delay buffer.
- The buffer is flushed if the oldest ACK is older than `max_ack_delay`.
- The buffer is flushed if more than `ack_threshold` bytes of stream data
  sent by the peer are awaiting ACKs.

Note that the ACK delay buffer is optimized towards ACKs over a gapless
sequence of packet numbers.  If the peer frequently skips packet numbers,
ACKs will get dropped before being sent.

(More details on the algorithm can be found in fd_quic_ack_tx)

## Encryption keys

fd_quic supports exporting of TLS master secrets in the SSLKEYLOGFILE
format.  fd_quic is further able to generate pcapng files that contain
both QUIC packets and TLS master secrets, allowing for convenient packet
analysis in Wireshark.

TLS secret logging is disabled by default.  It is available via the
`--pcap` flag for most fd_quic unit tests.

## Unsupported Features

As of 2024-Nov, features that fd_quic does not support include:

- IPv6
- Bidirectional streams
- qlog (a QUIC trace format)
- Version negotiation
- QUIC v2 (identical to QUIC v1)
- Congestion control and send pacing for outgoing packets
- 0-RTT packets and session resumption

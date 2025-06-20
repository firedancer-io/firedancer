# Bundle tile 2.0

This directory contains a rewrite of the "bundle" tile.

## Feature checklist

**Bundle tile 1.0**

Features supported by the old bundle tile:

- [x] Packet delivery
- [x] Bundle delivery
- [X] gRPC over HTTP/2 connections without TLS
- [x] gRPC over HTTP/2 connections with TLS
- [x] Custom SNI
- [x] Seccomp sandboxing
- [x] Challenge-response auth token flow
- [ ] Refresh auth token flow
- [x] Basic metrics
- [x] Connection time out
- [ ] Reconnect back-off

**Bundle tile 2.0**

Features to ship in the new bundle tile:

- [x] TCP performance metrics
- [ ] HTTP/2 performance metrics
- [ ] gRPC performance metrics
- [x] SSL key log file

**Unsure**

- [ ] Power saving (yield to OS scheduler when I/O is inactive)

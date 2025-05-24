This directory contains an implementation of the HTTP/2 framing layer.

## Notices

**HTTP**

This is not an HTTP library.  This library provides a framing layer
only.  In other words, RFC 9113 Section 8 is missing entirely.

**HPACK fragmentation**

This library assumes that a single header record (HPACK record) is not
fragmented across two HTTP frames (e.g. HEADERS and CONTINUATION).
Throws connection error COMPRESSION_ERROR if the peer does that.

**Server Push**

PUSH_PROMISE / HTTP Server Push is not supported (disabled via SETTINGS)

**Priority**

HTTP/2 priority hints are ignored.

**HPACK dynamic table**

The HPACK dynamic table is not supported (disabled via SETTINGS).

This may cause compatibility issues when running as a server.  The
dynamic table provides stateful HTTP header compression.  Unfortunately,
there is a race condition between disabling the dynamic table and the
client's first few requests.  A conforming client may generate multiple
requests before seeing our SETTINGS.  The second request might reuse a
header from the first request via HPACK, but fd_h2 does not understand
this.

**END_STREAM / CONTINUATION state**

> A HEADERS frame with the END_STREAM flag set signals the end of a stream.
> However, a HEADERS frame with the END_STREAM flag set can be followed by
> CONTINUATION frames on the same stream. Logically, the CONTINUATION frames
> are part of the HEADERS frame.

fd_h2 does not support this correctly.

## HTTP/2 quirks

This section points out a few HTTP/2 quirks in general.

### Header sequence

In the HTTP/2 framing layer, one may send arbitrarily many field blocks.
Examples of field blocks are headers (mandatory) or trailers (optional).
But a client might also send multiple field blocks before sending data,
giving the appearance that there are conflicting headers.  Or even send
field blocks while still transmitting data like an odd form of
out-of-band data.

### Server requests

In the HTTP/2 framing layer, the server may initiate streams.  This is
unrelated to server push or regular responses.  In HTTP semantics, this
is as if the HTTP server sent HTTP requests to the client.

## Coverage

```shell
CORPUS=~/corpus/fuzz_h2 # change this
make CC=clang EXTRAS=llvm-cov BUILDDIR=clang-cov -j build/clang-cov/fuzz-test/fuzz_h2 && \
  build/clang-cov/fuzz-test/fuzz_h2 $CORPUS && \
  llvm-profdata merge -o cov.profdata default.profraw && \
  llvm-cov export -format=lcov --instr-profile cov.profdata build/clang-cov/fuzz-test/fuzz_h2 > cov.lcov && \
  genhtml --output report cov.lcov
```

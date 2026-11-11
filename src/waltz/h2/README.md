This directory contains an implementation of the HTTP/2 framing layer.

## Notices

**HTTP**

This is not an HTTP library.  This library provides a framing layer
only.  In other words, RFC 9113 Section 8 is missing entirely.

**HPACK fragmentation**

Fragmented and discarded field blocks are validated incrementally,
including HPACK records split across frames, without retaining their
decoded fields.  Live-stream header consumers such as fd_grpc_client
still require each HPACK record to fit in one frame.

**Server Push**

PUSH_PROMISE / HTTP Server Push is not supported (disabled via SETTINGS)

**Priority**

HTTP/2 priority hints are ignored.

**HPACK dynamic table**

The decoder implements the HPACK dynamic table (`fd_hpack_dtable_t`).
The encoder only uses the static table.

A conn has no table unless the app attaches one (`conn->rx_dtable`)
and advertises its size as `SETTINGS_HEADER_TABLE_SIZE`
(`self_settings.header_table_size`).  fd_grpc_server does so with the
HTTP/2 default of 4096, because a client may send its first request
before it has read the server's SETTINGS.  With a table, every field
block is delivered to the headers callback, including those of refused
or released streams (with a NULL stream), so the app keeps the table in
sync.  Without a table, such blocks are validated by `fd_hpack_skip`
and dropped.

**END_STREAM / CONTINUATION state**

> A HEADERS frame with the END_STREAM flag set signals the end of a stream.
> However, a HEADERS frame with the END_STREAM flag set can be followed by
> CONTINUATION frames on the same stream. Logically, the CONTINUATION frames
> are part of the HEADERS frame.

The receive-side stream state preserves END_STREAM until the field
block completes.  Header consumers must check that state on END_HEADERS;
fd_grpc_client does so.

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

RFC 9113 Section 5.1 forbids HEADERS on an idle server-initiated stream.
The default client behavior is a connection PROTOCOL_ERROR.
Setting conn.allow_server_requests explicitly enables the previous,
nonstandard extension that accepts such streams through stream_create.
This extension is unrelated to server push or regular responses.

## Coverage

```shell
CORPUS=~/corpus/fuzz_h2 # change this
make CC=clang EXTRAS=llvm-cov BUILDDIR=clang-cov -j build/clang-cov/fuzz-test/fuzz_h2 && \
  build/clang-cov/fuzz-test/fuzz_h2 $CORPUS && \
  llvm-profdata merge -o cov.profdata default.profraw && \
  llvm-cov export -format=lcov --instr-profile cov.profdata build/clang-cov/fuzz-test/fuzz_h2 > cov.lcov && \
  genhtml --output report cov.lcov
```

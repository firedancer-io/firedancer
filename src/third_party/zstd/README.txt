This directory contains a subset of the Zstandard library at
https://github.com/facebook/zstd

Files are copied exactly from tag v1.5.7, with no Firedancer
specific modifications.  Do not edit vendored files locally; update
by re-running `vendor.sh` against a new pinned tag.

Compiled single-threaded (no ZSTD_MULTITHREAD; pool/threading reduce
to stubs, zstdmt_compress.c is not imported).  dictBuilder is
present only to satisfy librocksdb.a's ZDICT_* references in
dev-mode builds; first-party code uses no ZDICT API.  Consumers use
ZSTD_STATIC_LINKING_ONLY static-allocation APIs, which upstream
marks unstable -- version bumps must re-audit those call sites
(fd_zstd.c, snapdc).

zstd is dual-licensed BSD-3-Clause OR GPL-2.0; it is taken here
under BSD-3-Clause only (LICENSE in this directory; upstream's
COPYING/GPL text is deliberately not imported).  See also NOTICE in
the root of this repo.

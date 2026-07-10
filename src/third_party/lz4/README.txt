This directory contains a subset of the LZ4 library at
https://github.com/lz4/lz4

Files are copied exactly from tag v1.10.0 (lib/ only -- lib/ is
BSD-2-Clause; upstream's programs/ tree is GPL and must never be
imported).  No Firedancer specific modifications.  Do not edit
vendored files locally; update by re-running `vendor.sh` against a
new pinned tag.

lz4.c/lz4.h (core block API) cover all first-party use (fd_checkpt,
fd_restore, fd_wksp, vinyl).  lz4hc exists only to satisfy
librocksdb.a's LZ4_compress_HC* references in dev-mode builds.

For licensing information, see LICENSE in this directory and NOTICE
in the root of this repo.

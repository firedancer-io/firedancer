This directory contains a compress-only subset of the zlib library at
https://github.com/madler/zlib

Files are copied exactly from tag v1.3.1, with no Firedancer
specific modifications.  Do not edit vendored files locally; update
by re-running `vendor.sh` against a new pinned tag.

Only the deflate (compression) side is vendored: it exists solely
for fd_gzip_pack, which gzip-encodes GUI frontend assets at build
time (browsers decode; Firedancer never inflates gzip at runtime).
The inflate side, the gz* file API, and upstream's build system are
not imported.

For licensing information (zlib license), see LICENSE in this
directory and NOTICE in the root of this repo.

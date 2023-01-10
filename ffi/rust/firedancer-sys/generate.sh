#!/usr/bin/env sh

exec bindgen                                           \
  -o ./src/generated.rs                                \
  --blocklist-type "schar|uchar|ushort|uint|ulong"     \
  wrapper.h                                            \
  --                                                   \
  -iquote ../..

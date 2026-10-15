# VROOM: curve-agnostic AVX-512 IFMA RNS engine.  Header-and-fragment
# only -- each curve backend (bls, bn254) compiles the engine into its
# own unity translation unit with a dedicated clang IFMA rule.  These
# variables are shared by those rules (Local.mk files are all included
# into one Makefile, so definitions here are visible to the others).

FD_VROOM_CC:=clang-21
FD_VROOM_CFLAGS:=-std=c17 -O3 -g -fPIC -fno-semantic-interposition -fno-omit-frame-pointer -fwrapv -march=native -mavx512ifma \
  -DFD_HAS_AVX512=1 -DFD_HAS_INT128=1 -DFD_HAS_HOSTED=1 -DFD_HAS_X86=1 -DFD_IS_X86_64=1 \
  -Wno-unused-function -Wno-ignored-attributes -Wno-unknown-pragmas -I.
FD_VROOM_SRCS:=$(wildcard src/ballet/vroom/fd_vroom*.h src/ballet/vroom/fd_vroom*.c)

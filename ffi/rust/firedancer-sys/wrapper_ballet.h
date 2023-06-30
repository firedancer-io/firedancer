// Define all C feature flags, as we'll manage features via Rust.
#define FD_HAS_HOSTED    1
#define FD_HAS_X86       1
#define FD_HAS_ATOMIC    1
#define FD_HAS_THREADS   1
#define FD_USE_ATTR_WEAK 1
#define FD_HAS_INT128    1
#define FD_HAS_DOUBLE    1
#define FD_HAS_ALLOCA    1
#define FD_HAS_SSE       1
#define FD_HAS_AVX       1
#define FD_HAS_SHANI     1
#define FD_HAS_GFNI      1

#include "src/ballet/fd_ballet.h"
#include "src/ballet/sbpf/fd_sbpf_loader.h"
#include "src/ballet/sbpf/fd_sbpf_maps.c"
#include "src/ballet/shred/fd_shred.h"
#include "src/ballet/txn/fd_txn.h"

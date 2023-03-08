// Define all C feature flags, as we'll manage features via Rust.
#define FD_HAS_HOSTED    1
#define FD_HAS_X86       1
#define FD_HAS_ATOMIC    1
#define FD_HAS_THREADS   1
#define FD_USE_ATTR_WEAK 1

#include "firedancer/src/util/fd_util.h"
#include "firedancer/src/tango/fd_tango.h"
#include "firedancer/src/ballet/fd_ballet.h"
#include "firedancer/src/ballet/shred/fd_shred.h"
#include "firedancer/src/ballet/txn/fd_txn.h"
#include "firedancer/src/disco/fd_disco.h"

#if FD_MCACHE_LG_INTERLEAVE
#error "FD_MCACHE_LG_INTERLEAVE unsupported"
#endif

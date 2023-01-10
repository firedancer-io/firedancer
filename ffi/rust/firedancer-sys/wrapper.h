// Define all C feature flags, as we'll manage features via Rust.
#define FD_HAS_HOSTED  1
#define FD_HAS_X86     1
#define FD_HAS_ATOMIC  1
#define FD_HAS_THREADS 1

#include "../../../src/util/fd_util.h"
#include "../../../src/tango/fd_tango.h"
#include "../../../src/ballet/fd_ballet.h"
#include "../../../src/disco/fd_disco.h"

#if FD_MCACHE_LG_INTERLEAVE
#error "FD_MCACHE_LG_INTERLEAVE unsupported"
#endif

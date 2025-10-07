#ifndef HEADER_fd_src_vinyl_fd_vinyl_base_h
#define HEADER_fd_src_vinyl_fd_vinyl_base_h

/* Vinyl implements a persistent interprocess shared key-val store.
   Unlike other fd key-val stores (including groove and funk_rec),
   vinyl's key value store is backed by non-volatile storage.  Features
   include:

   - Massive batch requests processed async with zero-copy cut-through
     from the underlying I/O layer to an arbitrary number of clients.

   - Runtime plugin I/O backends to support various styles of non-volatile
     storage.  This includes kernel-bypassing the VM and/or the file
     system (e.g. direct I/O to raw block devices, I/O uring, memory
     mapped I/O, posix I/O volumes, etc).

   - Massive amounts of transparent in memory LRU data caching with fine
     grained user control of cache eviction priorities.

   - Acquire/release semantics with explicit completions for explicit
     control of pointer lifetimes.

   - Optional lockfree O(1) metadata queries.  E.g. hot-or-not query in
     sig-verify with I/O cost aware downstream packing.
     
   - Always in memory application specific metadata.  E.g. expirations,
     balances, etc are always available fast O(1).

   - Application controllable persistence guarantees (including massively
     parallel recovery / fast startup, recovery from power failures, and
     recovery to earlier known good states).

   - Support for practically unlimited number of keys.

   - Non-blocking speculative reads

   - Fast ignoring existing values (e.g. fast overwriting).

   - Extensive user and internal consistency checking

   - Transparent background meta and data integrity checking

   - Transparent background data compression (with dynamic load adaption
     and user configuration for low jitter) .

   - Live runtime statistics.

   - ...

   The most basic configuration is shown below:

   (optional)
   (read only) +------------+
     ..........| vinyl_meta |<------------+
     .         +------------+             |
     .                                    |
     .            +------+                |
     .    +------>| cnc  |<------+        |
     .    |       +------+       |        |
     v    v                      v        v                  vinyl_bstream
   ==========   +----------+   ==============  vinyl_io  +--------------------+
   = client =-->| vinyl_rq |-->= vinyl_tile = <--------> | non-volatile store |
   ==========   +----------+   ==============            +--------------------+
     ^    ^                      |        ^ 
     |    |     +----------+     |        |
     |    +-----| vinyl_cq |-----+        |
     |          +----------+              |
     |                                    | 
     |         +------------+             |
     +-------->| vinyl_data |<------------+
               +------------+ 

   - To interact with a vinyl instance, a client joins the vinyl
     command-and-control (cnc), vinyl data cache (vinyl_data) and (if
     useful to the client) vinyl metadata cache (vinyl_meta).

   - The client uses the cnc to connect to the vinyl instance and
     monitor the status of a vinyl instance.  When connecting, the
     client specifies the vinyl request queue (vinyl_rq) the client will
     use to send batch requests to the vinyl instance and the vinyl
     completion queue (vinyl_cq) the client will use to receive batch
     request completion notifications.

   - Most client-vinyl interactions have acquire/release semantics.

   - When a client wants to read, modify, etc a batch of key-val pairs,
     the client issues a batch request to acquire the keys.  The vinyl
     tile will order all incoming requests by clients for performance
     and do the necessary I/O operations asynchronously in the
     background.  When finished, the vinyl instance will notify the
     client where the values and metadata are for the keys are located
     in the vinyl data cache on completion.  This location will be
     stable until the client releases the keys.  As such, the client can
     operate on the values and metadata in-place zero-copy as
     appropriate for the type of request.

   - When the client is done operating on some or all of these keys,
     the client issues a second request to release them.  The vinyl
     instance will update the data, meta and non-volatile storage
     appropriately and notify the client when done.

   - The atomicity and ordering guarantees for requests from multiple
     are described in detail in fd_vinyl_rq.h.

   - Advanced optimizations support out-of-band completions, ignoring
     completions, and cut-through batch processing without waiting for a
     completion.  Likewise, a rq can be shared by multiple vinyl
     instanced (e.g.  sharding the store over multiple vinyl instances).
     Further, a cq can be shared by multiple clients (and not
     necessarily the same clients issuing requests) to support advanced
     thread modelings (e.g. read pipelining).

   - ... */

#include "../tango/fd_tango.h" /* For util and tango/cnc functionality */

/* fd_vinyl error code API ********************************************/

/* These mirror fd_map error codes exactly */

#include "../util/tmpl/fd_map.h"

#define FD_VINYL_SUCCESS     FD_MAP_SUCCESS
#define FD_VINYL_ERR_INVAL   FD_MAP_ERR_INVAL
#define FD_VINYL_ERR_AGAIN   FD_MAP_ERR_AGAIN
#define FD_VINYL_ERR_CORRUPT FD_MAP_ERR_CORRUPT
#define FD_VINYL_ERR_EMPTY   FD_MAP_ERR_EMPTY
#define FD_VINYL_ERR_FULL    FD_MAP_ERR_FULL
#define FD_VINYL_ERR_KEY     FD_MAP_ERR_KEY

FD_PROTOTYPES_BEGIN

/* fd_vinyl_strerror converts an FD_VINYL_SUCCESS / FD_VINYL_ERR_* code
   into a human readable cstr.  The lifetime of the returned pointer is
   infinite.  The returned pointer is always to a non-NULL cstr. */

FD_FN_CONST char const *
fd_vinyl_strerror( int err );

FD_PROTOTYPES_END

/* fd_vinyl_key_t API *************************************************/

/* A fd_vinyl_key_t specifies the key type for vinyl key-val pair.
   Compact binary keys are encouraged but a cstr can be used so long as
   it has strlen(cstr)<FD_VINYL_KEY_FOOTPRINT and the characters c[i]
   for i in [strlen(cstr),FD_VINYL_KEY_FOOTPRINT) are zero.  (Also, if
   encoding a cstr in a key, recommend using first byte to encode the
   strlen for accelerating cstr operations further but this is up to the
   user.) */

#define FD_VINYL_KEY_ALIGN     (8UL)
#define FD_VINYL_KEY_FOOTPRINT (40UL)

union __attribute__((aligned(FD_VINYL_KEY_ALIGN))) fd_vinyl_key {
  char  c [ FD_VINYL_KEY_FOOTPRINT ];
  uchar uc[ FD_VINYL_KEY_FOOTPRINT ];
  ulong ul[ FD_VINYL_KEY_FOOTPRINT / sizeof(ulong) ];
};

typedef union fd_vinyl_key fd_vinyl_key_t;

FD_PROTOTYPES_BEGIN

/* fd_vinyl_key_init populates the fd_vinyl_key_t compatible memory
   region mem with the src_sz bytes pointed to by src.  If src_sz is
   {less than,greater than} FD_VINYL_KEY_FOOTPRINT, it will be {zero
   padded,truncated} to FD_VINYL_KEY_FOOTPRINT bytes.  Assumes mem and
   src point to stable valid non-overlapping regions in the caller's
   address space for the duration of the call.  Retains no interest in
   mem or src.  Returns mem as a fd_vinyl_key_t. */

static inline fd_vinyl_key_t *
fd_vinyl_key_init( void *       FD_RESTRICT mem,
                   void const * FD_RESTRICT src,
                   ulong                    src_sz ) {
  fd_vinyl_key_t * k = (fd_vinyl_key_t *)mem;
  void * FD_RESTRICT dst = k->c;
  ulong csz = fd_ulong_min( src_sz, FD_VINYL_KEY_FOOTPRINT ); /* typically compile time */
  ulong zsz = FD_VINYL_KEY_FOOTPRINT - csz;                   /* " */
  if( zsz ) memset( dst, 0,   FD_VINYL_KEY_FOOTPRINT );       /* " */
  if( csz ) memcpy( dst, src, csz                    );       /* " */
  return k;
}

/* fd_vinyl_key_ulong populates the fd_vinyl_key_t compatible memory
   region mem with the given ulongs.  Assumes mem points to a stable
   valid region in the caller's address space for the duration of the
   call.  Retains no interest in mem.  Returns mem as a fd_vinyl_key_t. */

static inline fd_vinyl_key_t *
fd_vinyl_key_init_ulong( void * mem,
                         ulong  k0,
                         ulong  k1,
                         ulong  k2,
                         ulong  k3,
                         ulong  k4 ) {
  fd_vinyl_key_t * k = (fd_vinyl_key_t *)mem;
  k->ul[0] = k0; k->ul[1] = k1; k->ul[2] = k2; k->ul[3] = k3; k->ul[4] = k4;
  return k;
}

/* fd_vinyl_key_eq tests keys ka and kb for equality.  Assumes ka and
   kb point in the caller's address space to stable valid keys for the
   duration of the call.  Retains no interest in ka or kb.  Returns 1 if
   the keys are equal and 0 otherwise. */

FD_FN_PURE static inline int
fd_vinyl_key_eq( fd_vinyl_key_t const * ka,
                 fd_vinyl_key_t const * kb ) {
  ulong const * a = ka->ul;
  ulong const * b = kb->ul;
  return !((a[0]^b[0]) | (a[1]^b[1]) | (a[2]^b[2]) | (a[3]^b[3]) | (a[4]^b[4])); /* tons of ILP and vectorizable */
}

/* fd_vinyl_key_memo hashes the arbitrary 64-bit integer seed and the
   key pointed to by k to a uniform quasi-random 64-bit integer.  This
   hash function is meant to be high quality but not necessarily
   cryptographically secure.  Assumes k points in the caller's address
   space to a valid key for the duration of the call.  Retains no
   interest in k.  Returns the hash (arbitrary). */

FD_FN_PURE static inline ulong
fd_vinyl_key_memo( ulong                  seed,
                   fd_vinyl_key_t const * k ) {
  ulong const * a = k->ul;
  return fd_ulong_hash( a[0] ^   seed                         ) ^ fd_ulong_hash( a[1] ^ ( seed ^ 0x5555555555555555UL) ) ^
         fd_ulong_hash( a[2] ^ ( seed ^ 0xaaaaaaaaaaaaaaaaUL) ) ^ fd_ulong_hash( a[3] ^ ( seed ^ 0x5a5a5a5a5a5a5a5aUL) ) ^
         fd_ulong_hash( a[4] ^ (~seed)                        ); /* tons of ILP and vectorizable */
}

FD_PROTOTYPES_END

/* fd_vinyl_info_t ABI ************************************************/

/* A fd_vinyl_info_t gives the pair decoded value size and any
   application specific info (e.g. ctime, mtime, balance, expire, etc).
   This structure is directly used in the bstream, vinyl meta cache, and
   vinyl val data cache to reduce data marshalling, memory copies,
   random access, etc between clients, tiles, caches and I/O layers and
   to allow extra integrity checking.  The application can use whatever
   structure for the fd_vinyl_info_t so long as it is 8 byte aligned,
   FD_VINYL_INFO_SZ in size and the first 4 bytes are the decoded pair
   val size as a uint, in [0,FD_VINYL_VAL_MAX]. */

#define FD_VINYL_INFO_SZ (16UL)

union fd_vinyl_info {
  uint  _val_sz;
  uchar uc[ FD_VINYL_INFO_SZ                 ];
  uint  ui[ FD_VINYL_INFO_SZ / sizeof(uint ) ];
  ulong ul[ FD_VINYL_INFO_SZ / sizeof(ulong) ];
};

typedef union fd_vinyl_info fd_vinyl_info_t;

/* FD_VINYL_VAL_MAX is the maximum decoded byte size of a pair val.  The
   value below is:

     10MiB + block_sz - sizeof(ctl) - sizeof(key) - sizeof(info) - sizeof(ftr)
               512           8            40            16             16

   where the adjustment make it possible create a vinyl_data sizeclass
   whose val_max is exactly FD_VINYL_VAL_MAX. */

#define FD_VINYL_VAL_MAX (10486192UL)

#endif /* HEADER_fd_src_vinyl_fd_vinyl_base_h */

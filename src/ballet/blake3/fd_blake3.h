#ifndef HEADER_fd_src_ballet_blake3_fd_blake3_h
#define HEADER_fd_src_ballet_blake3_fd_blake3_h

#include "../fd_ballet_base.h"

/* fd_blake3 provides APIs for BLAKE3 hashing of messages.

   The BLAKE3 specification is available here:
   https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf

   ### High-level overview

   fd_blake3 provides the "hash" mode of BLAKE3 with variable size
   output.  Keyed hashing and key derivation are not supported.  For
   hashes with more than 1024 bytes of input data, uses SIMD parallelism
   depending on hardware capabilities.  For smaller message sizes, use
   the batch API to process multiple independent inputs in parallel.

   ### Usage (simple)

     fd_blake3_t hasher[1];
     fd_blake3_init( hasher );
     fd_blake3_append( hasher, data, sz );
     uchar hash[ 32 ];
     fd_blake3_fini( hasher, hash );

   ### Usage (batched)

     ... TODO ...

   ### Hash Construction

   The "core" of BLAKE3 is an add-rotate-xor compression function with
   a 512-bit state size.  This state is created from the following
   896-bit input:

   - 256-bit chaining value (optionally used to create a hash chain)
   - 512-bit input data
   -  64-bit counter
   -  32-bit input data size
   -  32-bit flags

   The BLAKE3 hash is constructed purely by repeated invocation of the
   compression function while mixing in input data and metadata.

   At a high-level, there exist two phases: Compress, and expand.
   The data dependencies of the compression phase form a hash tree,
   ending in a 896-bit root input.  In the expand phase, the compression
   function is repeatedly applied on the root input with increasing
   counter values (each call producing 512-bit of final output data).

   The compress phase is further divided into the chunk phase and the
   tree phase.  In the chunk phase, each 8192-bit input is hashed to
   a 256-bit output via serial calls to the compression function.
   (Note that each chunk can be computed independently)

   In the tree phase, the chunks are joined pairwise into a hash tree.

   Figure 1 illustrates a BLAKE3 hash tree with a 2170 byte input
   (34 chunks in{X}), one branch nodes (b{Y}), the root state (RS), and
   a 192 byte hash output (h{Z}). */

     /*** Figure 1: BLAKE3 Hash Tree ******************************
     *                                                            *
     *          ┌────┐    ┌────┐    ┌────┐     ─┐                 *
     *          │ h0 │    │ h1 │    │ h2 │      │                 *
     *          └──▲─┘    └─▲──┘    └─▲──┘      ├─ Expand         *
     *             │        │         │         │                 *
     *             └───────┐│┌────────┘        ─┘                 *
     *                     │││                                    *
     *                    ┌┴┴┴─┐               ─┐                 *
     *            ┌──────►│ RS ├───────┐        │                 *
     *            │       └────┘       │        │                 *
     *            │                    │        ├─ Compress Tree  *
     *          ┌─┴──┐                 │        │                 *
     *      ┌──►│ b0 │◄──┐             │        │                 *
     *      │   └────┘   │             │       ─┘                 *
     *      │            │             │                          *
     *   ┌──┴───┐     ┌──┴───┐      ┌──┴───┐   ─┐                 *
     *   │ in15 │     │ in31 │      │ in33 │    │                 *
     *   └──▲───┘     └──▲───┘      └──▲───┘    │                 *
     *      │            │             │        │                 *
     *     ...          ...         ┌──┴───┐    │                 *
     *      ▲            ▲          │ in32 │    │                 *
     *      │            │          └──────┘    ├─ Compress Chunk *
     *   ┌──┴───┐     ┌──┴───┐                  │                 *
     *   │ in1  │     │ in17 │                  │                 *
     *   └──▲───┘     └──▲───┘                  │                 *
     *      │            │                      │                 *
     *   ┌──┴───┐     ┌──┴───┐                  │                 *
     *   │ in0  │     │ in16 │                  │                 *
     *   └──────┘     └──────┘                 ─┘                 *
     *                                                            *
     **************************************************************/

/* ### Implementation

   fd_blake3 consists of three major parts:

     (1) Hash state machines, which track the progress of hash
         calculations and prepare operations to advance them;
     (2) Schedulers, which accumulate batches of operations from state
         machines, then send them to hash backends;
     (3) Hash backends (SSE, AVX2, AVX512) which work off a static size
         vector of independent hash operations.

   The goal is to maximize throughput.  The fastest backend usually is
   the widest, creating a scheduling problem.  The scheduler should be
   able to flexibly schedule operations in parallel without taking up
   valuable time that could be used for hashing.

   The simplest opportunity to parallelize is during chunk compression.
   The bulk of the work is done in the chunk phase, independently for
   each 1024 bytes of input data.  This is effective for inputs of size
   (width*FD_CHUNK_SZ), i.e. >=8192 bytes of input for AVX2.

   To accelerate processing of smaller inputs, a batch API is offered.
   Batching allows the scheduler to process operations over multiple
   independent messages at once. This has a significantly higher
   scheduling overhead though.

   It is worth noting that compression operations require a variable
   amount of compression function calls.  (Recall that each call
   processes 64 bytes of input data, but a chunk can have up to 1024
   bytes of data)  fd_blake3 therefore has an internal clock that ticks
   each time a hash backend processes a vector of blocks.  When a state
   machine schedules an op with a 1024 byte input, it knows that the op
   completes 16 ticks into the future. */


/* Protocol constants *************************************************/

/* FD_BLAKE3_BLOCK_SZ is the byte size of the inputs to the internal
   compression function.  This is a protocol constant. */

#define FD_BLAKE3_BLOCK_LG_SZ (6)
#define FD_BLAKE3_BLOCK_SZ    (64UL)

/* FD_BLAKE3_OUTCHAIN_SZ is the byte size of an "output chaining
   value".  This is a protocol constant. */

#define FD_BLAKE3_OUTCHAIN_LG_SZ (5)
#define FD_BLAKE3_OUTCHAIN_SZ    (32UL)

/* FD_BLAKE3_CHUNK_SZ is the max number of input bytes of a leaf node.
   This is a protocol constant.
   (1<<FD_BLAKE3_CHUNK_LG_SZ)==FD_BLAKE3_CHUNK_SZ */

#define FD_BLAKE3_CHUNK_LG_SZ (10)
#define FD_BLAKE3_CHUNK_SZ    (1024UL)

/* FD_BLAKE3_KEY_SZ is the byte size of the optional key in expanded
   form.  This is a protocol constant. */

#define FD_BLAKE3_KEY_SZ (32UL)

/* Implementation constants *******************************************/

/* FD_BLAKE3_ROW_CNT is the max supported tree height of fd_blake3. */

#define FD_BLAKE3_ROW_CNT (32UL)

/* FD_BLAKE3_INPUT_MAX_SZ is the max supported message size of
   fd_blake3, derived by FD_BLAKE3_ROW_CNT.  (About 4.40 terabytes) */

#define FD_BLAKE3_INPUT_MAX_SZ ((1UL<<FD_BLAKE3_ROW_CNT)<<FD_BLAKE3_CHUNK_LG_SZ)

/* FD_BLAKE3_COL_CNT is the max number of adjacent tree nodes to be
   buffered per hash state.  Used for parallel processing.
   (1<<FD_BLAKE3_COL_LG_CNT) == FD_BLAKE3_COL_CNT */

#define FD_BLAKE3_COL_LG_CNT ( 4UL)
#define FD_BLAKE3_COL_CNT    (16UL)

/* FD_BLAKE3_{ALIGN,FOOTPRINT} describe the alignment and footprint needed
   for a memory region to hold a fd_blake3_t.  ALIGN is a positive
   integer power of 2.  FOOTPRINT is a multiple of align.  ALIGN is
   recommended to be at least double cache line to mitigate various
   kinds of false sharing.  These are provided to facilitate compile
   time declarations. */

#define FD_BLAKE3_ALIGN (128UL)

/* A fd_blake3_t should be treated as an opaque handle of a blake3
   calculation state.  (It technically isn't here facilitate compile
   time declarations of fd_blake3_t memory.) */

#define FD_BLAKE3_MAGIC (0xF17EDA2CEB1A4E30) /* FIREDANCE BLAKE3 V0 */

/* Hash state machine *************************************************/

/* fd_blake3_pos_t is a hash state machine.  The user should consider
   this struct implementation-defined.  It prepares inputs to all
   compression function calls.  It also tracks dependencies between
   those calls.  For every fd_blake3_pos_t, there is a fd_blake3_buf_t.
   Depending on input size, it may be able to prepare multiple ops that
   can be worked on in parallel. */

struct __attribute__((aligned(FD_BLAKE3_ALIGN))) fd_blake3_pos {

  /* The tail and head arrays track the hash progress of each tree
     layer.  head.uc[n] is the number of nodes buffered for that layer.
     tail.uc[n] is the number of nodes already hashed into the next
     layer.  The 32-byte "output chaining value" for that node is stored
     in fd_blake3_buf_t.   */

  /* This point is 128-byte aligned */

# if FD_HAS_AVX
  union { uchar uc[ 32 ]; wb_t wb; } tail;
  union { uchar uc[ 32 ]; wb_t wb; } head;
# else
  union { uchar uc[ 32 ]; } tail;
  union { uchar uc[ 32 ]; } head;
# endif

  /* leaf_idx is the number of leaf chunks processed so far.  All but
     the last leaf chunk are of size FD_CHUNK_SZs.  live_cnt is the
     number of nodes for which an output chaining value is buffered and
     awaiting further processing.  next_tick keeps track of relative
     time to inform scheduling when a batch of operations will complete.
     layer is the tree layer that the scheduler will work on next. */

  /* This point is 64-byte aligned */

  ulong leaf_idx;
  ulong live_cnt;
  ulong next_tick;
  uint  layer;
  uchar _pad[4];

  /* [input,input+input_sz) is the user-provided memory region
     containing the hash input.  May be unaligned.  */

  /* This point is 32-byte aligned */

  uchar const * input;
  ulong         input_sz;

  /* magic==FD_BLAKE3_MAGIC (useful for debugging and detecting memory
     corruption) */

  ulong magic;

};

typedef struct fd_blake3_pos fd_blake3_pos_t;

/* fd_blake3_buf_t contains intermediate results of hash tree
   construction.  Internally, it is a table of output chaining values.
   Each row contains a contiguous window of output chaining values for
   the nodes at a specific tree layer.  Row 0 is the tree layer. */

union __attribute__((aligned(FD_BLAKE3_ALIGN))) fd_blake3_buf {

  uchar slots[ FD_BLAKE3_ROW_CNT ][ FD_BLAKE3_COL_CNT ][ FD_BLAKE3_OUTCHAIN_SZ ];
  uchar rows [ FD_BLAKE3_ROW_CNT ][ FD_BLAKE3_COL_CNT *  FD_BLAKE3_OUTCHAIN_SZ ];

};

typedef union fd_blake3_buf fd_blake3_buf_t;

/* Simple API *********************************************************/

#if FD_HAS_AVX512
#define FD_BLAKE3_BATCH_LG_MAX (4UL)
#elif FD_HAS_AVX
#define FD_BLAKE3_BATCH_LG_MAX (3UL)
#elif FD_HAS_SSE
#define FD_BLAKE3_BATCH_LG_MAX (2UL)
#else
#define FD_BLAKE3_BATCH_LG_MAX (0UL)
#endif
#define FD_BLAKE3_BATCH_MAX (1<<FD_BLAKE3_BATCH_LG_MAX)

#define FD_BLAKE3_PRIVATE_LG_BUF_MAX (FD_BLAKE3_BATCH_LG_MAX+FD_BLAKE3_CHUNK_LG_SZ)
#define FD_BLAKE3_PRIVATE_BUF_MAX    (1UL<<FD_BLAKE3_PRIVATE_LG_BUF_MAX)

struct fd_blake3 {
  fd_blake3_buf_t buf;
  uchar           block[ FD_BLAKE3_PRIVATE_BUF_MAX ];
  fd_blake3_pos_t pos;
  ulong           block_sz;
};

typedef struct fd_blake3 fd_blake3_t;

#define FD_BLAKE3_FOOTPRINT (sizeof(fd_blake3_t))

FD_PROTOTYPES_BEGIN

/* fd_blake3_{align,footprint,new,join,leave,delete} usage is identical to
   that of their fd_sha512 counterparts.  See ../sha512/fd_sha512.h */

FD_FN_CONST ulong
fd_blake3_align( void );

FD_FN_CONST ulong
fd_blake3_footprint( void );

void *
fd_blake3_new( void * shmem );

fd_blake3_t *
fd_blake3_join( void * shsha );

void *
fd_blake3_leave( fd_blake3_t * sha );

void *
fd_blake3_delete( void * shsha );

/* fd_blake3_init starts a blake3 calculation.  sha is assumed to be a
   current local join to a blake3 calculation state with no other
   concurrent operation that would modify the state while this is
   executing.  Any preexisting state for an in-progress or recently
   completed calculation will be discarded.  Returns sha (on return, sha
   will have the state of a new in-progress calculation). */

fd_blake3_t *
fd_blake3_init( fd_blake3_t * sha );

/* fd_blake3_append adds sz bytes locally pointed to by data an
   in-progress blake3 calculation.  sha, data and sz are assumed to be
   valid (i.e. sha is a current local join to a blake3 calculation state
   with no other concurrent operations that would modify the state while
   this is executing, data points to the first of the sz bytes and will
   be unmodified while this is running with no interest retained after
   return ... data==NULL is fine if sz==0).  Returns sha (on return, sha
   will have the updated state of the in-progress calculation).

   It does not matter how the user group data bytes for a blake3
   calculation; the final hash will be identical.  It is preferable for
   performance to try to append as many bytes as possible as a time
   though.  It is also preferable for performance if sz is a multiple of
   64 for all but the last append (it is also preferable if sz is less
   than 56 for the last append). */

fd_blake3_t *
fd_blake3_append( fd_blake3_t * sha,
                  void const *  data,
                  ulong         sz );

/* fd_blake3_fini finishes a a blake3 calculation.  sha and hash are
   assumed to be valid (i.e. sha is a local join to a blake3 calculation
   state that has an in-progress calculation with no other concurrent
   operations that would modify the state while this is executing and
   hash points to the first byte of a 32-byte memory region where the
   result of the calculation should be stored).  Returns hash (on
   return, there will be no calculation in-progress on sha and 32-byte
   buffer pointed to by hash will be populated with the calculation
   result). */

void *
fd_blake3_fini( fd_blake3_t * sha,
                void *        hash );

void *
fd_blake3_hash( void const * data,
                ulong        sz,
                void *       hash );

FD_PROTOTYPES_END

/* Batch API **********************************************************/

#if FD_BLAKE3_BATCH_LG_MAX > 0

#define FD_BLAKE3_BATCH_ALIGN (128UL)

struct __attribute__((aligned(FD_BLAKE3_BATCH_ALIGN))) fd_blake3_private_batch {
  fd_blake3_buf_t buf [ FD_BLAKE3_BATCH_MAX ];
  fd_blake3_pos_t pos [ FD_BLAKE3_BATCH_MAX ];
  void *          hash[ FD_BLAKE3_BATCH_MAX ];
  ulong           tick;
  uint            mask;
};

typedef struct fd_blake3_private_batch fd_blake3_batch_t;

#define FD_BLAKE3_BATCH_FOOTPRINT (sizeof(fd_blake3_batch_t))

FD_PROTOTYPES_BEGIN

static inline fd_blake3_batch_t *
fd_blake3_batch_init( void * mem ) {
  fd_blake3_batch_t * batch = (fd_blake3_batch_t *)mem;
  batch->mask = 0U;
  batch->tick = 0UL;
  return batch;
}

fd_blake3_batch_t *
fd_blake3_batch_add( fd_blake3_batch_t * batch,
                     void const *        data,
                     ulong               sz,
                     void *              hash );

void *
fd_blake3_batch_fini( fd_blake3_batch_t * batch );

void *
fd_blake3_batch_abort( fd_blake3_batch_t * batch );

FD_PROTOTYPES_END

#else /* No batch backend */

#define FD_BLAKE3_BATCH_ALIGN     (alignof(uint))
#define FD_BLAKE3_BATCH_FOOTPRINT (sizeof (uint))

typedef uint fd_blake3_batch_t;

FD_PROTOTYPES_BEGIN

static inline fd_blake3_batch_t *
fd_blake3_batch_init( void * mem ) {
  return (fd_blake3_batch_t *)mem;
}

static inline fd_blake3_batch_t *
fd_blake3_batch_add( fd_blake3_batch_t * batch,
                     void const *        data,
                     ulong               sz,
                     void *              hash ) {
  fd_blake3_hash( data, sz, hash );
  return batch;
}

void *
fd_blake3_batch_fini( fd_blake3_batch_t * batch ) {
  return batch;
}

void *
fd_blake3_batch_abort( fd_blake3_batch_t * batch ) {
   return batch;
}

FD_PROTOTYPES_END

#endif /* has batch? */

#endif /* HEADER_fd_src_ballet_blake3_fd_blake3_h */

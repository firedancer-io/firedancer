#ifndef HEADER_fd_src_ballet_sha256_fd_sha256_h
#define HEADER_fd_src_ballet_sha256_fd_sha256_h

/* fd_sha256 provides APIs for SHA-256 hashing of messages. */

#include "../fd_ballet_base.h"

/* FD_SHA256_{ALIGN,FOOTPRINT} describe the alignment and footprint needed
   for a memory region to hold a fd_sha256_t.  ALIGN is a positive
   integer power of 2.  FOOTPRINT is a multiple of align.  ALIGN is
   recommended to be at least double cache line to mitigate various
   kinds of false sharing.  These are provided to facilitate compile
   time declarations. */

#define FD_SHA256_ALIGN     (128UL)
#define FD_SHA256_FOOTPRINT (128UL)

/* FD_SHA256_{LG_HASH_SZ,HASH_SZ} describe the size of a SHA256 hash
   in bytes.  HASH_SZ==2^LG_HASH_SZ==32. */

#define FD_SHA256_LG_HASH_SZ (5)
#define FD_SHA256_HASH_SZ    (32UL) /* == 2^FD_SHA256_LG_HASH_SZ, explicit to workaround compiler limitations */

/* FD_SHA256_{LG_BLOCK_SZ,BLOCK_SZ} describe the size of a SHA256
   hash block in byte.  BLOCK_SZ==2^LG_BLOCK_SZ==64. */

#define FD_SHA256_LG_BLOCK_SZ (6)
#define FD_SHA256_BLOCK_SZ    (64UL) /* == 2^FD_SHA256_LG_BLOCK_SZ, explicit to workaround compiler limitations */

/* A fd_sha256_t should be treated as an opaque handle of a sha256
   calculation state.  (It technically isn't here facilitate compile
   time declarations of fd_sha256_t memory.) */

#define FD_SHA256_MAGIC (0xF17EDA2CE54A2560) /* FIREDANCE SHA256 V0 */

/* FD_SHA256_PRIVATE_{LG_BUF_MAX,BUF_MAX} describe the size of the
   internal buffer used by the sha256 computation object.  This is for
   internal use only.  BUF_MAX==2^LG_BUF_MAX==2*FD_SHA256_HASH_SZ==64. */

#define FD_SHA256_PRIVATE_LG_BUF_MAX FD_SHA256_LG_BLOCK_SZ
#define FD_SHA256_PRIVATE_BUF_MAX    FD_SHA256_BLOCK_SZ

struct __attribute__((aligned(FD_SHA256_ALIGN))) fd_sha256_private {

  /* This point is 128-byte aligned */

  uchar buf[ FD_SHA256_PRIVATE_BUF_MAX ];

  /* This point is 64-byte aligned */

  uint  state[ FD_SHA256_HASH_SZ / sizeof(uint) ];

  /* This point is 32-byte aligned */

  ulong magic;    /* ==FD_SHA256_MAGIC */
  ulong buf_used; /* Number of buffered bytes, in [0,FD_SHA256_BUF_MAX) */
  ulong bit_cnt;  /* How many bits have been appended total */

  /* Padding to 128-byte here */
};

typedef struct fd_sha256_private fd_sha256_t;

FD_PROTOTYPES_BEGIN

/* fd_sha256_{align,footprint,new,join,leave,delete} usage is identical to
   that of their fd_sha512 counterparts.  See ../sha512/fd_sha512.h */

FD_FN_CONST ulong
fd_sha256_align( void );

FD_FN_CONST ulong
fd_sha256_footprint( void );

void *
fd_sha256_new( void * shmem );

fd_sha256_t *
fd_sha256_join( void * shsha );

void *
fd_sha256_leave( fd_sha256_t * sha );

void *
fd_sha256_delete( void * shsha );

/* fd_sha256_init starts a sha256 calculation.  sha is assumed to be a
   current local join to a sha256 calculation state with no other
   concurrent operation that would modify the state while this is
   executing.  Any preexisting state for an in-progress or recently
   completed calculation will be discarded.  Returns sha (on return, sha
   will have the state of a new in-progress calculation). */

fd_sha256_t *
fd_sha256_init( fd_sha256_t * sha );

/* fd_sha256_append adds sz bytes locally pointed to by data an
   in-progress sha256 calculation.  sha, data and sz are assumed to be
   valid (i.e. sha is a current local join to a sha256 calculation state
   with no other concurrent operations that would modify the state while
   this is executing, data points to the first of the sz bytes and will
   be unmodified while this is running with no interest retained after
   return ... data==NULL is fine if sz==0).  Returns sha (on return, sha
   will have the updated state of the in-progress calculation).

   It does not matter how the user group data bytes for a sha256
   calculation; the final hash will be identical.  It is preferable for
   performance to try to append as many bytes as possible as a time
   though.  It is also preferable for performance if sz is a multiple of
   64 for all but the last append (it is also preferable if sz is less
   than 56 for the last append). */

fd_sha256_t *
fd_sha256_append( fd_sha256_t * sha,
                  void const *  data,
                  ulong         sz );

/* fd_sha256_fini finishes a a sha256 calculation.  sha and hash are
   assumed to be valid (i.e. sha is a local join to a sha256 calculation
   state that has an in-progress calculation with no other concurrent
   operations that would modify the state while this is executing and
   hash points to the first byte of a 32-byte memory region where the
   result of the calculation should be stored).  Returns hash (on
   return, there will be no calculation in-progress on sha and 32-byte
   buffer pointed to by hash will be populated with the calculation
   result). */

void *
fd_sha256_fini( fd_sha256_t * sha,
                void *        hash );

/* fd_sha256_hash is a streamlined implementation of:

     fd_sha256_t sha[1];
     return fd_sha256_fini( fd_sha256_append( fd_sha256_init( sha ), data, sz ), hash )

   This can be faster for small messages because it can eliminate
   function call overheads, branches, copies and data marshalling under
   the hood (things like binary Merkle tree construction were designed
   do lots of such operations). */

void *
fd_sha256_hash( void const * data,
                ulong        sz,
                void *       hash );

FD_PROTOTYPES_END

#if 0 /* SHA256 batch API details */

/* FD_SHA256_BATCH_{ALIGN,FOOTPRINT} return the alignment and footprint
   in bytes required for a region of memory to can hold the state of an
   in-progress set of SHA-256 calculations.  ALIGN will be an integer
   power of 2 and FOOTPRINT will be a multiple of ALIGN.  These are to
   facilitate compile time declartions. */

#define FD_SHA256_BATCH_ALIGN     ...
#define FD_SHA256_BATCH_FOOTPRINT ...

/* FD_SHA256_BATCH_MAX returns the batch size used under the hood.
   Will be positive.  Users should not normally need use this for
   anything. */

#define FD_SHA256_BATCH_MAX       ...

/* A fd_sha256_batch_t is an opaque handle for a set of SHA-256
   calculations. */

struct fd_sha256_private_batch;
typedef struct fd_sha256_private_batch fd_sha256_batch_t;

/* fd_sha256_batch_{align,footprint} return
   FD_SHA256_BATCH_{ALIGN,FOOTPRINT} respectively. */

ulong fd_sha256_batch_align    ( void );
ulong fd_sha256_batch_footprint( void );

/* fd_sha256_batch_init starts a new batch of SHA-256 calculations.  The
   state of the in-progress calculation will be held in the memory
   region whose first byte in the local address space is pointed to by
   mem.  The region should have the appropriate alignment and footprint
   and should not be read, changed or deleted until fini or abort is
   called on the in-progress calculation.

   Returns a handle to the in-progress batch calculation.  As this is
   used in HPC contexts, does no input validation. */

fd_sha256_batch_t *
fd_sha256_batch_init( void * mem );

/* fd_sha256_batch_add adds the sz byte message whose first byte in the
   local address space is pointed to by data to the in-progress batch
   calculation whose handle is batch.  The result of the calculation
   will be stored at the 32-byte memory region whose first byte in the
   local address space is pointed to by hash.

   There are _no_ alignment restrictions on data and hash and _no_
   restrictions on sz.  After a message is added, that message should
   not be changed or deleted until the fini or abort is called on the
   in-progress calculation.  Likewise, the hash memory region shot not
   be read, written or deleted until the calculation has completed.

   Messages can overlap and/or be added to a batch multiple times.  Each
   hash location added to a batch should not overlap any other hash
   location of calculation state or message region.  (Hash reuse /
   overlap have indeterminiant but non-crashing behavior as the
   implementation under the hood is free to execute the elements of the
   batch in whatever order it sees fit and potentially do those
   calculations incrementally / in the background / ... as the batch is
   assembled.)

   Depending on the implementation, it might help performance to cluster
   adds of similar sized messages together.  Likewise, it can be
   advantageous to use aligned message regions, aligned hash regions and
   messages sizes that are a multiple of a SHA block size.  None of this
   is required though.

   Returns batch (which will still be an in progress batch calculation).
   As this is used in HPC contexts, does no input validation. */

fd_sha256_batch_t *
fd_sha256_batch_add( fd_sha256_batch_t * batch,
                     void const *        data,
                     ulong               sz,
                     void *              hash );

/* fd_sha256_batch_fini finishes a set of SHA-256 calculations.  On
   return, all the hash memory regions will be populated with the
   corresponding message hash.  Returns a pointer to the memory region
   used to hold the calculation state (contents undefined) and the
   calculation will no longer be in progress.  As this is used in HPC
   contexts, does no input validation. */

void *
fd_sha256_batch_fini( fd_sha256_batch_t * batch );

/* fd_sha256_batch_abort aborts an in-progress set of SHA-256
   calcuations.  There is no guarantee which individual messages (if
   any) had their hashes computed and the contents of the hash memory
   regions is undefined.  Returns a pointer to the memory region used to
   hold the calculation state (contents undefined) and the calculation
   will no longer be in progress.  As this is used in HPC contexts, does
   no input validation. */

void *
fd_sha256_batch_abort( fd_sha256_batch_t * batch );

#endif

#ifndef FD_SHA256_BATCH_IMPL
#if FD_HAS_AVX512
#define FD_SHA256_BATCH_IMPL 2
#elif FD_HAS_AVX
#define FD_SHA256_BATCH_IMPL 1
#else
#define FD_SHA256_BATCH_IMPL 0
#endif
#endif

#if FD_SHA256_BATCH_IMPL==0 /* Reference batching implementation */

#define FD_SHA256_BATCH_ALIGN     (1UL)
#define FD_SHA256_BATCH_FOOTPRINT (1UL)
#define FD_SHA256_BATCH_MAX       (1UL)

typedef uchar fd_sha256_batch_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong fd_sha256_batch_align    ( void ) { return alignof(fd_sha256_batch_t); }
FD_FN_CONST static inline ulong fd_sha256_batch_footprint( void ) { return sizeof (fd_sha256_batch_t); }

static inline fd_sha256_batch_t * fd_sha256_batch_init( void * mem ) { return (fd_sha256_batch_t *)mem; }

static inline fd_sha256_batch_t *
fd_sha256_batch_add( fd_sha256_batch_t * batch,
                     void const *        data,
                     ulong               sz,
                     void *              hash ) {
  fd_sha256_hash( data, sz, hash );
  return batch;
}

static inline void * fd_sha256_batch_fini ( fd_sha256_batch_t * batch ) { return (void *)batch; }
static inline void * fd_sha256_batch_abort( fd_sha256_batch_t * batch ) { return (void *)batch; }

FD_PROTOTYPES_END

#elif FD_SHA256_BATCH_IMPL==1 /* AVX accelerated batching implementation */

#define FD_SHA256_BATCH_ALIGN     (128UL)
#define FD_SHA256_BATCH_FOOTPRINT (256UL)
#define FD_SHA256_BATCH_MAX       (8UL)

/* This is exposed here to facilitate inlining various operations */

struct __attribute__((aligned(FD_SHA256_BATCH_ALIGN))) fd_sha256_private_batch {
  void const * data[ FD_SHA256_BATCH_MAX ]; /* AVX aligned */
  ulong        sz  [ FD_SHA256_BATCH_MAX ]; /* AVX aligned */
  void *       hash[ FD_SHA256_BATCH_MAX ]; /* AVX aligned */
  ulong        cnt;
};

typedef struct fd_sha256_private_batch fd_sha256_batch_t;

FD_PROTOTYPES_BEGIN

/* Internal use only */

void
fd_sha256_private_batch_avx( ulong          batch_cnt,    /* In [1,FD_SHA256_BATCH_MAX] */
                             void const *   batch_data,   /* Indexed [0,FD_SHA256_BATCH_MAX), aligned 32,
                                                             only [0,batch_cnt) used, essentially a msg_t const * const * */
                             ulong const *  batch_sz,     /* Indexed [0,FD_SHA256_BATCH_MAX), aligned 32,
                                                             only [0,batch_cnt) used */
                             void * const * batch_hash ); /* Indexed [0,FD_SHA256_BATCH_MAX), aligned 32,
                                                             only [0,batch_cnt) used */

FD_FN_CONST static inline ulong fd_sha256_batch_align    ( void ) { return alignof(fd_sha256_batch_t); }
FD_FN_CONST static inline ulong fd_sha256_batch_footprint( void ) { return sizeof (fd_sha256_batch_t); }

static inline fd_sha256_batch_t *
fd_sha256_batch_init( void * mem ) {
  fd_sha256_batch_t * batch = (fd_sha256_batch_t *)mem;
  batch->cnt = 0UL;
  return batch;
}

static inline fd_sha256_batch_t *
fd_sha256_batch_add( fd_sha256_batch_t * batch,
                     void const *        data,
                     ulong               sz,
                     void *              hash ) {
  ulong batch_cnt = batch->cnt;
  batch->data[ batch_cnt ] = data;
  batch->sz  [ batch_cnt ] = sz;
  batch->hash[ batch_cnt ] = hash;
  batch_cnt++;
  if( FD_UNLIKELY( batch_cnt==FD_SHA256_BATCH_MAX ) ) {
    fd_sha256_private_batch_avx( batch_cnt, batch->data, batch->sz, batch->hash );
    batch_cnt = 0UL;
  }
  batch->cnt = batch_cnt;
  return batch;
}

static inline void *
fd_sha256_batch_fini( fd_sha256_batch_t * batch ) {
  ulong batch_cnt = batch->cnt;
  if( FD_LIKELY( batch_cnt ) ) fd_sha256_private_batch_avx( batch_cnt, batch->data, batch->sz, batch->hash );
  return (void *)batch;
}

static inline void *
fd_sha256_batch_abort( fd_sha256_batch_t * batch ) {
  return (void *)batch;
}

FD_PROTOTYPES_END

#elif FD_SHA256_BATCH_IMPL==2 /* AVX-512 accelerated batching implementation */

#define FD_SHA256_BATCH_ALIGN     (128UL)
#define FD_SHA256_BATCH_FOOTPRINT (512UL)
#define FD_SHA256_BATCH_MAX       (16UL)

/* This is exposed here to facilitate inlining various operations */

struct __attribute__((aligned(FD_SHA256_BATCH_ALIGN))) fd_sha256_private_batch {
  void const * data[ FD_SHA256_BATCH_MAX ]; /* AVX aligned */
  ulong        sz  [ FD_SHA256_BATCH_MAX ]; /* AVX aligned */
  void *       hash[ FD_SHA256_BATCH_MAX ]; /* AVX aligned */
  ulong        cnt;
};

typedef struct fd_sha256_private_batch fd_sha256_batch_t;

FD_PROTOTYPES_BEGIN

/* Internal use only */

void
fd_sha256_private_batch_avx512( ulong          batch_cnt,    /* In [1,FD_SHA256_BATCH_MAX] */
                                void const *   batch_data,   /* Indexed [0,FD_SHA256_BATCH_MAX), aligned 32,
                                                                only [0,batch_cnt) used, essentially a msg_t const * const * */
                                ulong const *  batch_sz,     /* Indexed [0,FD_SHA256_BATCH_MAX), aligned 32,
                                                                only [0,batch_cnt) used */
                                void * const * batch_hash ); /* Indexed [0,FD_SHA256_BATCH_MAX), aligned 32,
                                                                only [0,batch_cnt) used */

FD_FN_CONST static inline ulong fd_sha256_batch_align    ( void ) { return alignof(fd_sha256_batch_t); }
FD_FN_CONST static inline ulong fd_sha256_batch_footprint( void ) { return sizeof (fd_sha256_batch_t); }

static inline fd_sha256_batch_t *
fd_sha256_batch_init( void * mem ) {
  fd_sha256_batch_t * batch = (fd_sha256_batch_t *)mem;
  batch->cnt = 0UL;
  return batch;
}

static inline fd_sha256_batch_t *
fd_sha256_batch_add( fd_sha256_batch_t * batch,
                     void const *        data,
                     ulong               sz,
                     void *              hash ) {
  ulong batch_cnt = batch->cnt;
  batch->data[ batch_cnt ] = data;
  batch->sz  [ batch_cnt ] = sz;
  batch->hash[ batch_cnt ] = hash;
  batch_cnt++;
  if( FD_UNLIKELY( batch_cnt==FD_SHA256_BATCH_MAX ) ) {
    fd_sha256_private_batch_avx512( batch_cnt, batch->data, batch->sz, batch->hash );
    batch_cnt = 0UL;
  }
  batch->cnt = batch_cnt;
  return batch;
}

static inline void *
fd_sha256_batch_fini( fd_sha256_batch_t * batch ) {
  ulong batch_cnt = batch->cnt;
  if( FD_LIKELY( batch_cnt ) ) fd_sha256_private_batch_avx512( batch_cnt, batch->data, batch->sz, batch->hash );
  return (void *)batch;
}

static inline void *
fd_sha256_batch_abort( fd_sha256_batch_t * batch ) {
  return (void *)batch;
}

FD_PROTOTYPES_END

#else
#error "Unsupported FD_SHA256_BATCH_IMPL"
#endif

#endif /* HEADER_fd_src_ballet_sha256_fd_sha256_h */

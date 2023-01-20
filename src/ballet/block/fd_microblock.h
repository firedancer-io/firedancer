#ifndef HEADER_fd_src_ballet_block_fd_block_h
#define HEADER_fd_src_ballet_block_fd_block_h

/* Blocks are the logical representation of Solana block data.

   They consist of 64 entries, each containing a vector of txs. */

#include "../fd_ballet_base.h"
#include "../sha256/fd_sha256.h"
#include "../txn/fd_txn.h"

#define FD_MICROBLOCK_ALIGN (64UL)

#define FD_MICROBLOCK_MAGIC (0x176aa423e0372d6aUL) /* random */

struct __attribute__((packed)) fd_microblock_hdr {
  /* Number of PoH hashes between this and last microblock */
  ulong hash_cnt;

  /* PoH state of last microblock */
  uchar hash[ FD_SHA256_HASH_SZ ];

  /* Number of transactions in this microblock */
  ulong txn_cnt;
};
typedef struct fd_microblock_hdr fd_microblock_hdr_t;

FD_STATIC_ASSERT( sizeof(fd_microblock_hdr_t)==48UL, alignment );

/* `fd_txn_o` (read `fd_txn` owned) is a buffer that fits any `fd_txn_t`. */
struct fd_txn_o {
  /* Buffer containing `fd_txn_t`. */
  uchar txn_desc_raw[ FD_TXN_MAX_SZ ];
};
typedef struct fd_txn_o fd_txn_o_t;

/* `fd_rawtxn_b` references a serialized txn backing an `fd_txn_t`. */
struct fd_rawtxn_b {
  /* Pointer to txn in local wksp */
  void * raw; /* TODO: Make this a gaddr instead of laddr */

  /* Size of txn */
  ushort txn_sz;
};
typedef struct fd_rawtxn_b fd_rawtxn_b_t;

/* fd_microblock: Buffer storing a deserialized microblock. */
struct __attribute__((aligned(FD_MICROBLOCK_ALIGN))) fd_microblock {
  /* This point is 64-byte aligned */

  ulong magic;       /* ==FD_MICROBLOCK_MAGIC */
  ulong txn_max_cnt; /* Max element cnt in `raw_tbl` and `txn_tbl` */

  /* TODO: Add synchronization metadata (write lock) */

  /* Points to "raw txns" VLA within this struct. */
  fd_rawtxn_b_t * raw_tbl;

  /* Points to "txn descriptors" VLA within this struct. */
  fd_txn_o_t *    txn_tbl;

  /* This point is 64-byte aligned */

  /* Fixed size header */
  fd_microblock_hdr_t hdr;

  /* This point is 16-byte aligned */

  /* Serialized transactions */
  uchar txn_data[];
};
typedef struct fd_microblock fd_microblock_t;

FD_PROTOTYPES_BEGIN

/* fd_microblock_{align,footprint} return the required alignment and
   footprint of a memory region suitable for storing an `fd_microblock_t`.
   `fd_microblock_align` returns `fd_microblock_ALIGN`.
   `fd_microblock_footprint` returns the memory footprint of a `fd_microblock_t`
   that can store a given number of maximally-sized txns. */

FD_FN_CONST ulong
fd_microblock_align( void );

FD_FN_CONST ulong
fd_microblock_footprint( ulong txn_max_cnt );

/* fd_microblock_new formats an unused memory region for storing an
   `fd_microblock_t`. `shmem` is a non-NULL pointer to this region in the
   local address space with the required footprint and alignment.
   `txn_max_cnt` is the number of txn descriptors that can be stored
   in the `fd_microblock_t`.  The `fd_microblock_hdr_t` is initialized to zero.
   Returns `shmem` on success and NULL on failure (logs details).
   Reasons for failure include an obviously bad `shmem` (alignment)
   or bad `txn_max_cnt`. */

void *
fd_microblock_new( void * shmem,
              ulong  txn_max_cnt );

/* `fd_microblock_join` joins the caller to the microblock.
   `shblock` points to the first byte of the memory region backing the
   `fd_microblock_t` in the caller's address space.
   Returns `shblock` on success and NULL on failure (logs details).
   Reasons for failure include those of `fd_microblock_new` or that the
   memory region was not correctly initialized.
   Every successful join should have a matching leave. The lifetime of
   the join is until the matching leave or thread group is terminated. */

fd_microblock_t *
fd_microblock_join( void * shblock );

/* `fd_microblock_leave` leaves a current local join.  Returns a pointer to
   the underlying shared memory region on success.  Reasons for failure
   include `block` is NULL. */

void *
fd_microblock_leave( fd_microblock_t * block );

/* `fd_microblock_delete` unformats a memory region storing an `fd_microblock_t`.
   Assumes nobody is joined to the region.  Returns a pointer to the
   underlying shared memory region or NULL if used obviously in error
   (e.g. `shblock` is obviously not an `fd_microblock_t` ... logs details).
   The ownership of the memory region is transferred to the caller. */

void *
fd_microblock_delete( void * shblock );

/* fd_microblock_deserialize: Deserializes an microblock from `buf`.
   Only accesses up to `buf_sz` bytes beyond `buf`.
   Returns a pointer to the next microblock.  Or on failure, returns NULL.
   Reasons for failure include invalid data or unexpected EOF.
   If the returned ptr is non-NULL, it is guaranteed to be
     1) greater than the provided `buf` ptr
     2) less or equal than `(uchar *)buf + buf_sz` */
void *
fd_microblock_deserialize( fd_microblock_t * block,
                           void *            buf,
                           ulong             buf_sz,
                           fd_txn_parse_counters_t * counters_opt );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_block_fd_block_h */

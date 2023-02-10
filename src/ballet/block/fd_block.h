#ifndef HEADER_fd_src_ballet_block_fd_block_h
#define HEADER_fd_src_ballet_block_fd_block_h

/* Blocks are the logical representation of Solana block data.

   They consist of 64 entries, each containing a vector of txs. */

#include "../fd_ballet_base.h"
#include "../sha256/fd_sha256.h"

#include "../txn/fd_txn.h"

#define FD_ENTRY_ALIGN (64UL)

#define FD_ENTRY_MAGIC (0x176aa423e0372d6aUL) /* random */

/* fd_entry induces a PoH tick and contains a set of transactions.

   ### PoH Ticks

   Because each slot has 64 ticks, each block has 64 entries.

   The PoH tick is executed by first appending `hash_cnt-1` hashes to
   the PoH state, and then mixing in the `entry hash`.

   ### Entry Hash

   The entry hash is the 32-byte root of the binary Merkle tree given
   the first signature of each transaction as an input. */

/* fd_entry_hdr: Fixed size header preceding entry payload. */
struct __attribute__((packed)) fd_entry_hdr {
  /* Number of PoH hashes between this entry and last entry */
  /* 0x00 */ ulong hash_cnt;

  /* PoH state of last entry */
  /* 0x08 */ uchar hash[ FD_SHA256_HASH_SZ ];

  /* Number of transactions in this entry */
  /* 0x28 */ ulong txn_cnt;
};
typedef struct fd_entry_hdr fd_entry_hdr_t;

FD_STATIC_ASSERT( sizeof(fd_entry_hdr_t)==48UL, alignment );

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

/* fd_entry: Buffer storing a deserialized entry. */
struct __attribute__((aligned(FD_ENTRY_ALIGN))) fd_entry {
  /* This point is 64-byte aligned */

  ulong magic;       /* ==FD_ENTRY_MAGIC */
  ulong txn_max_cnt; /* Max element cnt in `raw_tbl` and `txn_tbl` */

  /* TODO: Add synchronization metadata (write lock) */

  /* Points to "raw txns" VLA within this struct. */
  fd_rawtxn_b_t * raw_tbl;

  /* Points to "txn descriptors" VLA within this struct. */
  fd_txn_o_t *    txn_tbl;

  /* This point is 64-byte aligned */

  /* Fixed size header */
  fd_entry_hdr_t  hdr;

  /* This point is 16-byte aligned */

  /* Variable-length `fd_entry_txn_tbl_t` follows here */
};
typedef struct fd_entry fd_entry_t;

FD_PROTOTYPES_BEGIN

/* fd_entry_{align,footprint} return the required alignment and
   footprint of a memory region suitable for storing an `fd_entry_t`.

   `fd_entry_align` returns `FD_ENTRY_ALIGN`.
   `fd_entry_footprint` returns the memory footprint of a `fd_entry_t`
   that can store a given number of maximally-sized txns. */

FD_FN_CONST ulong
fd_entry_align( void );

FD_FN_CONST ulong
fd_entry_footprint( ulong txn_max_cnt );

/* fd_entry_new formats an unused memory region for storing an
   `fd_entry_t`. `shmem` is a non-NULL pointer to this region in the
   local address space with the required footprint and alignment.
   `txn_max_cnt` is the number of txn descriptors that can be stored
   in the `fd_entry_t`.  The `fd_entry_hdr_t` is initialized to zero.

   Returns `shmem` on success and NULL on failure (logs details).
   Reasons for failure include an obviously bad `shmem` (alignment)
   or bad `txn_max_cnt`. */

void *
fd_entry_new( void * shmem,
              ulong  txn_max_cnt );

/* `fd_entry_join` joins the caller to the entry.
   `shentry` points to the first byte of the memory region backing the
   `fd_entry_t` in the caller's address space.

   Returns `shentry` on success and NULL on failure (logs details).
   Reasons for failure include those of `fd_entry_new` or that the
   memory region was not correctly initialized.

   Every successful join should have a matching leave. The lifetime of
   the join is until the matching leave or thread group is terminated. */

fd_entry_t *
fd_entry_join( void * shentry );

/* `fd_entry_leave` leaves a current local join.  Returns a pointer to
   the underlying shared memory region on success.  Reasons for failure
   include `entry` is NULL. */

void *
fd_entry_leave( fd_entry_t * entry );

/* `fd_entry_delete` unformats a memory region storing an `fd_entry_t`.
   Assumes nobody is joined to the region.  Returns a pointer to the
   underlying shared memory region or NULL if used obviously in error
   (e.g. `shentry` is obviously not an `fd_entry_t` ... logs details).
   The ownership of the memory region is transferred to the caller. */

void *
fd_entry_delete( void * shentry );

/* fd_entry_deserialize: Deserializes an entry from `buf`.
   Only accesses up to `buf_sz` bytes beyond `buf`.

   Returns a pointer to the next entry.  Or on failure, returns NULL.
   Reasons for failure include invalid data or unexpected EOF.

   If the returned ptr is non-NULL, it is guaranteed to be
     1) greater than the provided `buf` ptr
     2) less or equal than `(uchar *)buf + buf_sz` */
void *
fd_entry_deserialize( fd_entry_t * entry,
                      void **      buf,
                      ulong *      buf_sz,
                      fd_txn_parse_counters_t * counters_opt );

/* fd_entry_mixin: Calculates the PoH mixin hash.

   Computes the root of a 32-byte binary Merkle tree of a vector with
   each element containing the first Ed25519 signature of each txn.

   U.B. if this entry contains a txn with zero signatures (illegal txn).
   U.B. if this entry's `hdr.txn_cnt` is zero. */
void
fd_entry_mixin( fd_entry_t const * entry,
                uchar *            out_hash );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_block_fd_block_h */

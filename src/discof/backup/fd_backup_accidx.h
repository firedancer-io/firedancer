#ifndef HEADER_fd_src_discof_backup_fd_backup_accidx_h
#define HEADER_fd_src_discof_backup_fd_backup_accidx_h

/* fd_backup_accidx.h provides a read-only view of the accdb in-memory
   account index for snapshot production.

   The index is a chained hash map keyed by account address.  acc_map is
   an array of (chain_mask+1) chain heads, each an index into acc_pool
   or UINT_MAX for "end of chain". */

#include "../../flamenco/accdb/fd_accdb_private.h"
#include "../../util/fd_hash32.h"

struct fd_backup_accidx {
  uint const *               acc_map;      /* map chains */
  fd_accdb_accmeta_t const * acc_pool;     /* map ele pool */
  ulong                      max_accounts; /* map ele pool max */
  ulong                      seed;         /* map hash function */
  ulong                      chain_mask;   /* map chain count - 1 (chain counts exceed 2^32 at mainnet max_accounts) */

  ulong *       epoch_slot; /* epoch announced by this reader */
  ulong const * epoch;      /* accdb global epoch */

  uint root_generation;     /* newest generation in the snapshot */
};

typedef struct fd_backup_accidx fd_backup_accidx_t;

FD_PROTOTYPES_BEGIN

/* fd_backup_accidx_chain returns the acc_map chain that pubkey hashes
   to. */

FD_FN_PURE static inline ulong
fd_backup_accidx_chain( fd_backup_accidx_t const * idx,
                        uchar const                pubkey[ static 32 ] ) {
  return fd_hash32( pubkey, idx->seed ) & idx->chain_mask;
}

/* fd_backup_accidx_valid returns 1 if ele addresses an acc_pool element,
   0 otherwise.  The UINT_MAX chain terminator always fails this test
   because accdb rejects max_accounts>=UINT_MAX at creation, so callers
   walking a chain need only this one bound check. */

FD_FN_PURE static inline int
fd_backup_accidx_valid( fd_backup_accidx_t const * idx,
                        uint                       ele ) {
  return (ulong)ele < idx->max_accounts;
}

/* fd_backup_accidx_rooted returns 1 if the account version described by
   (generation,lamports) belongs in the snapshot: committed at or below
   the root generation, and not a tombstone. */

FD_FN_PURE static inline int
fd_backup_accidx_rooted( fd_backup_accidx_t const * idx,
                         uint                       generation,
                         ulong                      lamports ) {
  return ( generation<=idx->root_generation ) & ( lamports!=0UL );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backup_fd_backup_accidx_h */

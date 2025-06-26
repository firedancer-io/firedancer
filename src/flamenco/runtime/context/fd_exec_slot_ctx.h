#ifndef HEADER_fd_src_flamenco_runtime_context_fd_exec_slot_ctx_h
#define HEADER_fd_src_flamenco_runtime_context_fd_exec_slot_ctx_h

#include "../fd_blockstore.h"
#include "../../../funk/fd_funk.h"
#include "../../../util/rng/fd_rng.h"
#include "../../../util/wksp/fd_wksp.h"

#include "../../types/fd_types.h"
#include "../fd_txncache.h"
#include "../fd_acc_mgr.h"
#include "../fd_bank_hash_cmp.h"
#include "../fd_bank.h"

/* fd_exec_slot_ctx_t is the context that stays constant during all
   transactions in a block. */

/* TODO: The slot ctx should be removed entirely. Pointers to
   funk, funk_txn, status_cache should be passed in
   seperately.*/

struct fd_exec_slot_ctx {
  ulong                       magic; /* ==FD_EXEC_SLOT_CTX_MAGIC */

  ulong                       slot;

  fd_banks_t *                banks;
  fd_bank_t *                 bank;

  /* External joins, pointers to be set by caller */

  fd_funk_t *                 funk;
  fd_funk_txn_t *             funk_txn;

  fd_txncache_t *             status_cache;
};

#define FD_EXEC_SLOT_CTX_ALIGN     (alignof(fd_exec_slot_ctx_t))
#define FD_EXEC_SLOT_CTX_FOOTPRINT (sizeof (fd_exec_slot_ctx_t))
#define FD_EXEC_SLOT_CTX_MAGIC     (0xC2287BA2A5E6FC3DUL) /* random */

FD_PROTOTYPES_BEGIN

void *
fd_exec_slot_ctx_new( void * mem );

fd_exec_slot_ctx_t *
fd_exec_slot_ctx_join( void * mem );

void *
fd_exec_slot_ctx_leave( fd_exec_slot_ctx_t * ctx );

void *
fd_exec_slot_ctx_delete( void * mem );

/* fd_exec_slot_ctx_recover re-initializes the current epoch/slot
   context and recovers it from the manifest of a Solana Labs snapshot.

   Copies content of manifest to ctx.  The 'manifest' object may be
   freed after this function returns.  Assumes that slot context and
   epoch context use same allocator.  Returns ctx on success.
   On failure, logs reason for error and returns NULL. */

fd_exec_slot_ctx_t *
fd_exec_slot_ctx_recover( fd_exec_slot_ctx_t *                ctx,
                          fd_solana_manifest_global_t const * manifest_global,
                          fd_spad_t *                         spad );

/* fd_exec_slot_ctx_recover re-initializes the current slot
   context's status cache from the provided solana slot deltas.
   Assumes objects in slot deltas were allocated using slot ctx valloc
   (U.B. otherwise).
   On return, slot deltas is destroyed.  Returns ctx on success.
   On failure, logs reason for error and returns NULL. */

fd_exec_slot_ctx_t *
fd_exec_slot_ctx_recover_status_cache( fd_exec_slot_ctx_t *    ctx,
                                       fd_bank_slot_deltas_t * slot_deltas,
                                       fd_spad_t *             runtime_spad );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_context_fd_exec_slot_ctx_h */

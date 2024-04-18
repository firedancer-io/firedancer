#ifndef HEADER_fd_src_flamenco_runtime_context_fd_exec_slot_ctx_h
#define HEADER_fd_src_flamenco_runtime_context_fd_exec_slot_ctx_h

#include "../fd_blockstore.h"
#include "../../../funk/fd_funk.h"
#include "../../../util/rng/fd_rng.h"
#include "../../../util/wksp/fd_wksp.h"

#include "../../rewards/fd_rewards_types.h"
#include "../sysvar/fd_sysvar_cache.h"
#include "../sysvar/fd_sysvar_cache_old.h"
#include "../../types/fd_types.h"

/* fd_latest_vote_t records the latest voted slot hash by a given node. */

struct fd_latest_vote {
   fd_pubkey_t node_pubkey;
   fd_slot_hash_t slot_hash;
};
typedef struct fd_latest_vote fd_latest_vote_t;

#define DEQUE_NAME fd_latest_vote_deque
#define DEQUE_T    fd_latest_vote_t
#define DEQUE_MAX  (1UL << 16)
#include "../../../util/tmpl/fd_deque.c"

/* fd_exec_slot_ctx_t is the context that stays constant during all
   transactions in a block. */

struct __attribute__((aligned(8UL))) fd_exec_slot_ctx {
  ulong                    magic; /* ==FD_EXEC_SLOT_CTX_MAGIC */

  fd_exec_epoch_ctx_t *    epoch_ctx;

  fd_funk_txn_t *          funk_txn;
  fd_acc_mgr_t *           acc_mgr;
  fd_blockstore_t *        blockstore;
  fd_valloc_t              valloc;

  fd_slot_bank_t           slot_bank;
  fd_sysvar_cache_old_t    sysvar_cache_old; // TODO make const
  fd_pubkey_t const *      leader; /* Current leader */

  /* TODO figure out what to do with this */
  fd_epoch_reward_status_t epoch_reward_status;

  /* TODO remove this stuff */
  ulong                    signature_cnt;
  fd_hash_t                account_delta_hash;
  fd_hash_t                prev_banks_hash;

  fd_latest_vote_t *       latest_votes;
  fd_sysvar_cache_t *      sysvar_cache;
};

#define FD_EXEC_SLOT_CTX_ALIGN     (alignof(fd_exec_slot_ctx_t))
#define FD_EXEC_SLOT_CTX_FOOTPRINT (sizeof (fd_exec_slot_ctx_t))
#define FD_EXEC_SLOT_CTX_MAGIC (0xC2287BA2A5E6FC3DUL) /* random */

/* FD_FEATURE_ACTIVE evalutes to 1 if the given feature is active, 0
   otherwise.  First arg is the fd_exec_slot_ctx_t.  Second arg is the
   name of the feature.

   Example usage:   if( FD_FEATURE_ACTIVE( slot_ctx, set_exempt_rent_epoch_max ) ) */

#define FD_FEATURE_ACTIVE(_slot_ctx, _feature_name)  (_slot_ctx->slot_bank.slot >= _slot_ctx->epoch_ctx->features. _feature_name)

FD_PROTOTYPES_BEGIN

void *
fd_exec_slot_ctx_new( void *      mem,
                      fd_valloc_t valloc );

fd_exec_slot_ctx_t *
fd_exec_slot_ctx_join( void * mem );

void *
fd_exec_slot_ctx_leave( fd_exec_slot_ctx_t * ctx );

void *
fd_exec_slot_ctx_delete( void * mem );

/* fd_exec_slot_ctx_recover re-initializes the current epoch/slot
   context and recovers it from the manifest of a Solana Labs snapshot.
   Moves ownership of manifest to this function.  Assumes objects in
   manifest were allocated using slot ctx valloc (U.B. otherwise).
   Assumes that slot context and epoch context use same valloc.
   On return, manifest is destroyed.  Returns ctx on success.
   On failure, logs reason for error and returns NULL. */

fd_exec_slot_ctx_t *
fd_exec_slot_ctx_recover( fd_exec_slot_ctx_t *   ctx,
                          fd_solana_manifest_t * manifest );


/* Free all allocated memory within a slot ctx */
void
fd_exec_slot_ctx_free(fd_exec_slot_ctx_t * ctx);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_context_fd_exec_slot_ctx_h */

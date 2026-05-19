#ifndef HEADER_fd_src_flamenco_capture_fd_capture_ctx_h
#define HEADER_fd_src_flamenco_capture_fd_capture_ctx_h

/* fd_capture_ctx provides a context for capturing Solana runtime data
   during transaction execution.  The capture system supports two output
   modes:

   1. Buffer mode: writes to a shared memory buffer that is consumed by
      a capture tile and subsequently written to a file.  This is the
      default for live firedancer execution and backtest.

   2. File mode: writes directly to a file.  This is used for single-
      threaded harnesses that don't need the capture tile.

   Captured data includes account updates, bank preimages, and other
   runtime events in the solcap format. */

#include "fd_solcap_writer.h"
#include "../../util/fd_util_base.h"
#include "../../util/log/fd_log.h"
#include <sys/types.h>
#include "../../tango/fd_tango_base.h"

typedef struct fd_capture_link_vt fd_capture_link_vt_t;

/* fd_capture_link_t is the base type for capture links.  It uses a
   v-table pattern to support polymorphic write operations to either
   buffer or file destinations. */

struct fd_capture_link {
  fd_capture_link_vt_t const * vt; /* Virtual function table for this link type */
};
typedef struct fd_capture_link fd_capture_link_t;

/* fd_capture_link_buf_t is a capture link that writes to a shared
   memory buffer (frag stream).  This buffer is consumed by a capture
   tile which writes the data to a file. */

struct fd_capture_link_buf {
  fd_capture_link_t base;
  ulong             idx;
  fd_wksp_t *       mem;
  ulong             chunk0;
  ulong             wmark;
  ulong             chunk;
  fd_frag_meta_t *  mcache;
  ulong             depth;
  ulong             seq;
  ulong *           fseq;
};
typedef struct fd_capture_link_buf fd_capture_link_buf_t;

/* fd_capture_link_file_t is a capture link that writes directly to a
   file.  Used in single-threaded harness mode. */

struct fd_capture_link_file {
  fd_capture_link_t base;
  int               fd;
};
typedef struct fd_capture_link_file fd_capture_link_file_t;

/* fd_capture_link_vt_t is the virtual function table for capture
   links.  This allows the capture context to write to different
   destinations (buffer or file) without needing to check the link type
   at each call site. */

struct fd_capture_link_vt {
  void (* write_account_update)( fd_capture_ctx_t *               ctx,
                                 ulong                            txn_idx,
                                 fd_pubkey_t const *              key,
                                 fd_solana_account_meta_t const * info,
                                 ulong                            slot,
                                 uchar const *                    data,
                                 ulong                            data_sz);

  void (* write_bank_preimage)( fd_capture_ctx_t * ctx,
                                ulong              slot,
                                fd_hash_t const *  bank_hash,
                                fd_hash_t const *  prev_bank_hash,
                                fd_hash_t const *  accounts_lt_hash_checksum,
                                fd_hash_t const *  poh_hash,
                                ulong              signature_cnt);

  void (* write_stake_rewards_begin)( fd_capture_ctx_t * ctx,
                                      ulong              slot,
                                      ulong              payout_epoch,
                                      ulong              reward_epoch,
                                      ulong              inflation_lamports,
                                      ulong              total_points);

  void (* write_stake_reward_event)( fd_capture_ctx_t * ctx,
                                      ulong             slot,
                                      fd_pubkey_t       stake_acc_addr,
                                      fd_pubkey_t       vote_acc_addr,
                                      uint              commission,
                                      long              vote_rewards,
                                      long              stake_rewards,
                                      long              new_credits_observed );

  void (* write_stake_account_payout)( fd_capture_ctx_t * ctx,
                                      ulong               slot,
                                      fd_pubkey_t         stake_acc_addr,
                                      ulong               update_slot,
                                      ulong               lamports,
                                      long                lamports_delta,
                                      ulong               credits_observed,
                                      long                credits_observed_delta,
                                      ulong               delegation_stake,
                                      long                delegation_stake_delta );
};


/* fd_capture_account_event_msg_t is the on-wire frag format used by the
   event capture link.  Producers (replay/execrp tiles) publish one
   instance per account update to the event tile, which decodes and
   forwards it as a gRPC Account event.  Metadata only — account data
   bytes are not included. */

struct __attribute__((packed)) fd_capture_account_event_msg {
  uchar pubkey[ 32 ];
  uchar owner [ 32 ];
  ulong lamports;
  ulong slot;
  uchar signature[ 64 ];   /* signature of the txn that caused the update;
                              all-zero if not associated with a txn (e.g.
                              bank-hash-time updates). */
  ulong data_sz;
  uchar executable;
  uchar padding[ 7 ];
};
typedef struct fd_capture_account_event_msg fd_capture_account_event_msg_t;

/* fd_capture_bank_event_msg_t is the on-wire frag format used by the
   bank-hash event capture link.  One per slot, emitted at the end of
   bank hashing. */

struct __attribute__((packed)) fd_capture_bank_event_msg {
  uchar bank_hash                [ 32 ];
  uchar prev_bank_hash           [ 32 ];
  uchar accounts_lt_hash_checksum[ 32 ];
  uchar poh_hash                 [ 32 ];
  ulong slot;
  ulong signature_cnt;
};
typedef struct fd_capture_bank_event_msg fd_capture_bank_event_msg_t;

/* fd_capture_stake_event_msg_t — emitted whenever the runtime updates
   the stake delegations cache during transaction commit. */

struct __attribute__((packed)) fd_capture_stake_event_msg {
  uchar pubkey      [ 32 ];
  uchar voter_pubkey[ 32 ];
  ulong stake;
  ulong activation_epoch;
  ulong deactivation_epoch;
  ulong credits_observed;
  ulong slot;
  uchar removed;
  uchar padding[ 7 ];
};
typedef struct fd_capture_stake_event_msg fd_capture_stake_event_msg_t;

/* fd_capture_vote_event_msg_t — emitted whenever the runtime updates
   the top-votes cache during transaction commit. */

struct __attribute__((packed)) fd_capture_vote_event_msg {
  uchar pubkey[ 32 ];
  ulong last_vote_slot;
  long  last_vote_timestamp;
  ulong slot;
  uchar invalidated;
  uchar padding[ 7 ];
};
typedef struct fd_capture_vote_event_msg fd_capture_vote_event_msg_t;

/* Per-vote-instruction event capture.  Emitted from the vote program
   at the start of processing each vote instruction (tower_sync etc.)
   regardless of outcome. */

#define FD_CAPTURE_VOTE_TXN_TOWER_MAX (32UL)

struct __attribute__((packed)) fd_capture_vote_lockout {
  ulong slot;
  uint  confirmation_count;
  uchar pad[ 4 ];
};
typedef struct fd_capture_vote_lockout fd_capture_vote_lockout_t;

struct __attribute__((packed)) fd_capture_vote_txn_event_msg {
  uchar vote_account[ 32 ];
  uchar voter       [ 32 ];
  uchar bank_hash   [ 32 ];
  uchar block_id    [ 32 ];
  uchar signature   [ 64 ];
  ulong slot;
  ulong root_slot;
  long  timestamp;
  uchar has_root;
  uchar has_timestamp;
  uchar has_block_id;
  uchar lockouts_cnt;
  uchar ix_variant;
  uchar padding[ 3 ];
  fd_capture_vote_lockout_t lockouts[ FD_CAPTURE_VOTE_TXN_TOWER_MAX ];
};
typedef struct fd_capture_vote_txn_event_msg fd_capture_vote_txn_event_msg_t;

/* Context needed to do solcap capture during execution of transactions */

struct fd_capture_ctx {
  ulong magic; /* ==FD_CAPTURE_CTX_MAGIC */

  int                 capture_solcap;
  fd_capture_link_t * capture_link;
  union {
    fd_capture_link_buf_t * buf;
    fd_capture_link_file_t * file;
  } capctx_type;

  /* Solcap */
  ulong                    solcap_start_slot;
  fd_solcap_writer_t *     capture;

  ulong                    current_txn_idx;
  uchar                    current_txn_signature[ 64 ];   /* per-dispatched-txn,
                                                             set by execrp; used
                                                             by account event
                                                             producers */

  /* Event tile account capture (independent of solcap).  When
     capture_account_events is set, producers also publish a metadata-
     only frag to event_capture_link per account update. */
  int                     capture_account_events;
  fd_capture_link_buf_t * event_capture_link;

  /* Event tile bank-hash capture (independent of solcap).  When
     capture_bank_events is set, the runtime publishes one frag per
     completed slot to bank_capture_link. */
  int                     capture_bank_events;
  fd_capture_link_buf_t * bank_capture_link;

  /* Event tile stake-cache and top-votes-cache update capture
     (independent of solcap).  When set, the runtime publishes one
     frag per cache update during transaction commit. */
  int                     capture_stake_events;
  fd_capture_link_buf_t * stake_capture_link;
  int                     capture_vote_events;
  fd_capture_link_buf_t * vote_capture_link;

  /* Event tile per-vote-instruction capture (independent of solcap).
     When set, the vote program publishes one frag per vote instruction
     to vote_txn_capture_link. */
  int                     capture_vote_txn_events;
  fd_capture_link_buf_t * vote_txn_capture_link;
};
typedef struct fd_capture_ctx fd_capture_ctx_t;

static inline ulong
fd_capture_ctx_align( void ) {
  return fd_ulong_max( alignof(fd_capture_ctx_t), fd_solcap_writer_align() );
}

static inline ulong
fd_capture_ctx_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l    = FD_LAYOUT_APPEND ( l, fd_capture_ctx_align(),   sizeof(fd_capture_ctx_t) );
  l    = FD_LAYOUT_APPEND ( l, fd_solcap_writer_align(), fd_solcap_writer_footprint() );
  return FD_LAYOUT_FINI   ( l, fd_capture_ctx_align() );
}

#define FD_CAPTURE_CTX_MAGIC     (0x193ECD2A6C395195UL) /* random */

FD_PROTOTYPES_BEGIN

void *
fd_capture_ctx_new( void * mem );

fd_capture_ctx_t *
fd_capture_ctx_join( void * mem );

void *
fd_capture_ctx_leave( fd_capture_ctx_t * ctx );

void *
fd_capture_ctx_delete( void * mem );

FD_PROTOTYPES_END

/* Solcap capture link functions

   The following functions write solcap messages to either a buffer or
   file.  They are used as v-table implementations for the capture link
   abstraction.

   For each message type, there are two implementations:
   - _buf:  writes to a shared memory frag stream (buffer mode)
   - _file: writes directly to a file descriptor (file mode)

   The v-table dispatch mechanism automatically selects the correct
   implementation based on the link type, so callers use the inline
   wrapper functions below instead of calling these directly.

*/

void
fd_capture_link_write_account_update_buf( fd_capture_ctx_t *               ctx,
                                              ulong                            txn_idx,
                                              fd_pubkey_t const *              key,
                                              fd_solana_account_meta_t const * info,
                                              ulong                            slot,
                                              uchar const *                    data,
                                              ulong                            data_sz );

void
fd_capture_link_write_account_update_file( fd_capture_ctx_t *               ctx,
                                               ulong                            txn_idx,
                                               fd_pubkey_t const *              key,
                                               fd_solana_account_meta_t const * info,
                                               ulong                            slot,
                                               uchar const *                    data,
                                               ulong                            data_sz );

/* fd_capture_link_write_account_update writes an account update to the
   capture link. Uses v-table dispatch to automatically route to the
   correct implementation (buffer or file) based on the link type. */

static inline void
fd_capture_link_write_account_update( fd_capture_ctx_t *               ctx,
                                      ulong                            txn_idx,
                                      fd_pubkey_t const *              key,
                                      fd_solana_account_meta_t const * info,
                                      ulong                            slot,
                                      uchar const *                    data,
                                      ulong                            data_sz ) {
  FD_TEST( ctx && ctx->capture_link );
  ctx->capture_link->vt->write_account_update( ctx, txn_idx, key, info, slot, data, data_sz );
}

void
fd_capture_link_write_bank_preimage_buf( fd_capture_ctx_t * ctx,
                                         ulong              slot,
                                         fd_hash_t const *  bank_hash,
                                         fd_hash_t const *  prev_bank_hash,
                                         fd_hash_t const *  accounts_lt_hash_checksum,
                                         fd_hash_t const *  poh_hash,
                                         ulong              signature_cnt );

void
fd_capture_link_write_bank_preimage_file( fd_capture_ctx_t * ctx,
                                          ulong              slot,
                                          fd_hash_t const *  bank_hash,
                                          fd_hash_t const *  prev_bank_hash,
                                          fd_hash_t const *  accounts_lt_hash_checksum,
                                          fd_hash_t const *  poh_hash,
                                          ulong              signature_cnt );

/* fd_capture_link_write_bank_preimage writes a bank preimage to the
   capture link. Uses v-table dispatch to automatically route to the
   correct implementation (buffer or file) based on the link type. */

static inline void
fd_capture_link_write_bank_preimage( fd_capture_ctx_t * ctx,
                                     ulong              slot,
                                     fd_hash_t const *  bank_hash,
                                     fd_hash_t const *  prev_bank_hash,
                                     fd_hash_t const *  accounts_lt_hash_checksum,
                                     fd_hash_t const *  poh_hash,
                                     ulong              signature_cnt ) {
  FD_TEST( ctx && ctx->capture_link );
  ctx->capture_link->vt->write_bank_preimage( ctx, slot, bank_hash, prev_bank_hash, accounts_lt_hash_checksum, poh_hash, signature_cnt );
}

/* fd_capture_link_write_stake_rewards_begin writes a stake rewards begin to the
   capture link. Uses v-table dispatch to automatically route to the
   correct implementation (buffer or file) based on the link type. */

void
fd_capture_link_write_stake_rewards_begin_buf( fd_capture_ctx_t * ctx,
                                               ulong              slot,
                                               ulong              payout_epoch,
                                               ulong              reward_epoch,
                                               ulong              inflation_lamports,
                                               ulong              total_points );

void
fd_capture_link_write_stake_rewards_begin_file( fd_capture_ctx_t * ctx,
                                                ulong              slot,
                                                ulong              payout_epoch,
                                                ulong              reward_epoch,
                                                ulong              inflation_lamports,
                                                ulong              total_points );

static inline void
fd_capture_link_write_stake_rewards_begin( fd_capture_ctx_t * ctx,
                                           ulong              slot,
                                           ulong              payout_epoch,
                                           ulong              reward_epoch,
                                           ulong              inflation_lamports,
                                           ulong              total_points ) {
  FD_TEST( ctx && ctx->capture_link );
  ctx->capture_link->vt->write_stake_rewards_begin( ctx, slot, payout_epoch, reward_epoch, inflation_lamports, total_points );
}

void
fd_capture_link_write_stake_reward_event_buf( fd_capture_ctx_t * ctx,
                                              ulong              slot,
                                              fd_pubkey_t        stake_acc_addr,
                                              fd_pubkey_t        vote_acc_addr,
                                              uint               commission,
                                              long               vote_rewards,
                                              long               stake_rewards,
                                              long               new_credits_observed );

void
fd_capture_link_write_stake_reward_event_file( fd_capture_ctx_t * ctx,
                                               ulong              slot,
                                               fd_pubkey_t        stake_acc_addr,
                                               fd_pubkey_t        vote_acc_addr,
                                               uint               commission,
                                               long               vote_rewards,
                                               long               stake_rewards,
                                               long               new_credits_observed );

static inline void
fd_capture_link_write_stake_reward_event( fd_capture_ctx_t * ctx,
                                          ulong              slot,
                                          fd_pubkey_t        stake_acc_addr,
                                          fd_pubkey_t        vote_acc_addr,
                                          uint               commission,
                                          long               vote_rewards,
                                          long               stake_rewards,
                                          long               new_credits_observed ) {
  FD_TEST( ctx && ctx->capture_link );
  ctx->capture_link->vt->write_stake_reward_event( ctx, slot, stake_acc_addr, vote_acc_addr, commission, vote_rewards, stake_rewards, new_credits_observed );
}

void
fd_capture_link_write_stake_account_payout_buf( fd_capture_ctx_t * ctx,
                                                ulong              slot,
                                                fd_pubkey_t        stake_acc_addr,
                                                ulong              update_slot,
                                                ulong              lamports,
                                                long               lamports_delta,
                                                ulong              credits_observed,
                                                long               credits_observed_delta,
                                                ulong              delegation_stake,
                                                long               delegation_stake_delta );
void
fd_capture_link_write_stake_account_payout_file( fd_capture_ctx_t * ctx,
                                                ulong              slot,
                                                fd_pubkey_t        stake_acc_addr,
                                                ulong              update_slot,
                                                ulong              lamports,
                                                long               lamports_delta,
                                                ulong              credits_observed,
                                                long               credits_observed_delta,
                                                ulong              delegation_stake,
                                                long               delegation_stake_delta );

static inline void
fd_capture_link_write_stake_account_payout( fd_capture_ctx_t * ctx,
                                            ulong              slot,
                                            fd_pubkey_t        stake_acc_addr,
                                            ulong              update_slot,
                                            ulong              lamports,
                                            long               lamports_delta,
                                            ulong              credits_observed,
                                            long               credits_observed_delta,
                                            ulong              delegation_stake,
                                            long               delegation_stake_delta ) {
  FD_TEST( ctx && ctx->capture_link );
  ctx->capture_link->vt->write_stake_account_payout( ctx, slot, stake_acc_addr, update_slot, lamports, lamports_delta, credits_observed, credits_observed_delta, delegation_stake, delegation_stake_delta );
}

/* fd_capture_link_write_account_event publishes a metadata-only
   account update frag to the event capture link (consumed by the event
   tile).  No-op if event_capture_link is not configured. */

void
fd_capture_link_write_account_event( fd_capture_ctx_t *               ctx,
                                     uchar const *                    signature,
                                     fd_pubkey_t const *              key,
                                     fd_solana_account_meta_t const * info,
                                     ulong                            slot,
                                     ulong                            data_sz );

/* fd_capture_link_write_bank_event publishes one bank-hash frag to the
   bank event capture link.  No-op if bank_capture_link is not
   configured. */

void
fd_capture_link_write_bank_event( fd_capture_ctx_t * ctx,
                                  ulong              slot,
                                  fd_hash_t const *  bank_hash,
                                  fd_hash_t const *  prev_bank_hash,
                                  fd_hash_t const *  accounts_lt_hash_checksum,
                                  fd_hash_t const *  poh_hash,
                                  ulong              signature_cnt );

/* fd_capture_link_write_stake_event publishes one stake-cache update
   frag.  Pass removed=1 if the delegation was removed (then the other
   delegation fields should be zero). */

void
fd_capture_link_write_stake_event( fd_capture_ctx_t *  ctx,
                                   fd_pubkey_t const * pubkey,
                                   fd_pubkey_t const * voter_pubkey,
                                   ulong               stake,
                                   ulong               activation_epoch,
                                   ulong               deactivation_epoch,
                                   ulong               credits_observed,
                                   ulong               slot,
                                   int                 removed );

/* fd_capture_link_write_vote_event publishes one top-votes cache
   update frag.  Pass invalidated=1 if the vote account was
   invalidated (then last_vote_slot/timestamp should be zero). */

void
fd_capture_link_write_vote_event( fd_capture_ctx_t *  ctx,
                                  fd_pubkey_t const * pubkey,
                                  ulong               last_vote_slot,
                                  long                last_vote_timestamp,
                                  ulong               slot,
                                  int                 invalidated );

/* fd_capture_link_write_vote_txn publishes one per-vote-instruction
   frag.  lockouts may be NULL when lockouts_cnt==0.  bank_hash /
   block_id may be NULL (will be zeroed). */

void
fd_capture_link_write_vote_txn( fd_capture_ctx_t *                  ctx,
                                fd_pubkey_t const *                 vote_account,
                                fd_pubkey_t const *                 voter,
                                fd_hash_t const *                   bank_hash,
                                fd_hash_t const *                   block_id,
                                uchar const *                       signature,
                                ulong                               slot,
                                ulong                               root_slot,
                                long                                timestamp,
                                int                                 has_root,
                                int                                 has_timestamp,
                                int                                 has_block_id,
                                uint                                ix_variant,
                                fd_capture_vote_lockout_t const *   lockouts,
                                ulong                               lockouts_cnt );

/* fd_capture_link_buf_vt is the v-table for buffer mode capture links.
   It routes all write operations to the buffer implementations. */

static const
fd_capture_link_vt_t fd_capture_link_buf_vt = {
  .write_account_update      = fd_capture_link_write_account_update_buf,
  .write_bank_preimage       = fd_capture_link_write_bank_preimage_buf,
  .write_stake_rewards_begin = fd_capture_link_write_stake_rewards_begin_buf,
  .write_stake_reward_event = fd_capture_link_write_stake_reward_event_buf,
  .write_stake_account_payout = fd_capture_link_write_stake_account_payout_buf,
};

/* fd_capture_link_file_vt is the v-table for file mode capture links.
   It routes all write operations to the file implementations. */

static const
fd_capture_link_vt_t fd_capture_link_file_vt = {
  .write_account_update      = fd_capture_link_write_account_update_file,
  .write_bank_preimage       = fd_capture_link_write_bank_preimage_file,
  .write_stake_rewards_begin = fd_capture_link_write_stake_rewards_begin_file,
  .write_stake_reward_event = fd_capture_link_write_stake_reward_event_file,
  .write_stake_account_payout = fd_capture_link_write_stake_account_payout_file,
};

#endif /* HEADER_fd_src_flamenco_capture_fd_capture_ctx_h */


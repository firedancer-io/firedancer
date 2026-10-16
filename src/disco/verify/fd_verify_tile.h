#ifndef HEADER_fd_src_disco_verify_fd_verify_tile_h
#define HEADER_fd_src_disco_verify_fd_verify_tile_h

/* The verify tile verifies that the cryptographic signatures of
   incoming transactions match the data being signed.  Transactions with
   invalid signatures are filtered out of the frag stream. */

#include "../topo/fd_topo.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/sha512/fd_sha512.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../metrics/generated/fd_metrics_enums.h"

#define FD_TXN_VERIFY_SUCCESS  0
#define FD_TXN_VERIFY_FAILED  -1
#define FD_TXN_VERIFY_DEDUP   -2

/* Signer precomputation cache entries per verify tile (gossip votes
   are signed by ~1.5k vote authorities) */
#define FD_VERIFY_ED25519_CACHE_ENT_CNT (2048UL)

extern fd_topo_run_tile_t fd_tile_verify;

/* fd_verify_in_ctx_t is a context object for each in (producer) mcache
   connected to the verify tile. */

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_verify_in_ctx_t;

/* Transactions that are not part of a bundle are queued and their
   signatures verified in one batch, so a batched verify backend can
   check them together.  A batch is flushed when it holds
   FD_VERIFY_BATCH_SIG_MAX signatures or FD_VERIFY_BATCH_TXN_MAX
   transactions, when a fragment is rejected before it is queued, as
   soon as no input has this tile's next fragment ready, and in any
   case once its oldest transaction has waited FD_VERIFY_BATCH_MAX_AGE_NS,
   so batching only happens while the tile is behind and a queued
   transaction is never held beyond that bound. */

#define FD_VERIFY_BATCH_TXN_MAX    (8UL)
#define FD_VERIFY_BATCH_SIG_MAX    (8UL)
#define FD_VERIFY_BATCH_LANE_MAX   (FD_VERIFY_BATCH_TXN_MAX*FD_TXN_SIG_MAX)
#define FD_VERIFY_BATCH_MAX_AGE_NS (1000000L)

typedef struct {
  ulong chunk;       /* out chunk the staged transaction occupies */
  ulong realized_sz; /* fd_txn_m_realized_footprint of it */
  ulong tsorig;
  ulong dedup_tag;
  long  enq_tick;    /* fd_tickcount when queued */
  uchar sig_cnt;
} fd_verify_batch_txn_t;

typedef struct {
  fd_sha512_t * sha[ FD_TXN_SIG_MAX ];

  fd_ed25519_cache_t * ed25519_cache;

  int   bundle_failed;
  ulong bundle_id;

  /* One sha per lane the batch can hold */
  fd_sha512_t * batch_sha[ FD_VERIFY_BATCH_LANE_MAX ];

  fd_verify_batch_txn_t batch_txn[ FD_VERIFY_BATCH_TXN_MAX ];
  ulong                 batch_txn_cnt;
  ulong                 batch_sig_cnt;      /* lanes in use, sum of batch_txn[].sig_cnt */
  long                  batch_max_age_ticks; /* FD_VERIFY_BATCH_MAX_AGE_NS in ticks */

  /* Per input, the sequence number of a fragment for this tile that was
     seen published; no need to look again until it is consumed. */
  ulong in_cnt;
  ulong in_ready_seq[ 32 ];

  uchar const * batch_msg   [ FD_VERIFY_BATCH_LANE_MAX ];
  ulong         batch_msg_sz[ FD_VERIFY_BATCH_LANE_MAX ];
  uchar const * batch_sig   [ FD_VERIFY_BATCH_LANE_MAX ];
  uchar const * batch_pubkey[ FD_VERIFY_BATCH_LANE_MAX ];
  int           batch_result[ FD_VERIFY_BATCH_LANE_MAX ];

  ulong round_robin_idx;
  ulong round_robin_cnt;

  ulong   tcache_depth;
  ulong   tcache_map_cnt;
  ulong * tcache_sync;
  ulong * tcache_ring;
  ulong * tcache_map;

  ulong              in_kind[ 32 ];
  fd_verify_in_ctx_t in[ 32 ];

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;

  ulong       hashmap_seed;

  struct {
    ulong verify_tile_result[ FD_METRICS_ENUM_VERIFY_RESULT_CNT ];
    ulong gossiped_votes_cnt;
    ulong own_votes_cnt;
  } metrics;
} fd_verify_ctx_t;

static inline int
fd_txn_verify( fd_verify_ctx_t * ctx,
               uchar const *     udp_payload,
               ushort const      payload_sz,
               fd_txn_t const *  txn,
               int               dedup,
               ulong *           opt_sig ) {

  /* We do not want to deref any non-data field from the txn struct more than once */
  uchar  signature_cnt = txn->signature_cnt;
  ushort signature_off = txn->signature_off;
  ushort acct_addr_off = txn->acct_addr_off;
  ushort message_off   = txn->message_off;

  uchar const * signatures = udp_payload + signature_off;
  uchar const * pubkeys = udp_payload + acct_addr_off;
  uchar const * msg = udp_payload + message_off;
  ulong msg_sz = fd_txn_msg_sz( txn, (ulong)payload_sz );

  /* The first signature is the transaction id, i.e. a unique identifier.
     So use this to do a quick dedup of ha traffic. */

  ulong ha_dedup_tag = fd_hash( ctx->hashmap_seed, signatures, 64UL );
  int ha_dup = 0;
  if( FD_LIKELY( dedup ) ) {
    FD_FN_UNUSED ulong tcache_map_idx = 0; /* ignored */
    FD_TCACHE_QUERY( ha_dup, tcache_map_idx, ctx->tcache_map, ctx->tcache_map_cnt, ha_dedup_tag );
    if( FD_UNLIKELY( ha_dup ) ) {
      return FD_TXN_VERIFY_DEDUP;
    }
  }

  /* Verify signatures */
  int res = fd_ed25519_verify_batch_single_msg_cached( msg, msg_sz, signatures, pubkeys, ctx->sha, signature_cnt, ctx->ed25519_cache );
  if( FD_UNLIKELY( res != FD_ED25519_SUCCESS ) ) {
    return FD_TXN_VERIFY_FAILED;
  }

  /* Insert into the tcache to dedup ha traffic.
     The dedup check is repeated to guard against duped txs verifying signatures at the same time */
  if( FD_LIKELY( dedup ) ) {
    FD_TCACHE_INSERT( ha_dup, *ctx->tcache_sync, ctx->tcache_ring, ctx->tcache_depth, ctx->tcache_map, ctx->tcache_map_cnt, ha_dedup_tag );
    if( FD_UNLIKELY( ha_dup ) ) {
      return FD_TXN_VERIFY_DEDUP;
    }
  }

  *opt_sig = ha_dedup_tag;
  return FD_TXN_VERIFY_SUCCESS;
}

#endif /* HEADER_fd_src_disco_verify_fd_verify_tile_h */

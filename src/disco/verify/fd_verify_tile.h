#ifndef HEADER_fd_src_disco_verify_fd_verify_tile_h
#define HEADER_fd_src_disco_verify_fd_verify_tile_h

/* The verify tile verifies that the cryptographic signatures of
   incoming transactions match the data being signed.  Transactions with
   invalid signatures are filtered out of the frag stream. */

#include "../topo/fd_topo.h"
#include "../metrics/generated/fd_metrics_enums.h"

#define FD_TXN_VERIFY_SUCCESS  0
#define FD_TXN_VERIFY_FAILED  -1
#define FD_TXN_VERIFY_DEDUP   -2

extern fd_topo_run_tile_t fd_tile_verify;

/* fd_verify_in_ctx_t is a context object for each in (producer) mcache
   connected to the verify tile. */

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_verify_in_ctx_t;

/* Transactions that are not part of a bundle are verified in batches
   so the signatures can be checked in parallel with SIMD.  A batch is
   flushed when it holds FD_VERIFY_BATCH_SIG_MAX signatures, or as soon
   as no input has this tile's next fragment ready, so batching only
   happens while the tile is behind and adds no latency otherwise. */

#define FD_VERIFY_BATCH_TXN_MAX (8UL)
#define FD_VERIFY_BATCH_SIG_MAX (8UL)

typedef struct {
  ulong chunk;
  ulong realized_sz;
  ulong tsorig;
  ulong dedup_tag;
  int   dedup;
  uchar sig_cnt;
  uchar out_idx; /* the dedup tile it goes to */
} fd_verify_batch_txn_t;

/* One out link per dedup tile; a transaction's dedup is chosen by its
   first signature so duplicates from different verify tiles meet. */
#define FD_VERIFY_OUT_MAX (8UL)
typedef struct {
  ulong chunk0;
  ulong wmark;
  ulong chunk;
} fd_verify_out_ctx_t;

typedef struct {
  fd_sha512_t * sha[ FD_TXN_SIG_MAX ];

  int   bundle_failed;
  ulong bundle_id;

  /* One sha per lane the batch can hold, for the scalar fallback */
  fd_sha512_t * batch_sha[ FD_VERIFY_BATCH_TXN_MAX*FD_TXN_SIG_MAX ];

  fd_verify_batch_txn_t batch_txn[ FD_VERIFY_BATCH_TXN_MAX ];
  ulong                 batch_txn_cnt;
  ulong                 batch_sig_cnt;

  /* Per input, the sequence number of a fragment for this tile that was
     seen published; no need to look again until it is consumed. */
  ulong in_cnt;
  ulong in_ready_seq[ 32 ];

  uchar const * batch_msg   [ FD_VERIFY_BATCH_TXN_MAX*FD_TXN_SIG_MAX ];
  ulong         batch_msg_sz[ FD_VERIFY_BATCH_TXN_MAX*FD_TXN_SIG_MAX ];
  uchar const * batch_sig   [ FD_VERIFY_BATCH_TXN_MAX*FD_TXN_SIG_MAX ];
  uchar const * batch_pubkey[ FD_VERIFY_BATCH_TXN_MAX*FD_TXN_SIG_MAX ];
  int           batch_result[ FD_VERIFY_BATCH_TXN_MAX*FD_TXN_SIG_MAX ];

  ulong round_robin_idx;
  ulong round_robin_cnt;

  ulong   tcache_depth;
  ulong   tcache_map_cnt;
  ulong * tcache_sync;
  ulong * tcache_ring;
  ulong * tcache_map;

  ulong              in_kind[ 32 ];
  fd_verify_in_ctx_t in[ 32 ];

  fd_wksp_t *         out_mem; /* every out link's dcache is in this workspace */
  ulong               out_cnt;
  ulong               cur_out; /* chosen in during_frag */
  fd_verify_out_ctx_t out[ FD_VERIFY_OUT_MAX ];

  ulong       hashmap_seed;

  struct {
    ulong verify_tile_result[ FD_METRICS_ENUM_VERIFY_TILE_RESULT_CNT ];
    ulong gossiped_votes_cnt;
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
  int res = fd_ed25519_verify_batch_single_msg( msg, msg_sz, signatures, pubkeys, ctx->sha, signature_cnt );
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

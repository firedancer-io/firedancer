#ifndef HEADER_fd_src_app_fdctl_run_tiles_verify_h
#define HEADER_fd_src_app_fdctl_run_tiles_verify_h

#include "tiles.h"

#define VERIFY_TCACHE_DEPTH   16UL
#define VERIFY_TCACHE_MAP_CNT 64UL

#define FD_TXN_VERIFY_SUCCESS  0
#define FD_TXN_VERIFY_FAILED  -1
#define FD_TXN_VERIFY_DEDUP   -2

/* fd_verify_in_ctx_t is a context object for each in (producer) mcache
   connected to the verify tile. */

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_verify_in_ctx_t;

typedef struct {
  /* TODO switch to fd_sha512_batch_t? */
  fd_sha512_t * sha[ FD_TXN_ACTUAL_SIG_MAX ];

  ulong round_robin_idx;
  ulong round_robin_cnt;

  ulong   tcache_depth;
  ulong   tcache_map_cnt;
  ulong * tcache_sync;
  ulong * tcache_ring;
  ulong * tcache_map;

  fd_verify_in_ctx_t in[ 32 ];

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
} fd_verify_ctx_t;

static inline int
fd_txn_verify( fd_verify_ctx_t * ctx,
               uchar const *     udp_payload,
               ushort const      payload_sz,
               fd_txn_t const *  txn,
               ulong *           opt_sig ) {

  /* We do not want to deref any non-data field from the txn struct more than once */
  uchar  signature_cnt = txn->signature_cnt;
  ushort signature_off = txn->signature_off;
  ushort acct_addr_off = txn->acct_addr_off;
  ushort message_off   = txn->message_off;

  uchar const * signatures = udp_payload + signature_off;
  uchar const * pubkeys = udp_payload + acct_addr_off;
  uchar const * msg = udp_payload + message_off;
  ulong msg_sz = (ulong)payload_sz - message_off;

  /* The first signature is the transaction id, i.e. a unique identifier.
     So use this to do a quick dedup of ha traffic. */

  /* TODO: use more than 64 bits to dedup. */
  ulong ha_dedup_tag = *((ulong *)signatures);
  int ha_dup;
  FD_FN_UNUSED ulong tcache_map_idx = 0; /* ignored */
  FD_TCACHE_QUERY( ha_dup, tcache_map_idx, ctx->tcache_map, ctx->tcache_map_cnt, ha_dedup_tag );
  if( FD_UNLIKELY( ha_dup ) ) {
    return FD_TXN_VERIFY_DEDUP;
  }

  /* Verify signatures */
  int res = fd_ed25519_verify_batch_single_msg( msg, msg_sz, signatures, pubkeys, ctx->sha, signature_cnt );
  if( FD_UNLIKELY( res != FD_ED25519_SUCCESS ) ) {
    return FD_TXN_VERIFY_FAILED;
  }

  /* Insert into the tcache to dedup ha traffic.
     The dedup check is repeated to guard against duped txs verifying signatures at the same time */
  FD_TCACHE_INSERT( ha_dup, *ctx->tcache_sync, ctx->tcache_ring, ctx->tcache_depth, ctx->tcache_map, ctx->tcache_map_cnt, ha_dedup_tag );
  if( FD_UNLIKELY( ha_dup ) ) {
    return FD_TXN_VERIFY_DEDUP;
  }

  *opt_sig = ha_dedup_tag;
  return FD_TXN_VERIFY_SUCCESS;
}

#endif /* HEADER_fd_src_app_fdctl_run_tiles_verify_h */

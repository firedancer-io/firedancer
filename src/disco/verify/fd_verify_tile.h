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

/* Transactions are queued and their signatures verified in one batch.
   A batch is flushed once it holds FD_VERIFY_BATCH_SIG_MAX signatures
   (so at most FD_VERIFY_BATCH_LANE_MAX, since the last transaction can
   bring FD_TXN_SIG_MAX), when no input has a fragment ready for this
   tile, or when its oldest transaction has waited
   FD_VERIFY_BATCH_MAX_AGE_NS. */

#define FD_VERIFY_BATCH_TXN_MAX    (8UL)
#define FD_VERIFY_BATCH_SIG_MAX    (8UL)
#define FD_VERIFY_BATCH_LANE_MAX   (FD_VERIFY_BATCH_SIG_MAX-1UL+FD_TXN_SIG_MAX)
#define FD_VERIFY_BATCH_MAX_AGE_NS (1000000L)

typedef struct {
  ulong chunk;       /* out chunk of the staged transaction */
  ulong realized_sz;
  ulong tsorig;
  ulong dedup_tag;   /* unused for a bundle transaction */
  ulong bundle_id;   /* 0 if not part of a bundle */
  long  enq_tick;
  uchar sig_cnt;
} fd_verify_batch_txn_t;

typedef struct {
  fd_sha512_t * sha[ FD_VERIFY_BATCH_LANE_MAX ];

  fd_ed25519_cache_t * ed25519_cache;

  /* Last bundle seen, and whether one of its members failed */
  int   bundle_failed;
  ulong bundle_id;

  fd_verify_batch_txn_t batch_txn[ FD_VERIFY_BATCH_TXN_MAX ];
  ulong                 batch_txn_cnt;
  ulong                 batch_sig_cnt;
  long                  batch_max_age_ticks;

  /* Per input, a sequence number seen published for this tile */
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
  } metrics;
} fd_verify_ctx_t;

#endif /* HEADER_fd_src_disco_verify_fd_verify_tile_h */

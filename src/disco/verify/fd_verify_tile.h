#ifndef HEADER_fd_src_disco_verify_fd_verify_tile_h
#define HEADER_fd_src_disco_verify_fd_verify_tile_h

/* The verify tile verifies that the cryptographic signatures of
   incoming transactions match the data being signed.  Transactions with
   invalid signatures are filtered out of the frag stream. */

#include "../topo/fd_topo.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/ed25519/fd_ed25519_verifier.h"
#include "../metrics/generated/fd_metrics_enums.h"

/* Signer precomputation cache entries per verify tile (gossip votes
   are signed by ~1.5k vote authorities) */
#define FD_VERIFY_ED25519_CACHE_ENT_CNT (2048UL)

/* A transaction's recent blockhash is valid for FD_VERIFY_BLOCKHASH_AGE
   slots after the slot that produced it (MAX_PROCESSING_AGE in Agave).
   A transaction can only land in a block we produce if that block's
   slot is within that window, so a TPU transaction whose blockhash
   slot s satisfies s+FD_VERIFY_BLOCKHASH_AGE<next_leader_slot can be
   dropped before signature verification.  This is the same window
   resolv uses (reference_slot+151<completed_slot is expired). */

#define FD_VERIFY_BLOCKHASH_AGE (150UL)

/* The verify tile remembers the blockhashes of the last
   FD_VERIFY_BLOCKHASH_RING_LEN completed slots.  Anything older is
   unknown to it and passes through to resolv, which keeps 19 days of
   history and drops them there. */

#define FD_VERIFY_BLOCKHASH_LG_RING_CNT (10UL)
#define FD_VERIFY_BLOCKHASH_RING_LEN    (1UL<<FD_VERIFY_BLOCKHASH_LG_RING_CNT)

struct fd_verify_blockhash {
  uchar b[ 32 ];
};

typedef struct fd_verify_blockhash fd_verify_blockhash_t;

struct fd_verify_blockhash_map {
  fd_verify_blockhash_t key;
  ulong                 slot;
};

typedef struct fd_verify_blockhash_map fd_verify_blockhash_map_t;

extern fd_topo_run_tile_t fd_tile_verify;

/* fd_verify_in_ctx_t is a context object for each in (producer) mcache
   connected to the verify tile. */

typedef struct {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
} fd_verify_in_ctx_t;

/* Transactions are queued and their signatures verified in one batch.
   A transaction joins the batch while the signatures fit in
   batch_sig_max (FD_ED25519_VERIFIER_GROUP, what the verifier wants
   per call; tests may lower or raise it within
   FD_VERIFY_BATCH_SIG_MAX); one that would overflow it flushes the
   batch first, and one with more signatures than a batch goes alone
   (so a batch holds at most FD_VERIFY_BATCH_LANE_MAX lanes).  A batch
   is also flushed when it is full, when no input has a fragment ready
   for this tile, or when its oldest transaction has waited
   FD_VERIFY_BATCH_MAX_AGE_NS. */

#define FD_VERIFY_BATCH_TXN_MAX    (FD_ED25519_VERIFIER_BATCH)
#define FD_VERIFY_BATCH_SIG_MAX    (FD_ED25519_VERIFIER_BATCH)
#define FD_VERIFY_BATCH_LANE_MAX   (FD_TXN_SIG_MAX)
#define FD_VERIFY_BATCH_MAX_AGE_NS (1000000L)

typedef struct {
  ulong chunk;       /* out chunk of the staged transaction */
  ulong realized_sz;
  ulong tsorig;
  ulong dedup_tag;   /* unused for a bundle transaction */
  ulong bundle_id;   /* 0 if not part of a bundle */
  long  enq_tick;
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
  fd_ed25519_verifier_t * verifier;

  /* Last bundle seen, and whether one of its members failed */
  int   bundle_failed;
  ulong bundle_id;

  fd_verify_batch_txn_t batch_txn[ FD_VERIFY_BATCH_TXN_MAX ];
  ulong                 batch_txn_cnt;
  ulong                 batch_sig_cnt;
  ulong                 batch_sig_max;
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
  uint *  tcache_map;

  ulong              in_kind[ 32 ];
  fd_verify_in_ctx_t in[ 32 ];

  fd_wksp_t *         out_mem; /* every out link's dcache is in this workspace */
  ulong               out_cnt;
  ulong               cur_out; /* chosen in during_frag */
  fd_verify_out_ctx_t out[ FD_VERIFY_OUT_MAX ];

  ulong       hashmap_seed;

  /* Blockhash -> slot for the last FD_VERIFY_BLOCKHASH_RING_LEN
     completed slots, fed by REPLAY_SIG_SLOT_COMPLETED on replay_slot,
     and the next slot we lead, fed by REPLAY_SIG_NEXT_LEADER.
     has_leader_schedule is set by the first NEXT_LEADER: replay loads
     the leader schedule for the current and next epoch before the boot
     slot's NEXT_LEADER, so from then on next_leader_slot==ULONG_MAX means we have
     no leader slot in either.  See fd_verify_blockhash_expires. */
  fd_verify_blockhash_map_t * blockhash_map;
  ulong                       blockhash_ring_idx;
  fd_verify_blockhash_t       blockhash_ring[ FD_VERIFY_BLOCKHASH_RING_LEN ];
  int                         has_leader_schedule;
  ulong                       next_leader_slot;

  ulong _replay_sig;
  uchar _replay_msg[ 64 ] __attribute__((aligned(8UL)));

  struct {
    ulong verify_tile_result[ FD_METRICS_ENUM_VERIFY_RESULT_CNT ];
  } metrics;
} fd_verify_ctx_t;

/* fd_verify_is_durable_nonce returns 1 if txn may be a durable nonce
   transaction (first instruction is SystemProgram::AdvanceNonceAccount)
   and 0 otherwise.  Durable nonce transactions do not expire with their
   recent blockhash.  Same check as the resolv tile. */

FD_FN_PURE static inline int
fd_verify_is_durable_nonce( fd_txn_t const * txn,
                            uchar    const * payload ) {
  /* base58 decode of 11111111111111111111111111111111 */
  static const uchar system_program_id[ FD_TXN_ACCT_ADDR_SZ ] = { 0 };

  if( FD_UNLIKELY( txn->instr_cnt==0 ) ) return 0;

  fd_txn_instr_t const * ix0 = &txn->instr[ 0 ];
  fd_acct_addr_t const * prog0 = fd_txn_get_acct_addrs( txn, payload ) + ix0->program_id;
  if( FD_LIKELY( !fd_memeq( prog0->b, system_program_id, FD_TXN_ACCT_ADDR_SZ ) ) ) return 0;

  /* three accounts and a four byte little-endian uint value 4 */
  if( FD_UNLIKELY( (ix0->data_sz!=4) | (ix0->acct_cnt!=3) ) ) return 0;

  return fd_uint_load_4( payload + ix0->data_off )==4U;
}

/* fd_verify_blockhash_expires returns 1 if a transaction whose recent
   blockhash was produced in blockhash_slot can no longer be included in
   any block this validator produces, and 0 otherwise.  next_leader_slot
   is the next slot we lead as of the last NEXT_LEADER from replay, which
   computes it over the leader schedules of the current and the next
   epoch (fd_multi_epoch_leaders).  ULONG_MAX therefore means we have no
   leader slot for the rest of this epoch and the whole of the next one,
   at least 432000 slots away, far beyond the 150 slot life of any
   blockhash, so it expires everything.  Callers must not use this
   before the first NEXT_LEADER has been received (has_leader_schedule), as
   before that ULONG_MAX only means "not initialized". */

FD_FN_CONST static inline int
fd_verify_blockhash_expires( ulong blockhash_slot,
                             ulong next_leader_slot ) {
  return blockhash_slot+FD_VERIFY_BLOCKHASH_AGE<next_leader_slot;
}

#endif /* HEADER_fd_src_disco_verify_fd_verify_tile_h */

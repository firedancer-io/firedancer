#ifndef HEADER_fd_src_disco_tiles_h
#define HEADER_fd_src_disco_tiles_h

#include "stem/fd_stem.h"
#include "shred/fd_shredder.h"
#include "../ballet/shred/fd_shred.h"
#include "../flamenco/leaders/fd_leaders_base.h"
#include "pack/fd_pack.h"
#include "topo/fd_topo.h"
#include "bundle/fd_bundle_crank.h"
#include "../disco/metrics/generated/fd_metrics_pack.h"

#include <linux/filter.h>

struct fd_became_leader {
   ulong slot;

  /* Start and end time of the slot in nanoseconds (from
     fd_log_wallclock()). */
  long   slot_start_ns;
  long   slot_end_ns;

  /* An opaque pointer to a Rust Arc<Bank> object, which should only
     be used with fd_ext_* functions to execute transactions or drop
     the bank.  The ownership is complicated, but basically any bank
     tile that receives this frag has a strong refcnt to the bank and
     should release it when done, other tiles should ignore and never
     use the bank. */
  void const * bank;

  /* In Firedancer, we just pass around the bank_idx which has already
     been refcounted by the replay tile, rather than a bank pointer. */
  ulong bank_idx;

  /* The app-wide bank sequence number of the leader bank (the durable
     fork discriminator; bank_idx is reused, bank_seq is not).  Used by
     monitoring (the GUI) to key per-fork transaction history. */
  ulong bank_seq;

  /* The maximum number of microblocks that pack is allowed to put
     into the block. This allows PoH to accurately track and make sure
     microblocks do not need to be dropped. */
  ulong max_microblocks_in_slot;

  /* The number of ticks (effectively empty microblocks) that the PoH
     tile will put in the block.  This is used to adjust some pack
     limits. */
  ulong ticks_per_slot;

  ulong tick_duration_ns;

  /* The number of ticks that the PoH tile has skipped, but needs to
     publish to show peers they were skipped correctly.  This is used
     to adjust some pack limits. */
  ulong total_skipped_ticks;

  /* The number of hashes per tick.  This is used to update the
     parameter for the proof of history component in case it has
     changed. */
  ulong hashcnt_per_tick;

  /* The epoch of the slot for which we are becoming leader. */
  ulong epoch;

  /* The block height of the slot for which we are becoming leader. */
  ulong block_height;

  /* Consensus-critical cost limits for the slot we are becoming leader.
     These are typically unchanging, but may change after a feature
     activation. */
  struct {
    ulong slot_max_cost;
    ulong slot_max_vote_cost;
    ulong slot_max_write_cost_per_acct;
    ulong slot_max_allocated_data_per_block;
    ulong slot_max_data_shreds;
  } limits;

  /* Information from the accounts database as of the start of the slot
     determined by the bank above that is necessary to crank the bundle
     tip programs properly.  If bundles are not enabled (determined
     externally, but the relevant tiles should know), these fields are
     set to 0. */
  struct {
    fd_bundle_crank_tip_payment_config_t config[1];
    uchar                                tip_receiver_owner[32];
    uchar                                last_blockhash[32];
  } bundle[1];
};
typedef struct fd_became_leader fd_became_leader_t;

struct fd_rooted_bank {
  void * bank;
  ulong  slot;
};

typedef struct fd_rooted_bank fd_rooted_bank_t;

struct fd_completed_bank {
   ulong slot;
   ulong block_height;
   uchar hash[32];
};

typedef struct fd_completed_bank fd_completed_bank_t;

/* fd_txn_ns_dt contains nanosecond offsets for an executed solana
   transaction relative to the publish event by pack for its
   corresponding microblock.

   In Firedancer, these states align with the struct declaration order,
   but in Frankendancer the "check" phase happens before "load". */
struct __attribute__((packed)) fd_txn_ns_dt {
  float load_start;
  float check_start;
  float exec_start;
  float commit_start;
  float commit_end;
};

typedef struct fd_txn_ns_dt fd_txn_ns_dt_t;

/* fd_pack_vclock_t is a vector clock counting frags on each link pack
   sends towards PoH through (execle_poh for microblocks, pack_poh for
   done_packing).  It is used to order those frags.  PoH must not mix
   in a microblock before any microblock it conflicts with that executed
   earlier, or the accounts database changes would be misordered with
   respect to PoH and replay could fail.

   Pack only releases the account locks of a microblock once it has
   observed its execle tile go idle, so every microblock a new one
   conflicts with is among those pack has seen complete when it
   schedules the new one.  Pack records, for each source link, how many
   frags it had seen complete (execle_poh links, counted in pack_idx
   units, i.e. one per bundle transaction) or published (pack_poh, the
   done_packing count) at that point.  Motor counts the frags it has
   processed from each link, and holds a frag until it has processed
   at least that many from every link.  Each link is in order, so this
   is enough, and a microblock is never held behind one that was still
   executing when it was scheduled.

   done_packing waits for every frag pack sent before it, which is a
   prefix of pack_idx, so it needs no vector clock: motor holds it until
   the total count of frags processed reaches its pack_idx.
   Pack only schedules for the next slot after publishing done_packing,
   and microblocks depend on the done_packing count, so slots stay in
   order and no later frag can be counted early.  Counters are not reset
   between slots and wrap, so they are compared through their signed
   difference.

   done_packing counts pack_poh, execle[ i ] counts execle i's
   execle_poh link.  Only done_packing and the first execle_cnt entries
   of execle are live: they are the only ones copied
   (fd_pack_vclock_copy) or read, the others hold stale bytes from
   earlier frags. */

struct fd_pack_vclock {
  uint done_packing;
  uint execle[ FD_PACK_MAX_EXECLE_TILES ];
};
typedef struct fd_pack_vclock fd_pack_vclock_t;

/* fd_pack_vclock_copy copies the live entries of src to dst. */

static inline void
fd_pack_vclock_copy( fd_pack_vclock_t *       dst,
                     fd_pack_vclock_t const * src,
                     ulong                    execle_cnt ) {
  fd_memcpy( dst, src, offsetof( fd_pack_vclock_t, execle ) + execle_cnt*sizeof(uint) );
}

/* fd_pack_vclock_covers returns 1 if seen, the frags processed so far
   from each link, covers the live entries of deps, and 0 otherwise. */

static inline int
fd_pack_vclock_covers( fd_pack_vclock_t const * seen,
                       fd_pack_vclock_t const * deps,
                       ulong                    execle_cnt ) {
  if( (int)(seen->done_packing-deps->done_packing)<0 ) return 0;
  for( ulong i=0UL; i<execle_cnt; i++ ) {
    if( (int)(seen->execle[ i ]-deps->execle[ i ])<0 ) return 0;
  }
  return 1;
}

/* fd_pack_vclock_total returns the number of frags counted by the live
   entries of v, modulo 2^32. */

static inline uint
fd_pack_vclock_total( fd_pack_vclock_t const * v,
                      ulong                    execle_cnt ) {
  uint total = v->done_packing;
  for( ulong i=0UL; i<execle_cnt; i++ ) total += v->execle[ i ];
  return total;
}

/* fd_pack_vclock_admit decides whether motor/poh can process now a
   microblock from execle execle_idx, carrying deps.  If so, it counts
   the frag in seen and returns 1.  Otherwise it returns 0 and the frag
   must be retried later.  Pack counted every earlier frag of the same
   execle in deps, so if seen is behind there, a frag was lost and the
   frag could never be processed. */

static inline int
fd_pack_vclock_admit( fd_pack_vclock_t *       seen,
                      fd_pack_vclock_t const * deps,
                      ulong                    execle_idx,
                      ulong                    execle_cnt ) {
  if( FD_UNLIKELY( (int)(seen->execle[ execle_idx ]-deps->execle[ execle_idx ])<0 ) ) {
    FD_LOG_ERR(( "microblock from execle %lu depends on %u earlier frags of that execle but only %u were received", execle_idx, deps->execle[ execle_idx ], seen->execle[ execle_idx ] ));
  }
  if( FD_UNLIKELY( !fd_pack_vclock_covers( seen, deps, execle_cnt ) ) ) return 0;
  seen->execle[ execle_idx ]++;
  return 1;
}

/* fd_pack_vclock_admit_done_packing is fd_pack_vclock_admit for a
   done_packing message, which waits for the pack_idx frags pack sent
   before it.  Microblocks of the next slot wait for this done_packing,
   so processing more than pack_idx frags first means one was lost. */

static inline int
fd_pack_vclock_admit_done_packing( fd_pack_vclock_t * seen,
                                   uint               pack_idx,
                                   ulong              execle_cnt ) {
  uint total = fd_pack_vclock_total( seen, execle_cnt );
  if( FD_UNLIKELY( (int)(total-pack_idx)>0 ) ) {
    FD_LOG_ERR(( "done_packing with pack_idx %u received after %u frags were processed", pack_idx, total ));
  }
  if( FD_UNLIKELY( total!=pack_idx ) ) return 0;
  seen->done_packing++;
  return 1;
}

struct fd_microblock_trailer {
  /* The hash of the transactions in the microblock, ready to be
     mixed into PoH. */
  uchar hash[ 32UL ];

   /* A sequentially increasing index of the first transaction in the
     microblock, across all slots ever processed by pack.  This is used
     by monitoring tools that maintain an ordered history of
     transactions. */
  ulong pack_txn_idx;

  /* The tips included in the transaction, in lamports. 0 for non-bundle
     transactions */
  ulong tips;

  /* The app-wide bank sequence number of the bank this microblock was
     executed against (the durable fork discriminator).  Used by
     monitoring (the GUI) to key per-fork transaction history. */
  ulong bank_seq;

  fd_txn_ns_dt_t txn_ns_dt;

  /* When the exec tile began executing this microblock (for a bundle,
     the bundle start) and when its transaction finished committing
     (LONG_MAX if nothing committed). */
  long exec_start_ticks;
  long exec_end_ticks;

  /* Frags PoH must process before this one, copied from the execle
     trailer.  See fd_pack_vclock_t. */
  fd_pack_vclock_t deps;
};
typedef struct fd_microblock_trailer fd_microblock_trailer_t;

/* Sentinel sig values for messages on the pack_poh.  Normal
   done_packing messages use fd_disco_execle_sig( slot, pack_idx ). */
#define FD_PACK_MSG_DONE_DRAINING   (ULONG_MAX)
#define FD_PACK_MSG_REDUCE_MB_BOUND (ULONG_MAX-1UL)

#define FD_PACK_END_SLOT_REASON_TIME       (1)
#define FD_PACK_END_SLOT_REASON_MICROBLOCK (2)
#define FD_PACK_END_SLOT_REASON_ABANDONED  (3)

struct fd_done_packing {
  ulong microblocks_in_slot;

  fd_pack_limits_usage_t limits_usage[ 1 ];
  fd_pack_limits_t limits[ 1 ];

  ulong block_results    [ FD_METRICS_COUNTER_PACK_TXN_SCHEDULE_ATTEMPTED_CNT ];
  ulong end_block_results[ FD_METRICS_COUNTER_PACK_TXN_SCHEDULE_ATTEMPTED_CNT ];

  fd_pack_smallest_t pending_smallest[ 1 ];
  fd_pack_smallest_t pending_votes_smallest[ 1 ];

  int end_slot_reason;

  long  pack_start_ns;
  long  pack_end_ns;
  ulong bundle_txn_count;
};
typedef struct fd_done_packing fd_done_packing_t;

struct fd_microblock_execle_trailer {
  /* An opaque pointer to the bank to use when executing and committing
     transactions.  The lifetime of the bank is owned by the PoH tile,
     which guarantees it is valid while pack or bank tiles might be
     using it. */
  void const * bank;

  /* In full Firedancer we just pass an index of the bank in a pool of
     banks.  The lifetime is fully managed by the replay tile, which has
     given us a refcount while we are leader for this bank.  bank value
     above will be NULL. */
  ulong bank_idx;

  /* The app-wide bank sequence number of the leader bank (the durable
     fork discriminator; bank_idx is reused, bank_seq is not).  Used by
     monitoring (the GUI) to key per-fork transaction history. */
  ulong bank_seq;

  /* The sequentially increasing index of the microblock in the slot,
     across all execles. */
  ulong microblock_idx;
  uint  pack_idx;

  /* Frags PoH must process before this microblock.  See
     fd_pack_vclock_t. */
  fd_pack_vclock_t deps;

  /* A sequentially increasing index of the first transaction in the
     microblock, across all slots ever processed by pack.  This is used
     by monitoring tools that maintain an ordered history of
     transactions. */
  ulong pack_txn_idx;

  /* If the microblock is a bundle, with a set of potentially
     conflicting transactions that should be executed in order, and
     all either commit or fail atomically. */
  int is_bundle;
};
typedef struct fd_microblock_execle_trailer fd_microblock_execle_trailer_t;

/* Exact worst-case frag sizes for the pack_execle and execle_poh
   links.  execle strips the ALT accounts from each fd_txn_e_t before
   forwarding to poh, so the poh side is smaller. */
#define FD_PACK_EXECLE_MTU (MAX_TXN_PER_MICROBLOCK*sizeof(fd_txn_e_t)+sizeof(fd_microblock_execle_trailer_t))
#define FD_EXECLE_POH_MTU  (MAX_TXN_PER_MICROBLOCK*sizeof(fd_txn_p_t)+sizeof(fd_microblock_trailer_t))

#endif /* HEADER_fd_src_disco_tiles_h */

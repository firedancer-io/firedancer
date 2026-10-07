#include <stdio.h> /* for vsnprintf */
#include <stdarg.h> /* for va_list */

#include "fd_sched.h"
#include "fd_sched_lthash.h"
#include "../../flamenco/alpenglow/fd_block_marker_serde.h"
#include "fd_execrp.h" /* for poh hash value */
#include "../../ballet/sha256/fd_sha256.h"
#include "../../disco/fd_disco_base.h" /* for FD_MAX_TXN_PER_SLOT_SHRED */
#include "../../disco/fd_txn_p.h"
#include "../../disco/metrics/fd_metrics.h" /* for fd_metrics_convert_ticks_to_nanoseconds and etc. */
#include "../../disco/pack/fd_chkdup.h"
#include "../../disco/shred/fd_shredder.h" /* FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ */
#include "../../flamenco/runtime/fd_runtime.h" /* for fd_runtime_load_txn_address_lookup_tables */
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_slot_hashes.h" /* for ALUTs */

#define FD_SCHED_MAX_STAGING_LANES_LOG     (2)
#define FD_SCHED_MAX_STAGING_LANES         (1UL<<FD_SCHED_MAX_STAGING_LANES_LOG)
#define FD_SCHED_MAX_PRINT_BUF_SZ          (2UL<<20)
#define FD_SCHED_POISON_MAX_ACCT_PER_SLOT  (64UL)

/* 64 ticks per slot, and a single gigantic microblock containing min
   size transactions. */
FD_STATIC_ASSERT( FD_MAX_TXN_PER_SLOT_SHRED==((FD_SHRED_DATA_PAYLOAD_MAX_PER_SLOT-65UL*sizeof(fd_microblock_hdr_t))/FD_TXN_MIN_SERIALIZED_SZ), max_txn_per_slot_shred );

/* We size the buffer to be able to hold residual data from the previous
   FEC set that only becomes parseable after the next FEC set is
   ingested, as well as the incoming FEC set.  The largest minimally
   parseable unit of data is a transaction.  So that much data may
   straddle FEC set boundaries.  Other minimally parseable units of data
   include the microblock header and the microblock count within a
   batch. */
#define FD_SCHED_MAX_PAYLOAD_PER_FEC       (63985UL)
FD_STATIC_ASSERT( FD_SCHED_MAX_PAYLOAD_PER_FEC>=FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ, bump sched fec size bound ); /* FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ is the bound we want, but older ledgers have larger FEC sets. */
#define FD_SCHED_MAX_RESIDUAL_SZ           (FD_TXN_MTU>FD_BLOCK_MARKER_SER_MAX ? FD_TXN_MTU : FD_BLOCK_MARKER_SER_MAX)
#define FD_SCHED_MAX_FEC_BUF_SZ            (FD_SCHED_MAX_PAYLOAD_PER_FEC+FD_SCHED_MAX_RESIDUAL_SZ)
FD_STATIC_ASSERT( FD_SCHED_MAX_RESIDUAL_SZ>=sizeof(fd_microblock_hdr_t), resize buffer for residual data );
FD_STATIC_ASSERT( FD_SCHED_MAX_RESIDUAL_SZ>=sizeof(ulong),               resize buffer for residual data );

#define FD_SCHED_MAX_TXN_PER_FEC           ((FD_SCHED_MAX_PAYLOAD_PER_FEC-1UL)/FD_TXN_MIN_SERIALIZED_SZ+1UL) /* 478 */
#define FD_SCHED_MAX_MBLK_PER_FEC          ((FD_SCHED_MAX_PAYLOAD_PER_FEC-1UL)/sizeof(fd_microblock_hdr_t)+1UL) /* 1334 */

FD_STATIC_ASSERT( FD_SCHED_MIN_DEPTH>=FD_SCHED_MAX_TXN_PER_FEC, limits );
FD_STATIC_ASSERT( FD_SCHED_MAX_DEPTH<=FD_RDISP_MAX_DEPTH,       limits );
FD_STATIC_ASSERT( FD_SCHED_MAX_DEPTH<=UINT_MAX,                 txn_idx_width );

#define FD_SCHED_MAX_POH_HASHES_PER_TASK   (4096UL) /* This seems to be the sweet spot. */

/* Out-of-band LtHash.

   The dispatcher sizes its account pool from the depth, and every
   account waiting for an addition pseudo transaction pins an entry in
   it, up to FD_RDISP_MAX_WRITERS_PER_BLOCK per lane, on top of what
   live transactions reference.  So the depth is inflated by enough
   number of transactions to account for pseudo transactions and that
   many entries are held back from FEC ingest.

   The speculation pool holds the values of speculative additions so a
   later intra-block rewrite can undo the addition.  Speculation stops
   when this pool gets full.  There is a threshold for free speculation
   entries per exec tile before a deactivated block is activated to
   engage in speculation.   This is meant to reduce churn. */
#define FD_SCHED_LTHASH_RESERVE  ((FD_SCHED_MAX_STAGING_LANES*FD_RDISP_MAX_WRITERS_PER_BLOCK+FD_RDISP_MAX_ACCT_PER_TXN-1UL)/FD_RDISP_MAX_ACCT_PER_TXN)
#define FD_SCHED_LTHASH_SPEC_MAX (8192UL)
#define FD_SCHED_LTHASH_SPEC_THRESHOLD_PER_TILE (2UL)
/* While a transaction of the block is in flight, a batch carries at
   most this many accounts, so that the tile it takes is free again
   soon.  Otherwise, a batch is allowed to carry up to
   FD_SCHED_LTHASH_BATCH_MAX accounts.  The one exception is an addition
   batch that fills to FD_SCHED_LTHASH_BATCH_MAX inside a poll, in which
   case the batch will go out even to the last idle exec tile, since the
   next poll could pop an addition with no room to batch it. */
#define FD_SCHED_LTHASH_BATCH_BUSY_MAX (8UL)
#define FD_SCHED_LTHASH_DRAIN_CHUNK (64UL)
/* A released lane map is cleared this many entries at a time when
   appropriate. */
#define FD_SCHED_LTHASH_CLEAN_CHUNK (64UL)
FD_STATIC_ASSERT( FD_SCHED_LTHASH_LANE_CNT==FD_SCHED_MAX_STAGING_LANES, lanes );
FD_STATIC_ASSERT( FD_SCHED_LTHASH_BATCH_MAX>=1UL && FD_SCHED_LTHASH_BATCH_MAX<=FD_EXECRP_LTHASH_BATCH_MAX, lthash_batch );
FD_STATIC_ASSERT( FD_SCHED_LTHASH_BATCH_BUSY_MAX>=1UL && FD_SCHED_LTHASH_BATCH_BUSY_MAX<=FD_SCHED_LTHASH_BATCH_MAX, lthash_batch_busy_max );

#define FD_SCHED_MAGIC (0xace8a79c181f89b6UL) /* echo -n "fd_sched_v0" | sha512sum | head -c 16 */

struct fd_sched_mblk {
  ulong start_txn_idx; /* inclusive parse idx */
  ulong end_txn_idx;   /* non-inclusive parse idx */
  ulong curr_txn_idx;  /* next txn to mixin, parse idx in block */
  ulong hashcnt;       /* number of pure hashes, excluding final mixin */
  ulong curr_hashcnt;
  fd_hash_t end_hash[ 1 ];
  fd_hash_t curr_hash[ 1 ];
  uint curr_sig_cnt;
  uint next;
  uint mixin_txn_idx; /* rdisp pool idx of the next txn to mixin */
  int is_tick;
};
typedef struct fd_sched_mblk fd_sched_mblk_t;

#define SLIST_NAME  mblk_slist
#define SLIST_ELE_T fd_sched_mblk_t
#define SLIST_IDX_T uint
#define SLIST_NEXT  next
#include "../../util/tmpl/fd_slist.c"

#define SET_NAME txn_bitset
#define SET_MAX  FD_SCHED_MAX_DEPTH
#include "../../util/tmpl/fd_set.c"

struct fd_sched_block {
  ulong               slot;
  ulong               parent_slot;
  ulong               parent_idx;  /* Index of the parent in the pool. */
  ulong               child_idx;   /* Index of the left-child in the pool. */
  ulong               sibling_idx; /* Index of the right-sibling in the pool. */

  /* Counters. */
  uint                txn_parsed_cnt;
  /*                  txn_queued_cnt = txn_parsed_cnt-txn_in_flight_cnt-txn_done_cnt */
  uint                txn_exec_in_flight_cnt;
  uint                txn_exec_done_cnt;
  uint                txn_sigverify_in_flight_cnt;
  uint                txn_sigverify_done_cnt;
  uint                poh_hashing_in_flight_cnt; /* number of in-flight PoH batch tasks */
  uint                poh_mblk_in_flight_cnt;    /* number of individual in-flight PoH jobs across batches */
  uint                poh_hashing_done_cnt;
  uint                poh_hash_cmp_done_cnt; /* poh_hashing_done_cnt==poh_hash_cmp_done_cnt+len(mixin_in_progress) */
  uint                cert_in_flight_cnt;    /* in-flight footer cert verify tasks, see fd_sched_cert_dispatch */
  uint                txn_done_cnt; /* A transaction is considered done when all types of tasks associated with it are done. */
  uint                shred_cnt;
  uint                shred_scan_idx; /* First shred boundary not before shred_scan_off. */
  uint                shred_scan_off; /* Block byte offset at the start of shred_scan_idx. */
  uint                mblk_cnt;          /* Total number of microblocks, including ticks and non ticks.
                                            mblk_cnt==len(unhashed)+len(hashing_in_progress)+poh_mblk_in_flight_cnt+len(mixin_in_progress)+hash_cmp_done_cnt */
  uint                mblk_tick_cnt;     /* Total number of tick microblocks. */
  uint                mblk_freed_cnt;    /* This is ==hash_cmp_done_cnt in most cases, except for aborted
                                            blocks, where the freed cnt will catch up to mblk_cnt and surpass
                                            hash_cmp_done_cnt when the block is reaped. */
  uint                mblk_unhashed_cnt; /* ==len(unhashed) */
  ulong               hashcnt; /* How many hashes this block wants replay to do.  A mixin/record counts as one hash. */
  ulong               txn_pool_max_popcnt;   /* Peak transaction pool occupancy during the time this block was replaying. */
  ulong               mblk_pool_max_popcnt;  /* Peak mblk pool occupancy. */
  ulong               block_pool_max_popcnt; /* Peak block pool occupancy. */
  uint                txn_idx_tail;           /* Most recently parsed rdisp pool index. */
  uint                txn_sigverify_next_idx; /* Next rdisp pool index to dispatch for sigverify, or 0 if caught up. */
  uint                parse_mblk_idx;         /* mblk pool index currently receiving parsed transactions. */

  /* Out-of-band LtHash.

     When the block has claim on the lane map, each entry in the map
     corresponds to one subtraction for the block.

       entries_cnt==sub_queued_cnt+sub_in_flight_cnt+sub_applied_cnt

     Additions the block owes but has no pseudo transaction for yet are

       add_owed_cnt

     While we don't track first writes on a per-block basis, which each
     puts an addition on the owed side, they balance out with other
     counters as follows.

       first_write_cnt==add_owed_cnt+add_created_cnt

     Unsurfaced additions that rdisp has been instructed to create but
     hasn't handed back to us via next_ready() are

       add_created_cnt-add_surfaced_cnt

     In-flight additions, including those staged in a batch and not yet
     dispatched, are

       add_surfaced_cnt-add_done_cnt

     Additions completed without a hash, or whose hash was dropped,
     because their account was written again within the same block are

       add_stale_cnt==add_done_cnt-add_applied_cnt

     The net number of additions absorbed by the block's delta is

       add_applied_cnt-add_undone_cnt

     At BLOCK_END every entry has been subtracted and added exactly once.

       sub_applied_cnt==add_applied_cnt-add_undone_cnt==entries_cnt */
  uint                lthash_in_flight_cnt; /* Task count, could be either add or sub. */
  uint                sub_q_head;        /* UINT_MAX if empty.  Linked through entry->q_next. */
  uint                sub_q_tail;
  uint                sub_queued_cnt;
  uint                sub_in_flight_cnt;
  uint                sub_applied_cnt;
  uint                add_owed_cnt;      /* First writes whose addition pseudo transaction is not created yet. */
  uint                add_created_cnt;   /* Addition pseudo transactions that we've instructed rdisp to create and queue up, for owed additions or extras. */
  uint                add_surfaced_cnt;  /* Returned by fd_rdisp_get_next_ready.  Will be either dispatched or completed on the spot. */
  uint                add_done_cnt;      /* fd_rdisp_complete_txn issued for pseudo transactions, with or without a dispatched hashing. */
  uint                add_applied_cnt;   /* Addition results rolled into the block's delta. */
  uint                add_undone_cnt;    /* Applied additions rolled back due to a subsequent account rewrite. */

  /* PoH verify. */
  fd_hash_t    poh_hash[ 1 ]; /* running end_hash of last parsed mblk */
  int          last_mblk_is_tick;
  mblk_slist_t mblks_unhashed[ 1 ]; /* A microblock, once parsed out, is in one of these queues.  It
                                       generally progresses from unhashed to hashing to mixin.  When a
                                       microblock is being hashed/in-flight, it'll be transiently out of
                                       any of the queues.  Once a microblock progresses through all stages
                                       of work, it'll be immediately freed. */
  mblk_slist_t mblks_hashing_in_progress[ 1 ];
  mblk_slist_t mblks_mixin_in_progress[ 1 ];
  uchar bmtree_mem[ FD_BMTREE_COMMIT_FOOTPRINT(0) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_commit_t * bmtree;
  ulong tick_hashcnt_wmk;  /* All ticks in a valid block must accumulate the same number of
                              hashes since the previous tick, or since block start, and this hash
                              count must match hashes_per_tick for the block. */
  ulong curr_tick_hashcnt; /* Starts at 0, accumulates hashcnt, resets to 0 on the next tick. */
  ulong tick_height;       /* Block is built off of a parent block with this many ticks. */
  ulong max_tick_height;   /* Block should end with precisely this many ticks. */
  ulong hashes_per_tick;   /* Fixed per block, feature gated, known after bank clone. */
  int inconsistent_hashes_per_tick;
  int zero_hash_tick;

  /* Parser state. */
  uchar               txn[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  ulong               mblks_rem;    /* Number of microblocks remaining in the current batch. */
  ulong               txns_rem;     /* Number of transactions remaining in the current microblock. */
  uint                fec_buf_sz;   /* Size of the fec_buf in bytes. */
  uint                fec_buf_soff; /* Starting offset into fec_buf for unparsed transactions. */
  uint                fec_buf_boff; /* Byte offset into raw block data of the first byte currently in fec_buf */
  uint                poison_cnt;   /* [0, FD_SCHED_POISON_MAX_ACCT_PER_SLOT) */
  fd_acct_addr_t      poison[ FD_SCHED_POISON_MAX_ACCT_PER_SLOT ]; /* Poison set to handle loader v3 implied programdata accounts.

                                                                      A transaction that lists a loader v3 program account P is charged
                                                                      for, and gated on, P's implicit programdata account PD, which the
                                                                      transaction does not have to declare.  The dispatcher therefore
                                                                      establishes no dependency for said transaction against a
                                                                      transaction that writes PD without also touching P, for example a
                                                                      simple lamports transfer into PD, or a Close on an Unintialized PD.
                                                                      Every loader v3 instruction that changes a live PD's size or
                                                                      liveness (from alive to dead) does write lock P (except for the
                                                                      aforementioned Close on Unintialized PD).  Simple transfers cannot
                                                                      debit PD since it's a PDA.

                                                                      So, when a loader v3 instruction that could modify PD is inserted,
                                                                      its writable accounts are added to a poison set, and any later
                                                                      transaction that writes a set member is inserted serializing.  That
                                                                      sequences the unordered writer of PD against any implied use of PD
                                                                      for the rest of the block.  This allows the runtime to treat the
                                                                      current fork's view of PD as stable.

                                                                      Note that this does not cover the case where the poisoning
                                                                      transaction (with the PD-modifying loader v3 instruction) and the
                                                                      PD-only transactions do not land in the same block.  Non-determinism
                                                                      between the PD-only transaction and an implied PD transaction in
                                                                      that case is a protocol bug. */
  long                fec_completed_ns; /* Network arrival (wallclock ns) of the FEC set being ingested; txns
                                           parse out only once the FEC completing their bytes arrives, so this
                                           is stamped on every txn parsed during the current ingest. */
  uint                poison_serialize:1; /* Serialize everything in the rest of the block.  Set when the poison
                                             set overflows or we couldn't maintain the poison property for any
                                             other reason. */
  uint                fec_eob:1;    /* FEC end-of-batch: set if the last FEC set in the batch is being
                                       ingested. */
  uint                fec_sob:1;    /* FEC start-of-batch: set if the parser expects to be parsing out a
                                       batch header. */

  /* Block state. */
  uint                fec_eos:1;                          /* FEC end-of-stream: set if the last FEC set in the block has been
                                                             ingested. */
  uint                rooted:1;                           /* Set if the block is rooted. */
  uint                dying:1;                            /* Set if the block has been abandoned and no transactions should be
                                                             scheduled from it. */
  uint                discarded:1;                        /* Set if the block went down with a discarded (not invalid) lineage:
                                                             its own discard or an ancestor's.  This field, along with
                                                             dead_reason, can be in one of three possible combinations when a
                                                             block is dead:

                                                             dead_reason!=DEAD_ANCESTOR, discarded initialized to 0: invalid block due to dead_reason
                                                             dead_reason==DEAD_ANCESTOR, discarded==0: invalid lineage
                                                             dead_reason==DEAD_ANCESTOR||NONE, discarded==1: discarded lineage */
  uint                refcnt:1;                           /* Starts at 1 when the block is added, set to 0 if caller has been
                                                             informed to decrement refcnt for sched. */
  uint                in_sched:1;                         /* Set if the block is being tracked by the scheduler. */
  uint                in_rdisp:1;                         /* Set if the block is being tracked by the dispatcher, either as staged
                                                             or unstaged. */
  uint                block_start_signaled:1;             /* Set if the start-of-block sentinel has been dispatched. */
  uint                block_end_signaled:1;               /* Set if the end-of-block sentinel has been dispatched. */
  uint                block_start_done:1;                 /* Set if the start-of-block processing has been completed. */
  uint                block_end_done:1;                   /* Set if the end-of-block processing has been completed. */
  uint                staged:1;                           /* Set if the block is in a dispatcher staging lane; a staged block is
                                                             tracked by the dispatcher. */
  uint                lthash_oob:1;                       /* Copy of sched->lthash_oob. */
  uint                lthash_drained:1;                   /* Set if fec_eos AND something equivalent to
                                                             fd_rdisp_add_all_pseudo_txn() has been done since fec_eos.  That is
                                                             to say, every writable account has an addition pseudo transaction
                                                             that will capture its final value. */
  uint                lthash_draining:1;                  /* Counted in sched->lthash_draining_cnt. */
  ulong               staging_lane;                       /* Ignored if staged==0. */
  ulong               luf_depth;                          /* Depth of longest unstaged fork starting from this node; only
                                                             stageable unstaged descendants are counted. */
  int                 dead_reason;                        /* One of FD_SCHED_DEAD_REASON_*; records the first reason the block
                                                             was ruled invalid (set-once via record_dead_reason), NONE otherwise. */
  uchar               fec_buf[ FD_SCHED_MAX_FEC_BUF_SZ ]; /* The previous FEC set could have some residual data that only becomes
                                                             parseable after the next FEC set is ingested. */

  /* Alpenglow block footer, deserialized out of the marker batch at
     parse time.  footer_seen is set if the block carries a footer
     marker and it is seen by sched; footer is only meaningful in that
     case. */
  fd_block_footer_t footer;

  /* Alpenglow block structure, mirroring agave's BlockComponentStage
     as a set of "seen" flags.  Only maintained when sched->is_alpenglow.
     Together with mblk_cnt they determine what may come next:

       agave stage               header footer alpentick mblk_cnt
       PreParentMarker             0      0       0        0
       AcceptingGenesisOrEntries   1      0       0        0     (and no genesis cert yet)
       AcceptingEntriesOrFooter    1      0       0        *
       AcceptingAlpentick          1      1       0        *
       Done                        1      1       1        *      */
  int header_seen;
  int genesis_cert_seen;
  int update_parent_seen;
  int footer_seen;
  int alpentick_seen;
};
typedef struct fd_sched_block fd_sched_block_t;

FD_STATIC_ASSERT( sizeof(fd_sched_mblk_t)==120UL, fd_sched_mblk );
FD_STATIC_ASSERT( sizeof(fd_sched_txn_info_t)==192UL, fd_sched_txn_info );
FD_STATIC_ASSERT( sizeof(fd_sched_block_t)==75872UL, fd_sched_block );
FD_STATIC_ASSERT( sizeof(fd_hash_t)==sizeof(((fd_microblock_hdr_t *)0)->hash), unexpected poh hash size );


struct fd_sched_metrics {
  uint  block_added_cnt;
  uint  block_added_staged_cnt;
  uint  block_added_unstaged_cnt;
  uint  block_added_dead_ood_cnt;
  uint  block_removed_cnt;
  uint  block_abandoned_cnt;
  uint  block_bad_cnt;
  uint  block_promoted_cnt;
  uint  block_demoted_cnt;
  uint  deactivate_no_child_cnt;
  uint  deactivate_no_txn_cnt;
  uint  deactivate_pruned_cnt;
  uint  deactivate_abandoned_cnt;
  uint  lane_switch_cnt;
  uint  lane_promoted_cnt;
  uint  lane_demoted_cnt;
  uint  fork_observed_cnt;
  uint  alut_success_cnt;
  uint  alut_serializing_cnt;
  uint  poison_latch_overflow_cnt;
  uint  poison_latch_alt_cnt;
  uint  poison_cnt_wmk;
  uint  txn_poison_serializing_cnt;
  uint  txn_poisoned_cnt;
  uint  txn_abandoned_parsed_cnt;
  uint  txn_abandoned_exec_done_cnt;
  uint  txn_abandoned_done_cnt;
  uint  txn_max_in_flight_cnt;
  ulong txn_weighted_in_flight_cnt;
  ulong txn_weighted_in_flight_tickcount;
  ulong txn_none_in_flight_tickcount;
  ulong txn_parsed_cnt;
  ulong txn_exec_done_cnt;
  ulong txn_sigverify_done_cnt;
  ulong txn_mixin_done_cnt;
  ulong txn_done_cnt;
  ulong mblk_parsed_cnt;
  ulong mblk_poh_hashed_cnt;
  ulong mblk_poh_done_cnt;
  ulong bytes_ingested_cnt;
  ulong bytes_ingested_unparsed_cnt;
  ulong bytes_dropped_cnt;
  ulong fec_cnt;

  /* Out-of-band LtHash.  sum(x) sums per-block counter x over the
     blocks in the scheduler.  The lthash_discarded_* counters are for
     what abandon and demotion throw away.  We expect the following
     invariants.

     Writes observed, by source, and what the dispatcher made of each.
     A given up speculation puts its account back as written, so it is a
     source too:
       lthash_parsed_writable_cnt+lthash_start_reg_cnt+lthash_late_reg_cnt+lthash_demote_reg_cnt+lthash_spec_given_up_cnt==lthash_first_write_cnt+lthash_coalesced_cnt

     Sometimes rdisp reports a write as the account's first write since
     its last addition pseudo transaction.  It makes the block owe the
     account one addition, which a drain or a speculation will get going
     later.  Writes in between coalesce into that owed addition, which
     is the add-add coalescing rdisp provides:
       lthash_first_write_cnt==lthash_add_created_cnt+sum(add_owed_cnt)+lthash_discarded_add_owed_cnt

     Additions.  A surfaced addition sits in sched->lthash_add_batch
     until its batch reaches a tile, so the held batch is a term:
       lthash_add_created_cnt==lthash_add_surfaced_cnt+sum(add_created_cnt-add_surfaced_cnt)+lthash_discarded_add_pending_cnt
       lthash_add_surfaced_cnt==lthash_add_surfaced_stale_cnt+lthash_spec_given_up_cnt+lthash_add_dispatched_cnt+(held additions)+lthash_discarded_add_held_cnt
       lthash_add_dispatched_cnt==lthash_add_dispatched_stale_cnt+lthash_add_applied_cnt+(in-flight additions)
       lthash_add_applied_cnt-lthash_add_undone_cnt==lthash_frozen_cnt+sum(add_applied_cnt-add_undone_cnt)+lthash_discarded_add_applied_cnt

     Subtractions:
       lthash_entry_cnt==lthash_sub_dispatched_cnt+sum(sub_queued_cnt)+lthash_discarded_sub_queued_cnt
       lthash_sub_dispatched_cnt==lthash_sub_applied_cnt+(in-flight subtractions)
       lthash_sub_applied_cnt==lthash_frozen_cnt+sum(sub_applied_cnt)+lthash_discarded_sub_applied_cnt

     Speculation: lthash_spec_cnt of the additions were guesses.  Once
     the blocks finish, lthash_spec_applied_cnt-lthash_add_undone_cnt of
     them survive, lthash_spec_stale_cnt were invalidated before their
     hash applied, and lthash_spec_given_up_cnt were withdrawn before
     they reached a tile with no write involved.  The rest of the stale
     counts are drain additions invalidated by a registration that came
     after the drain.  Draining is a parse time operation, and the
     registrations that invalidate it could come from either
     start-of-block processing or ALT expansions.  The owed, pending and
     queued lthash_discarded_* counters come only from abandon, since a
     demotable block has nothing queued or unsurfaced and keeps its owed
     additions.  The two lthash_discarded_*_applied delta counters can
     come from either abandon or demotion. */
  ulong lthash_parsed_writable_cnt;       /* Declared writable accounts of parsed transactions.  ALT accounts of a transaction whose tables could not be expanded are not counted here, and instead count as late registrations. */
  uint  lthash_start_reg_cnt;             /* Accounts registered by start-of-block processing. */
  uint  lthash_late_reg_cnt;              /* Declared writable lookup table accounts registered at transaction completion. */
  uint  lthash_demote_reg_cnt;            /* Accounts put back into rdisp when their block was demoted.  A later promotion will drain these back out of rdisp.  Not really new writes. */
  ulong lthash_first_write_cnt;           /* Writes rdisp reported as the account's first since its last addition pseudo transaction. */
  ulong lthash_coalesced_cnt;             /* Writes to an account the block already owed an addition for. */
  ulong lthash_entry_cnt;                 /* Lane head account map entries inserted, each owing one subtraction. */
  ulong lthash_sub_dispatched_cnt;        /* Subtractions dispatched to a tile. */
  ulong lthash_sub_task_cnt;              /* Subtraction tasks dispatched to a tile, each a batch of the accounts lthash_sub_dispatched_cnt counts. */
  ulong lthash_sub_applied_cnt;           /* Subtractions rolled into a block's delta. */
  ulong lthash_add_created_cnt;           /* Addition pseudo transactions rdisp handed us. */
  ulong lthash_spec_cnt;                  /* Of those, speculatively created while the block was still receiving FEC sets. */
  ulong lthash_add_surfaced_cnt;          /* Pseudo transactions returned by fd_rdisp_get_next_ready(). */
  ulong lthash_add_surfaced_stale_cnt;    /* Of those, no longer the account's addition of record due to a rewrite.  We will complete these pseudo transactions without hashing. */
  ulong lthash_add_dispatched_cnt;        /* Additions dispatched to a tile. */
  ulong lthash_add_task_cnt;              /* Addition tasks dispatched to a tile, each a batch of the accounts lthash_add_dispatched_cnt counts. */
  ulong lthash_add_dispatched_stale_cnt;  /* Of those, rewritten while in flight.  We will drop the hashing result. */
  ulong lthash_add_batch_held_cnt;        /* Addition batches held because a transaction surfaced behind them, released by a stale addition completed in the same poll, or because a speculative addition went alone. */
  ulong lthash_add_batch_wait_idle_cnt;   /* Polls that left an addition batch held because of insufficient idle tile. */
  ulong lthash_add_applied_cnt;           /* Addition results rolled into a block's delta. */
  ulong lthash_add_undone_cnt;            /* Applied additions rolled back because the account was rewritten. */
  ulong lthash_spec_applied_cnt;          /* Of lthash_add_applied_cnt, speculative. */
  ulong lthash_spec_stale_cnt;            /* Speculations rewritten while PENDING or DISPATCHED, invalidated before they applied.  Applied speculations are not included here. */
  uint  lthash_spec_given_up_cnt;         /* Speculations that surfaced when the idleness policy would not let them onto a tile. */
  uint  lthash_pool_full_cnt;             /* Deactivations of a block that still owed additions, because the speculation pool had no free entry.  Such blocks have a chance to be activated if sufficient entries per exec tile are free again. */
  uint  lthash_spec_yield_cnt;            /* Deactivations of a block that could only speculate, because it's yielding to another lane head that has must-do work. */
  ulong lthash_frozen_cnt;                /* Number of accounts that were rolled into the final LtHash value of a successfully replayed block.  This does not include the handful of end-of-block account writes that are done in-band.  The scheduler only tracks out-of-band LtHash.  FIXME: counted when BLOCK_END completes, which is before replay_block_finalize gives its verdict, so a block whose bank is marked dead there (bad footer, footer bank hash mismatch) is counted as well. */
  uint  lthash_discarded_add_owed_cnt;    /* Additions owed by abandoned blocks.  Never created. */
  uint  lthash_discarded_add_pending_cnt; /* Pseudo transactions of abandoned blocks.  Never surfaced. */
  uint  lthash_discarded_add_held_cnt;    /* Additions of abandoned blocks batched behind a transaction.  Never on a tile. */
  uint  lthash_discarded_add_applied_cnt; /* Additions in the delta of an abandoned or demoted block, net of undone. */
  uint  lthash_discarded_sub_queued_cnt;  /* Subtractions of abandoned blocks.  Never dispatched. */
  uint  lthash_discarded_sub_applied_cnt; /* Subtractions in the delta of an abandoned or demoted block. */
  ulong lane_wait_cnt;
};
typedef struct fd_sched_metrics fd_sched_metrics_t;

/* A batch of LtHash entries of one block and one kind, either what a
   tile is actively hashing or the additions that have been staged but
   not yet dispatched.  A pseudo transaction is unreadable once it is
   completed, so we capture the values at batching. */
struct fd_sched_lthash_batch {
  ulong          bank_idx;
  ulong          cnt; /* In [0, FD_SCHED_LTHASH_BATCH_MAX] */
  uint           lane;
  uchar          kind;
  uint           entry_idx[ FD_SCHED_LTHASH_BATCH_MAX ]; /* Entries in the lane map. */
  uint           ptxn_idx [ FD_SCHED_LTHASH_BATCH_MAX ]; /* FD_RDISP_LTHASH_PSEUDO_TXN bit set.  0 for a subtraction. */
  fd_acct_addr_t accts    [ FD_SCHED_LTHASH_BATCH_MAX ];
};
typedef struct fd_sched_lthash_batch fd_sched_lthash_batch_t;
FD_STATIC_ASSERT( alignof(fd_sched_lthash_batch_t)==alignof(ulong), lthash_batch_align ); /* The layout places the records at alignof(ulong). */

#define DEQUE_NAME ref_q
#define DEQUE_T    ulong
#include "../../util/tmpl/fd_deque_dynamic.c"

struct fd_sched {
  fd_acct_addr_t        aluts[ 256 ]; /* Resolve ALUT accounts into this buffer for more parallelism. */
  char                  print_buf[ FD_SCHED_MAX_PRINT_BUF_SZ ];
  ulong                 print_buf_sz;
  ushort *              shred_sz;             /* Payload size of each ingested data shred, max_shreds_per_block per block pool idx. */
  ulong                 max_shreds_per_block; /* Immutable. */
  ulong                 max_txn_per_slot;     /* Immutable. */
  ulong                 max_mblk_per_slot;    /* Immutable, FD_SCHED_MAX_MBLK_PER_SLOT scaled with max_shreds_per_block. */
  fd_chkdup_t           chkdup[ 1 ];
  fd_sched_metrics_t    metrics[ 1 ];
  int                   is_alpenglow; /* set if alpenglow is enabled. */
  ulong                 canary; /* == FD_SCHED_MAGIC */
  ulong                 depth;         /* Immutable.  Pool depth, inflated by lthash_reserve. */
  ulong                 block_cnt_max; /* Immutable. */
  int                   lthash_oob;     /* Immutable.  Set if account LtHashes are computed out of band. */
  uint                  lthash_draining_cnt; /* Blocks with lthash_draining set, 0 unless lthash_oob. */
  ulong                 lthash_reserve; /* Immutable.  Pool entries held back from ingest for pseudo transactions, 0 unless lthash_oob. */
  ulong                 exec_cnt;      /* Immutable. */
  ulong                 poh_simd_min;  /* Immutable. */
  ulong                 poh_simd_max;  /* Immutable. */
  int                   bypass_poh_verify; /* Test/fuzz: skip the PoH end_hash compare in maybe_mixin. */
  int                   bypass_alut_resolution; /* Test/fuzz: skip ALUT resolution (no accdb). */
  long                  txn_in_flight_last_tick;
  long                  next_ready_last_tick;
  ulong                 next_ready_last_bank_idx;
  ulong                 root_idx;
  fd_rdisp_t *          rdisp;
  ulong                 txn_exec_ready_bitset[ 1 ];
  ulong                 sigverify_ready_bitset[ 1 ];
  ulong                 poh_ready_bitset[ 1 ];
  ulong                 cert_ready_bitset[ 1 ];
  ulong                 lthash_ready_bitset[ 1 ];
  ulong                 active_bank_idx; /* Index of the actively replayed block, or ULONG_MAX if no block is
                                            actively replayed; has to have a transaction to dispatch; staged
                                            blocks that have no transactions to dispatch are not eligible for
                                            being active. */
  ulong                 last_active_bank_idx;
  ulong                 staged_bitset;    /* Bit i set if staging lane i is occupied. */
  ulong                 staged_head_bank_idx[ FD_SCHED_MAX_STAGING_LANES ]; /* Head of the linear chain in each staging lane, ignored if bit i is
                                                                               not set in the bitset. */
  ulong                 staged_popcnt_wmk;
  ulong                 txn_pool_free_cnt;
  fd_txn_p_t *          txn_pool;      /* Just a flat array. */
  fd_sched_txn_info_t * txn_info_pool; /* Just a flat array. */
  fd_sched_mblk_t *     mblk_pool;     /* Just a flat array. */
  ulong                 mblk_pool_free_cnt;
  uint                  mblk_pool_free_head;
  ulong                 tile_to_bank_idx[ FD_SCHED_MAX_EXEC_TILE_CNT ]; /* Index of the bank that the exec tile is executing against. */
  fd_sched_poh_hash_t   poh_inflight[ FD_SCHED_MAX_EXEC_TILE_CNT ]; /* PoH dispatch metadata, indexed by exec tile. */
  fd_sched_lthash_batch_t * lthash_inflight;  /* What each tile is hashing, FD_SCHED_MAX_EXEC_TILE_CNT records indexed by exec tile; NULL unless lthash_oob. */
  fd_sched_lthash_batch_t * lthash_add_batch; /* Additions the next_ready poll surfaced and has not put on a tile, cnt 0 if none; NULL unless lthash_oob. */
  fd_sched_lthash_t *   lthash;       /* Per-lane account maps and the hash pool; NULL unless lthash_oob. */
  fd_lthash_value_t *   lthash_delta; /* Per-block delta, block_cnt_max entries indexed by bank_idx; NULL unless lthash_oob. */
  txn_bitset_t          exec_done_set[ txn_bitset_word_cnt ];      /* Indexed by txn_idx. */
  txn_bitset_t          sigverify_done_set[ txn_bitset_word_cnt ]; /* Indexed by txn_idx. */
  txn_bitset_t          poh_mixin_done_set[ txn_bitset_word_cnt ]; /* Indexed by txn_idx. */
  fd_sched_block_t *    block_pool; /* Just a flat array. */
  ulong                 block_pool_popcnt;
  ulong *               ref_q;
};
typedef struct fd_sched fd_sched_t;


/* Internal helpers. */

static int
verify_ticks_eager( fd_sched_block_t * block );

static int
verify_ticks_final( fd_sched_block_t * block );

static int
ag_on_final( fd_sched_block_t * block );

static void
add_block( fd_sched_t * sched,
           ulong        bank_idx,
           ulong        parent_bank_idx );

FD_WARN_UNUSED static int
fd_sched_parse( fd_sched_t * sched, fd_sched_block_t * block, fd_sched_alut_ctx_t * alut_ctx );

FD_WARN_UNUSED static int
fd_sched_parse_txn( fd_sched_t * sched, fd_sched_block_t * block, fd_sched_alut_ctx_t * alut_ctx );

static void
dispatch_sigverify( fd_sched_t * sched, fd_sched_block_t * block, ulong bank_idx, int exec_tile_idx, fd_sched_task_t * out );

static uint
shred_split( fd_sched_t *       sched,
             fd_sched_block_t * block,
             uint               query );

static void
dispatch_poh( fd_sched_t * sched, fd_sched_block_t * block, ulong bank_idx, int exec_tile_idx, ulong max_cnt, fd_sched_task_t * out );

static int
poh_retire_mblk( fd_sched_t * sched, fd_sched_block_t * block, uint mblk_idx );

static int
poh_retire_ready_mblks( fd_sched_t * sched, fd_sched_block_t * block );

static inline ulong
poh_batch_max_cnt( fd_sched_t const * sched, ulong queued_cnt, ulong free_cnt, ulong threshold ) {
  ulong tile_cnt = free_cnt-threshold;
  ulong per_tile = (queued_cnt+tile_cnt-1UL)/tile_cnt;
  ulong max_cnt  = fd_ulong_min( fd_ulong_max( per_tile, 1UL ), sched->poh_simd_max );
  return fd_ulong_if( max_cnt<sched->poh_simd_min, 1UL, max_cnt );
}

FD_WARN_UNUSED static int
maybe_mixin( fd_sched_t * sched, fd_sched_block_t * block );

static void
free_mblk( fd_sched_t * sched, fd_sched_block_t * block, uint mblk_idx ) {
  sched->mblk_pool[ mblk_idx ].next = sched->mblk_pool_free_head;
  sched->mblk_pool_free_head = mblk_idx;
  sched->mblk_pool_free_cnt++;
  block->mblk_freed_cnt++;
}

static void
free_mblk_slist( fd_sched_t * sched, fd_sched_block_t * block, mblk_slist_t * list ) {
  while( !mblk_slist_is_empty( list, sched->mblk_pool ) ) {
    uint idx = (uint)mblk_slist_idx_pop_head( list, sched->mblk_pool );
    free_mblk( sched, block, idx );
  }
}

static void
try_activate_block( fd_sched_t * sched );

static void
check_or_set_active_block( fd_sched_t * sched );

static void
subtree_abandon( fd_sched_t * sched, fd_sched_block_t * block );

static void
subtree_release_refcnt( fd_sched_t * sched, fd_sched_block_t * block );

static void
subtree_prune( fd_sched_t * sched, ulong bank_idx, ulong except_idx );

static void
maybe_switch_block( fd_sched_t * sched, ulong bank_idx );

static ulong
compute_longest_unstaged_fork( fd_sched_t * sched, ulong bank_idx );

static ulong
promote_from_longest_unstaged_fork( fd_sched_t * sched, ulong bank_idx, int lane_idx );

static int
lane_is_demotable( fd_sched_t * sched, int lane_idx );

static void
demote_lane( fd_sched_t * sched, int lane_idx );

static inline fd_sched_block_t *
block_pool_ele( fd_sched_t * sched, ulong idx ) {
  FD_TEST( idx<sched->block_cnt_max || idx==ULONG_MAX );
  return idx==ULONG_MAX ? NULL : sched->block_pool+idx;
}

FD_FN_UNUSED static inline int
block_is_void( fd_sched_block_t * block ) {
  /* We've seen everything in the block and no transaction got parsed
     out. */
  return block->fec_eos && block->txn_parsed_cnt==0;
}

/* Assumes that every serializing transaction has completed, so every
   late registration has happened. */
static inline int
block_lthash_settled( fd_sched_block_t * block ) {
  return !block->lthash_oob || ( block->lthash_drained && !block->sub_queued_cnt && !block->sub_in_flight_cnt && block->add_created_cnt==block->add_done_cnt );
}

static inline int
block_should_signal_end( fd_sched_block_t * block ) {
  /* Under the current policy of eager synchronous PoH mixin, hashing
     done plus fec_eos imply that all mixins have been done. */
  if( FD_UNLIKELY( !( !block->fec_eos || ((block->mblk_cnt==block->poh_hashing_done_cnt&&block->mblk_cnt==block->poh_hash_cmp_done_cnt)||block->mblk_cnt!=block->poh_hashing_done_cnt) ) ) ) FD_LOG_CRIT(( "invariant violation: slot %lu fec_eos %d mblk_cnt %u poh_hashing_done_cnt %u poh_hash_cmp_done_cnt %u", block->slot, block->fec_eos, block->mblk_cnt, block->poh_hashing_done_cnt, block->poh_hash_cmp_done_cnt ));
  return block->fec_eos && block->txn_parsed_cnt==block->txn_done_cnt && block->mblk_cnt==block->poh_hashing_done_cnt && block->block_start_done && !block->block_end_signaled && block_lthash_settled( block );
}

static inline int
block_will_signal_end( fd_sched_block_t * block ) {
  return block->fec_eos && !block->block_end_signaled;
}

/* Is there something known to be dispatchable in the block?  This is an
   important liveness property.  A block that doesn't contain any known
   dispatchable tasks will be deactivated or demoted.  The block
   boundary tests come first because they settle a complete or an
   unstarted block with one load each.  The replay tile asks this
   question of every staged block on every loop while a first FEC set
   waits for a lane, so this needs to be fast. */
static inline int
block_is_dispatchable( fd_sched_block_t * block ) {
  return !block->block_start_signaled ||
         block_will_signal_end( block ) ||
         block->txn_parsed_cnt-block->txn_exec_in_flight_cnt-block->txn_exec_done_cnt>0U || /* exec_queued_cnt */
         block->txn_parsed_cnt-block->txn_sigverify_in_flight_cnt-block->txn_sigverify_done_cnt>0U || /* sigverify_queued_cnt */
         block->mblk_cnt-block->poh_mblk_in_flight_cnt-block->poh_hashing_done_cnt>0U || /* poh_queued_cnt */
         block->sub_queued_cnt>0U ||
         block->add_created_cnt>block->add_surfaced_cnt;
}

/* Tasks of the block on exec tiles. */
static inline ulong
block_in_flight_cnt( fd_sched_block_t * block ) {
  return (ulong)block->txn_exec_in_flight_cnt + (ulong)block->txn_sigverify_in_flight_cnt + (ulong)block->poh_hashing_in_flight_cnt + (ulong)block->lthash_in_flight_cnt;
}

/* Unlike block_in_flight_cnt, this goes by the LtHash account counters,
   so an addition batch staged but not yet dispatched keeps the block in
   flight. */
static inline int
block_is_in_flight( fd_sched_block_t * block ) {
  return block->txn_exec_in_flight_cnt || block->txn_sigverify_in_flight_cnt || block->poh_hashing_in_flight_cnt || block->cert_in_flight_cnt || (block->block_end_signaled && !block->block_end_done)
      || block->sub_in_flight_cnt || block->add_surfaced_cnt>block->add_done_cnt;
}

static inline int
block_is_done( fd_sched_block_t * block ) {
  return block->fec_eos && block->txn_parsed_cnt==block->txn_done_cnt && block->mblk_cnt==block->poh_hash_cmp_done_cnt && block->block_start_done && block->block_end_done && !block->cert_in_flight_cnt;
}

static inline int
block_is_stageable( fd_sched_block_t * block ) {
  int rv = !block_is_done( block ) && !block->dying;
  if( FD_UNLIKELY( rv && !block->in_rdisp ) ) {
    /* Invariant: stageable blocks may be currently staged or unstaged,
       but must be in the dispatcher either way.  When a block
       transitions to DONE, it will be immediately removed from the
       dispatcher.  When a block transitions to DYING, it will be
       eventually abandoned from the dispatcher. */
    FD_LOG_CRIT(( "invariant violation: stageable block->in_rdisp==0, txn_parsed_cnt %u, txn_done_cnt %u, fec_eos %u,, slot %lu, parent slot %lu",
                  block->txn_parsed_cnt, block->txn_done_cnt, (uint)block->fec_eos, block->slot, block->parent_slot ));
  }
  return rv;
}

static inline int
block_is_promotable( fd_sched_block_t * block ) {
  return block_is_stageable( block ) && block_is_dispatchable( block ) && !block->staged;
}

static inline int
block_is_demotable( fd_sched_block_t * block ) {
  /* A block can only be demoted from rdisp if it is empty, meaning no
     PENDING, READY, or DISPATCHED transactions.  This is equivalent to
     having no in-flight transactions (DISPATCHED) and no queued
     transactions (PENDING or READY).  This function actually implements
     a stronger requirement.  We consider a block demotable only if
     there are no in-flight or queued tasks of any kind. */
  return block->staged && !block_is_dispatchable( block ) && !block_is_in_flight( block );
}

static inline int
block_is_activatable( fd_sched_block_t * block ) {
  return block_is_stageable( block ) && block_is_dispatchable( block ) && block->staged;
}

static inline ulong
block_to_idx( fd_sched_t * sched, fd_sched_block_t * block ) { return (ulong)(block-sched->block_pool); }

static inline int
block_is_lane_head( fd_sched_t * sched, fd_sched_block_t * block ) {
  return block->staged && sched->staged_head_bank_idx[ block->staging_lane ]==block_to_idx( sched, block );
}

static inline int
block_is_lane_tail( fd_sched_t * sched, fd_sched_block_t * block ) {
  if( !block->staged ) return 0;
  fd_rdisp_staging_lane_info_t lane_info[ FD_SCHED_MAX_STAGING_LANES ];
  ulong occupied = fd_rdisp_staging_lane_info( sched->rdisp, lane_info );
  return fd_ulong_extract_bit( occupied, (int)block->staging_lane ) && lane_info[ block->staging_lane ].insert_ready_block==block_to_idx( sched, block );
}

/* Under out-of-band LtHash, a block with absolutely nothing to dispatch
   may still speculate on additions when it is the only block of its
   lane, it is still receiving FEC sets, it owes additions, and the
   speculation pool has at least spec_free_min free entries.  Only the
   active block speculates.  An already speculating block keeps going
   until the last free entry.  In contrast, deactivated blocks are
   activated for speculation only if a higher free entry threshold is
   reached, so a trickle of freed entries does not bounce blocks in and
   out of the active state. */
static inline int
block_may_speculate( fd_sched_t * sched, fd_sched_block_t * block, ulong spec_free_min ) {
  if( FD_UNLIKELY( !block->lthash_oob ) ) return 0;
  if( block->fec_eos || !block->add_owed_cnt ) return 0;
  if( fd_sched_lthash_spec_free_cnt( sched->lthash )<spec_free_min ) return 0;
  /* No need to check for tail because we have one block per lane. */
  return block_is_lane_head( sched, block );
}

/* Is there a lane head, other than the block, that we could activate to
   perform must-do work? */
static inline int
other_lane_has_real_work( fd_sched_t * sched, fd_sched_block_t * block ) {
  ulong staged_bitset = fd_ulong_clear_bit( sched->staged_bitset, (int)block->staging_lane );
  while( staged_bitset ) {
    int lane_idx  = fd_ulong_find_lsb( staged_bitset );
    staged_bitset = fd_ulong_pop_lsb( staged_bitset );
    fd_sched_block_t * head = block_pool_ele( sched, sched->staged_head_bank_idx[ lane_idx ] );
    if( block_is_done( block_pool_ele( sched, head->parent_idx ) ) && block_is_activatable( head ) ) return 1;
  }
  return 0;
}

static inline int
block_should_deactivate( fd_sched_t * sched, fd_sched_block_t * block ) {
  /* We allow a grace period, during which a block has nothing to
     dispatch, but has something in-flight.  The block is allowed to
     stay activated and ingest FEC sets during this time.  The block
     will be deactivated if there's still nothing to dispatch by the
     time all in-flight tasks are completed, unless it can spend the
     idle time speculating on LtHash additions. */
  return !block_is_activatable( block ) && !block_is_in_flight( block ) && !block_may_speculate( sched, block, 1UL );
}

static inline int
block_is_prunable( fd_sched_block_t * block ) {
  return !block->in_rdisp && !block_is_in_flight( block );
}

__attribute__((format(printf,2,3)))
static void
fd_sched_printf( fd_sched_t * sched,
                 char const * fmt,
                 ... ) {
  va_list ap;
  ulong len;
  va_start( ap, fmt );
  int ret = vsnprintf( sched->print_buf+sched->print_buf_sz,
                       FD_SCHED_MAX_PRINT_BUF_SZ-sched->print_buf_sz,
                       fmt, ap );
  va_end( ap );
  len = fd_ulong_if( ret<0, 0UL, fd_ulong_min( (ulong)ret, FD_SCHED_MAX_PRINT_BUF_SZ-sched->print_buf_sz-1UL ) );
  sched->print_buf[ sched->print_buf_sz+len ] = '\0';
  sched->print_buf_sz += len;
}

FD_FN_UNUSED static void
print_histogram( fd_sched_t * sched, fd_histf_t * hist, ulong converter, char * title ) {
  fd_sched_printf( sched, " +---------------------+----------------------+--------------+\n" );
  fd_sched_printf( sched, " | %-19s |                      | Count        |\n", title );
  fd_sched_printf( sched, " +---------------------+----------------------+--------------+\n" );

  ulong total_count = 0;
  for( ulong i=0UL; i<fd_histf_bucket_cnt( hist ); i++ ) {
    total_count += fd_histf_cnt( hist, i );
  }

  for( ulong i=0UL; i< fd_histf_bucket_cnt( hist ); i++ ) {
    ulong bucket_count = fd_histf_cnt( hist, i );

    char * lt_str;
    char lt_buf[ 64 ];
    if( FD_UNLIKELY( i==fd_histf_bucket_cnt( hist )-1UL ) ) {
      lt_str = "+Inf";
    } else {
      ulong edge = fd_histf_right( hist, i );
      if( converter==FD_METRICS_CONVERTER_NANOSECONDS ) {
        edge = fd_metrics_convert_ticks_to_nanoseconds( edge-1UL );
        FD_TEST( fd_cstr_printf_check( lt_buf, sizeof( lt_buf ), NULL, "<= %lu nanos", edge ) );
      } else if( converter==FD_METRICS_CONVERTER_NONE ) {
        FD_TEST( fd_cstr_printf_check( lt_buf, sizeof( lt_buf ), NULL, "<= %lu", edge-1UL ) );
      }
      lt_str = lt_buf;
    }

    /* Create visual bar - scale to max 20 characters. */
    char bar_buf[ 22 ];
    if( bucket_count>0UL && total_count>0UL ) {
      ulong bar_length = (bucket_count*20UL)/total_count;
      if( !bar_length ) bar_length = 1;
      for( ulong j=0UL; j<bar_length; j++ ) { bar_buf[ j ] = '*'; }
      bar_buf[ bar_length ] = '\0';
    } else {
      bar_buf[ 0 ] = '\0';
    }

    fd_sched_printf( sched, " | %19s | %-20s | %12lu |\n", lt_str, bar_buf, bucket_count );
  }
}

FD_FN_UNUSED static void
print_block_metrics( fd_sched_t * sched, fd_sched_block_t * block ) {
  fd_sched_printf( sched, "block idx %lu, block slot %lu, parent_slot %lu, fec_eos %d, rooted %d, txn_parsed_cnt %u, txn_exec_done_cnt %u, txn_sigverify_done_cnt %u, poh_hashing_done_cnt %u, poh_hash_cmp_done_cnt %u, txn_done_cnt %u, shred_cnt %u, mblk_cnt %u, mblk_freed_cnt %u, mblk_tick_cnt %u, mblk_unhashed_cnt %u, hashcnt %lu, txn_pool_max_popcnt %lu/%lu, mblk_pool_max_popcnt %lu/%lu, block_pool_max_popcnt %lu/%lu, mblks_rem %lu, txns_rem %lu, fec_buf_sz %u, fec_buf_boff %u, fec_buf_soff %u, fec_eob %d, fec_sob %d\n",
                   block_to_idx( sched, block ), block->slot, block->parent_slot, block->fec_eos, block->rooted, block->txn_parsed_cnt, block->txn_exec_done_cnt, block->txn_sigverify_done_cnt, block->poh_hashing_done_cnt, block->poh_hash_cmp_done_cnt, block->txn_done_cnt, block->shred_cnt, block->mblk_cnt, block->mblk_freed_cnt, block->mblk_tick_cnt, block->mblk_unhashed_cnt, block->hashcnt, block->txn_pool_max_popcnt, sched->depth, block->mblk_pool_max_popcnt, sched->depth, block->block_pool_max_popcnt, sched->block_cnt_max, block->mblks_rem, block->txns_rem, block->fec_buf_sz, block->fec_buf_boff, block->fec_buf_soff, block->fec_eob, block->fec_sob );
}

FD_FN_UNUSED static void
print_block_debug( fd_sched_t * sched, fd_sched_block_t * block ) {
  fd_sched_printf( sched, "block idx %lu, block slot %lu, parent_slot %lu, staged %d (lane %lu), dying %d, in_rdisp %d, fec_eos %d, rooted %d, block_start_signaled %d, block_end_signaled %d, block_start_done %d, block_end_done %d, txn_parsed_cnt %u, txn_exec_in_flight_cnt %u, txn_exec_done_cnt %u, txn_sigverify_in_flight_cnt %u, txn_sigverify_done_cnt %u, poh_hashing_in_flight_cnt %u, poh_mblk_in_flight_cnt %u, cert_in_flight_cnt %u, poh_hashing_done_cnt %u, poh_hash_cmp_done_cnt %u, txn_done_cnt %u, shred_cnt %u, mblk_cnt %u, mblk_freed_cnt %u, mblk_tick_cnt %u, mblk_unhashed_cnt %u, hashcnt %lu, txn_pool_max_popcnt %lu/%lu, mblk_pool_max_popcnt %lu/%lu, block_pool_max_popcnt %lu/%lu, tick_hashcnt_wmk %lu, curr_tick_hashcnt %lu, hashes_per_tick %lu, mblks_rem %lu, txns_rem %lu, fec_buf_sz %u, fec_buf_boff %u, fec_buf_soff %u, fec_eob %d, fec_sob %d, lthash_drained %d, add_owed_cnt %u, sub_queued_cnt %u, sub_in_flight_cnt %u, sub_applied_cnt %u, add_created_cnt %u, add_surfaced_cnt %u, add_done_cnt %u, add_applied_cnt %u, add_undone_cnt %u, lthash_in_flight_cnt %u, lthash_draining %d\n",
                   block_to_idx( sched, block ), block->slot, block->parent_slot, block->staged, block->staging_lane, block->dying, block->in_rdisp, block->fec_eos, block->rooted, block->block_start_signaled, block->block_end_signaled, block->block_start_done, block->block_end_done, block->txn_parsed_cnt, block->txn_exec_in_flight_cnt, block->txn_exec_done_cnt, block->txn_sigverify_in_flight_cnt, block->txn_sigverify_done_cnt, block->poh_hashing_in_flight_cnt, block->poh_mblk_in_flight_cnt, block->cert_in_flight_cnt, block->poh_hashing_done_cnt, block->poh_hash_cmp_done_cnt, block->txn_done_cnt, block->shred_cnt, block->mblk_cnt, block->mblk_freed_cnt, block->mblk_tick_cnt, block->mblk_unhashed_cnt, block->hashcnt, block->txn_pool_max_popcnt, sched->depth, block->mblk_pool_max_popcnt, sched->depth, block->block_pool_max_popcnt, sched->block_cnt_max, block->tick_hashcnt_wmk, block->curr_tick_hashcnt, block->hashes_per_tick, block->mblks_rem, block->txns_rem, block->fec_buf_sz, block->fec_buf_boff, block->fec_buf_soff, block->fec_eob, block->fec_sob, block->lthash_drained, block->add_owed_cnt, block->sub_queued_cnt, block->sub_in_flight_cnt, block->sub_applied_cnt, block->add_created_cnt, block->add_surfaced_cnt, block->add_done_cnt, block->add_applied_cnt, block->add_undone_cnt, block->lthash_in_flight_cnt, block->lthash_draining );
}

FD_FN_UNUSED static void
print_block_and_parent( fd_sched_t * sched, fd_sched_block_t * block ) {
  print_block_debug( sched, block );
  fd_sched_block_t * parent = block_pool_ele( sched, block->parent_idx );
  if( FD_LIKELY( parent ) ) print_block_debug( sched, parent );
}

FD_FN_UNUSED static void
print_metrics( fd_sched_t * sched ) {
    fd_sched_printf( sched, "metrics: block_added_cnt %u, block_added_staged_cnt %u, block_added_unstaged_cnt %u, block_added_dead_ood_cnt %u, block_removed_cnt %u, block_abandoned_cnt %u, block_bad_cnt %u, block_promoted_cnt %u, block_demoted_cnt %u, deactivate_no_child_cnt %u, deactivate_no_txn_cnt %u, deactivate_pruned_cnt %u, deactivate_abandoned_cnt %u, lane_switch_cnt %u, lane_promoted_cnt %u, lane_demoted_cnt %u, lane_wait_cnt %lu, fork_observed_cnt %u, alut_success_cnt %u, alut_serializing_cnt %u, poison_latch_overflow_cnt %u, poison_latch_alt_cnt %u, poison_cnt_wmk %u, txn_poison_serializing_cnt %u, txn_poisoned_cnt %u, txn_abandoned_parsed_cnt %u, txn_abandoned_exec_done_cnt %u, txn_abandoned_done_cnt %u, txn_max_in_flight_cnt %u, txn_weighted_in_flight_cnt %lu, txn_weighted_in_flight_tickcount %lu, txn_none_in_flight_tickcount %lu, txn_parsed_cnt %lu, txn_exec_done_cnt %lu, txn_sigverify_done_cnt %lu, txn_mixin_done_cnt %lu, txn_done_cnt %lu, mblk_parsed_cnt %lu, mblk_poh_hashed_cnt %lu, mblk_poh_done_cnt %lu, bytes_ingested_cnt %lu, bytes_ingested_unparsed_cnt %lu, bytes_dropped_cnt %lu, fec_cnt %lu, lthash_parsed_writable_cnt %lu, lthash_start_reg_cnt %u, lthash_late_reg_cnt %u, lthash_demote_reg_cnt %u, lthash_first_write_cnt %lu, lthash_coalesced_cnt %lu, lthash_add_created_cnt %lu, lthash_spec_cnt %lu, lthash_entry_cnt %lu, lthash_sub_dispatched_cnt %lu, lthash_sub_task_cnt %lu, lthash_sub_applied_cnt %lu, lthash_add_surfaced_cnt %lu, lthash_add_surfaced_stale_cnt %lu, lthash_add_dispatched_cnt %lu, lthash_add_task_cnt %lu, lthash_add_dispatched_stale_cnt %lu, lthash_add_batch_held_cnt %lu, lthash_add_batch_wait_idle_cnt %lu, lthash_add_applied_cnt %lu, lthash_add_undone_cnt %lu, lthash_spec_applied_cnt %lu, lthash_spec_stale_cnt %lu, lthash_spec_given_up_cnt %u, lthash_pool_full_cnt %u, lthash_spec_yield_cnt %u, lthash_frozen_cnt %lu, lthash_discarded_add_owed_cnt %u, lthash_discarded_add_pending_cnt %u, lthash_discarded_add_held_cnt %u, lthash_discarded_sub_queued_cnt %u, lthash_discarded_sub_applied_cnt %u, lthash_discarded_add_applied_cnt %u\n",
                     sched->metrics->block_added_cnt, sched->metrics->block_added_staged_cnt, sched->metrics->block_added_unstaged_cnt, sched->metrics->block_added_dead_ood_cnt, sched->metrics->block_removed_cnt, sched->metrics->block_abandoned_cnt, sched->metrics->block_bad_cnt, sched->metrics->block_promoted_cnt, sched->metrics->block_demoted_cnt, sched->metrics->deactivate_no_child_cnt, sched->metrics->deactivate_no_txn_cnt, sched->metrics->deactivate_pruned_cnt, sched->metrics->deactivate_abandoned_cnt, sched->metrics->lane_switch_cnt, sched->metrics->lane_promoted_cnt, sched->metrics->lane_demoted_cnt, sched->metrics->lane_wait_cnt, sched->metrics->fork_observed_cnt, sched->metrics->alut_success_cnt, sched->metrics->alut_serializing_cnt, sched->metrics->poison_latch_overflow_cnt, sched->metrics->poison_latch_alt_cnt, sched->metrics->poison_cnt_wmk, sched->metrics->txn_poison_serializing_cnt, sched->metrics->txn_poisoned_cnt, sched->metrics->txn_abandoned_parsed_cnt, sched->metrics->txn_abandoned_exec_done_cnt, sched->metrics->txn_abandoned_done_cnt, sched->metrics->txn_max_in_flight_cnt, sched->metrics->txn_weighted_in_flight_cnt, sched->metrics->txn_weighted_in_flight_tickcount, sched->metrics->txn_none_in_flight_tickcount, sched->metrics->txn_parsed_cnt, sched->metrics->txn_exec_done_cnt, sched->metrics->txn_sigverify_done_cnt, sched->metrics->txn_mixin_done_cnt, sched->metrics->txn_done_cnt, sched->metrics->mblk_parsed_cnt, sched->metrics->mblk_poh_hashed_cnt, sched->metrics->mblk_poh_done_cnt, sched->metrics->bytes_ingested_cnt, sched->metrics->bytes_ingested_unparsed_cnt, sched->metrics->bytes_dropped_cnt, sched->metrics->fec_cnt, sched->metrics->lthash_parsed_writable_cnt, sched->metrics->lthash_start_reg_cnt, sched->metrics->lthash_late_reg_cnt, sched->metrics->lthash_demote_reg_cnt, sched->metrics->lthash_first_write_cnt, sched->metrics->lthash_coalesced_cnt, sched->metrics->lthash_add_created_cnt, sched->metrics->lthash_spec_cnt, sched->metrics->lthash_entry_cnt, sched->metrics->lthash_sub_dispatched_cnt, sched->metrics->lthash_sub_task_cnt, sched->metrics->lthash_sub_applied_cnt, sched->metrics->lthash_add_surfaced_cnt, sched->metrics->lthash_add_surfaced_stale_cnt, sched->metrics->lthash_add_dispatched_cnt, sched->metrics->lthash_add_task_cnt, sched->metrics->lthash_add_dispatched_stale_cnt, sched->metrics->lthash_add_batch_held_cnt, sched->metrics->lthash_add_batch_wait_idle_cnt, sched->metrics->lthash_add_applied_cnt, sched->metrics->lthash_add_undone_cnt, sched->metrics->lthash_spec_applied_cnt, sched->metrics->lthash_spec_stale_cnt, sched->metrics->lthash_spec_given_up_cnt, sched->metrics->lthash_pool_full_cnt, sched->metrics->lthash_spec_yield_cnt, sched->metrics->lthash_frozen_cnt, sched->metrics->lthash_discarded_add_owed_cnt, sched->metrics->lthash_discarded_add_pending_cnt, sched->metrics->lthash_discarded_add_held_cnt, sched->metrics->lthash_discarded_sub_queued_cnt, sched->metrics->lthash_discarded_sub_applied_cnt, sched->metrics->lthash_discarded_add_applied_cnt );
}

FD_FN_UNUSED static void
print_sched( fd_sched_t * sched ) {
  fd_sched_printf( sched, "sched canary 0x%lx, exec_cnt %lu, root_idx %lu, txn_exec_ready_bitset[ 0 ] 0x%lx, sigverify_ready_bitset[ 0 ] 0x%lx, poh_ready_bitset[ 0 ] 0x%lx, cert_ready_bitset[ 0 ] 0x%lx, lthash_ready_bitset[ 0 ] 0x%lx, active_idx %lu, staged_bitset %lu, staged_head_idx[0] %lu, staged_head_idx[1] %lu, staged_head_idx[2] %lu, staged_head_idx[3] %lu, staged_popcnt_wmk %lu, txn_pool_free_cnt %lu/%lu, block_pool_popcnt %lu/%lu, lthash_draining_cnt %u, lthash_add_batch_cnt %lu\n",
                   sched->canary, sched->exec_cnt, sched->root_idx, sched->txn_exec_ready_bitset[ 0 ], sched->sigverify_ready_bitset[ 0 ], sched->poh_ready_bitset[ 0 ], sched->cert_ready_bitset[ 0 ], sched->lthash_ready_bitset[ 0 ], sched->active_bank_idx, sched->staged_bitset, sched->staged_head_bank_idx[ 0 ], sched->staged_head_bank_idx[ 1 ], sched->staged_head_bank_idx[ 2 ], sched->staged_head_bank_idx[ 3 ], sched->staged_popcnt_wmk, sched->txn_pool_free_cnt, sched->depth, sched->block_pool_popcnt, sched->block_cnt_max, sched->lthash_draining_cnt, sched->lthash_oob ? sched->lthash_add_batch->cnt : 0UL );
  fd_sched_block_t * active_block = block_pool_ele( sched, sched->active_bank_idx );
  if( active_block ) print_block_debug( sched, active_block );
  for( int l=0; l<(int)FD_SCHED_MAX_STAGING_LANES; l++ ) {
    if( fd_ulong_extract_bit( sched->staged_bitset, l ) ) {
      fd_sched_block_t * block = block_pool_ele( sched, sched->staged_head_bank_idx[ l ] );
      print_block_debug( sched, block );
    }
  }
}

FD_FN_UNUSED static void
print_all( fd_sched_t * sched, fd_sched_block_t * block ) {
  print_metrics( sched );
  print_sched( sched );
  print_block_and_parent( sched, block );
}

/* How many idle exec tiles a poll leaves free for the critical path
   when it hands out anything but a transaction.

   One idle:
     - If the block may still get transactions and has none in flight,
       so a transaction that becomes ready dispatches right away.

   None idle:
     - If the block has received all its FEC sets, since a queued
       transaction then only becomes ready when an in-flight one
       completes and frees its own tile.
     - If a transaction is in flight, for the same reason.
     - If there's only a single exec tile anyway. */
static inline int
idle_reserve( fd_sched_t const * sched, fd_sched_block_t const * block ) {
  return !(block->fec_eos || block->txn_exec_in_flight_cnt>0U || sched->exec_cnt==1UL);
}

/* The reserve for an LtHash batch.  An LtHash batch may hold a tile for
   longer than a sigverify, since its accounts may be large or cold, so
   it always leaves one tile idle, except with a single exec tile. */
static inline int
lthash_idle_reserve( fd_sched_t const * sched, fd_sched_block_t const * block ) {
  (void)block;
  return sched->exec_cnt>1UL;
}

/* Each tile runs at most one task at a time, so no tile may be busy
   in two bitsets. */
static inline void
exec_ready_bitsets_check( fd_sched_t * sched ) {
  ulong mask = fd_ulong_mask_lsb( (int)sched->exec_cnt );
  ulong a    = (~sched->txn_exec_ready_bitset [ 0 ])&mask;
  ulong b    = (~sched->sigverify_ready_bitset[ 0 ])&mask;
  ulong c    = (~sched->poh_ready_bitset      [ 0 ])&mask;
  ulong d    = (~sched->lthash_ready_bitset   [ 0 ])&mask;
  if( FD_UNLIKELY( (a&(b|c|d)) | (b&(c|d)) | (c&d) ) ) {
    FD_LOG_CRIT(( "invariant violation: txn_exec_ready_bitset 0x%lx sigverify_ready_bitset 0x%lx poh_ready_bitset 0x%lx cert_ready_bitset 0x%lx lthash_ready_bitset 0x%lx", sched->txn_exec_ready_bitset[ 0 ], sched->sigverify_ready_bitset[ 0 ], sched->poh_ready_bitset[ 0 ], sched->cert_ready_bitset[ 0 ], sched->lthash_ready_bitset[ 0 ] ));
  }
}

/* Every busy tile should be accounted for by an in-flight task of a
   staged lane head, which could be an actively dispatching block, or a
   dying block waiting for in-flight tasks to drain. */
static void
exec_busy_check( fd_sched_t * sched, fd_sched_block_t * block ) {
  exec_ready_bitsets_check( sched );
  ulong total_exec_busy_cnt = sched->exec_cnt-(ulong)fd_ulong_popcnt( sched->txn_exec_ready_bitset[ 0 ]&sched->sigverify_ready_bitset[ 0 ]&sched->poh_ready_bitset[ 0 ]&sched->cert_ready_bitset[ 0 ]&sched->lthash_ready_bitset[ 0 ] );
  if( FD_UNLIKELY( block_in_flight_cnt( block )!=total_exec_busy_cnt ) ) {
    /* Ideally we'd simply assert that the two sides of the equation are
       equal.  But abandoned blocks throw a wrench into this.  We allow
       abandoned blocks to have in-flight transactions that are
       naturally drained while we try to dispatch from another block.
       In such cases, the total number of in-flight transactions should
       include the abandoned blocks too.  The contract is that blocks
       with in-flight transactions cannot be abandoned or demoted from
       rdisp.  So a dying block has to be the head of one of the staging
       lanes. */
    // FIXME This contract no longer true if we implement immediate
    // demotion of abandoned blocks.
    ulong total_in_flight = 0UL;
    for( int l=0; l<(int)FD_SCHED_MAX_STAGING_LANES; l++ ) {
      if( fd_ulong_extract_bit( sched->staged_bitset, l ) ) {
        fd_sched_block_t * staged_block = block_pool_ele( sched, sched->staged_head_bank_idx[ l ] );
        if( FD_UNLIKELY( block_is_in_flight( staged_block )&&!(staged_block==block||staged_block->dying) ) ) {
          sched->print_buf_sz = 0UL;
          print_all( sched, staged_block );
          FD_LOG_NOTICE(( "%s", sched->print_buf ));
          FD_LOG_CRIT(( "invariant violation: in-flight block is neither active nor dying" ));
        }
        total_in_flight += block_in_flight_cnt( staged_block );
      }
    }
    if( FD_UNLIKELY( total_in_flight!=total_exec_busy_cnt ) ) {
      sched->print_buf_sz = 0UL;
      print_all( sched, block );
      FD_LOG_NOTICE(( "%s", sched->print_buf ));
      FD_LOG_CRIT(( "invariant violation: total_in_flight %lu != total_exec_busy_cnt %lu", total_in_flight, total_exec_busy_cnt ));
    }
    FD_LOG_DEBUG(( "exec_busy_cnt %lu checks out", total_exec_busy_cnt ));
  }
}

static inline void
record_dead_reason( fd_sched_block_t * block,
                    int                dead_reason ) {
  if( FD_LIKELY( block->dead_reason==FD_SCHED_DEAD_REASON_NONE ) ) {
    block->dead_reason = dead_reason;
    block->discarded = 0;
  }
}

/* Record that the block goes down with its lineage rather than for a
   defect of its own, aka DEAD_ANCESTOR.  Also record the parent's
   deadness flavor so we can tell a discarded (but not invalid) lineage
   from an invalid one.

   Gated on the block having no dead reason of its own, so a verdict
   sched already reached is never overwritten.  That gate neither bounds
   how often the inherit runs nor sees a ruling the replay tile made,
   which leaves dead_reason NONE.  Callers are responsible for invoking
   this only on a block that is newly going down. */
static inline void
record_lineage_death( fd_sched_block_t * block, fd_sched_block_t const * parent ) {
  if( FD_LIKELY( block->dead_reason==FD_SCHED_DEAD_REASON_NONE ) ) {
    record_dead_reason( block, FD_SCHED_DEAD_REASON_DEAD_ANCESTOR );
    block->discarded = parent->discarded;
  }
}

static void
handle_bad_block( fd_sched_t * sched, fd_sched_block_t * block, int dead_reason ) {
  record_dead_reason( block, dead_reason );
  sched->print_buf_sz = 0UL;
  print_all( sched, block );
  FD_LOG_DEBUG(( "%s", sched->print_buf ));
  subtree_abandon( sched, block );
  sched->metrics->block_bad_cnt++;
  check_or_set_active_block( sched );
}

/* Returns the number of shred boundaries strictly before query.
   Transaction offsets are visited in nondecreasing order, so each
   shred length is scanned at most once per block. */
static uint
shred_split( fd_sched_t *       sched,
             fd_sched_block_t * block,
             uint               query ) {
  FD_TEST( block->shred_scan_idx<=block->shred_cnt );
  FD_TEST( block->shred_scan_off<=query );
  ushort const * shred_sz = sched->shred_sz + block_to_idx( sched, block )*sched->max_shreds_per_block;
  while( block->shred_scan_idx<block->shred_cnt ) {
    uint next_off = block->shred_scan_off + (uint)shred_sz[ block->shred_scan_idx ];
    if( next_off>=query ) break;
    block->shred_scan_off = next_off;
    block->shred_scan_idx++;
  }
  return block->shred_scan_idx;
}


/* Out-of-band LtHash helpers. */

static inline int
block_owns_lane_map( fd_sched_t *       sched,
                     fd_sched_block_t * block ) {
  return block->staged && fd_sched_lthash_lane_bank( sched->lthash, block->staging_lane )==block_to_idx( sched, block );
}

/* A new entry for acct in the block's lane map.  The account owes its
   one subtraction, so the entry goes on the block's sub queue. */
static fd_sched_lthash_entry_t *
lthash_entry_new( fd_sched_t *           sched,
                  fd_sched_block_t *     block,
                  fd_acct_addr_t const * acct ) {
  /* A block claims lane map upon being staged. */
  if( FD_UNLIKELY( !block_owns_lane_map( sched, block ) ) ) FD_LOG_CRIT(( "invariant violation: block %lu:%lu owns no lane map", block->slot, block_to_idx( sched, block ) ));
  ulong                     lane = block->staging_lane;
  fd_sched_lthash_entry_t * e    = fd_sched_lthash_insert( sched->lthash, lane, acct );
  uint                      idx  = (uint)fd_sched_lthash_entry_idx( sched->lthash, lane, e );
  sched->metrics->lthash_entry_cnt++;
  if( FD_LIKELY( block->sub_q_tail==UINT_MAX ) ) block->sub_q_head = idx;
  else fd_sched_lthash_entry( sched->lthash, lane, block->sub_q_tail )->q_next = idx;
  block->sub_q_tail = idx;
  block->sub_queued_cnt++;
  return e;
}

/* A write to the entry's account arrived after its addition was
   created.  Undo the addition if it was applied.  Also zero the
   reference to the pseudo transaction of record, so the stale pseudo
   transaction is completed on the spot when it surfaces, or is ignored
   when its in-flight hashing finishes. */
static void
lthash_entry_rewrite( fd_sched_t *              sched,
                      fd_sched_block_t *        block,
                      fd_sched_lthash_entry_t * e ) {
  int undone = e->add_state==FD_SCHED_LTHASH_ADD_DONE;
  sched->metrics->lthash_add_undone_cnt += (ulong)undone;
  sched->metrics->lthash_spec_stale_cnt += (ulong)(!undone && e->spec_idx!=UINT_MAX);
  block->add_undone_cnt                 += (uint)undone;
  fd_sched_lthash_entry_rewrite( sched->lthash, e, sched->lthash_delta+block_to_idx( sched, block ) );
}

static void
lthash_entry_new_write_observed( fd_sched_t *           sched,
                                 fd_sched_block_t *     block,
                                 fd_acct_addr_t const * acct ) {
  fd_sched_lthash_entry_t * e = fd_sched_lthash_query( sched->lthash, block->staging_lane, acct );
  if( FD_LIKELY( !e ) ) lthash_entry_new( sched, block, acct );
  else                  lthash_entry_rewrite( sched, block, e );
}

/* The dispatcher created addition pseudo transaction ptxn_idx for the
   block.  The pseudo transaction's account gets stamped with ptxn_idx
   as its latest addition, after undoing any addition it had.  A
   speculative addition reserves a speculation entry so the addition can
   be undone later if needed.  Caller is responsible for ensuring a
   speculation entry is free. */
static void
lthash_add_created( fd_sched_t *       sched,
                    fd_sched_block_t * block,
                    ulong              ptxn_idx,
                    int                speculative ) {
  FD_TEST( ptxn_idx & FD_RDISP_LTHASH_PSEUDO_TXN );
  block->add_created_cnt++;
  sched->metrics->lthash_add_created_cnt++;
  fd_acct_addr_t acct[ 1 ];
  fd_rdisp_pseudo_txn_to_addr( sched->rdisp, ptxn_idx, acct );
  fd_sched_lthash_entry_t * e = fd_sched_lthash_query( sched->lthash, block->staging_lane, acct );
  if( FD_LIKELY( !e ) ) e = lthash_entry_new( sched, block, acct );
  else                  lthash_entry_rewrite( sched, block, e );
  e->add_state = (uchar)FD_SCHED_LTHASH_ADD_PENDING;
  e->ptxn_idx  = (uint)ptxn_idx;
  if( FD_LIKELY( speculative ) ) {
    e->spec_idx = fd_sched_lthash_spec_acquire( sched->lthash );
    FD_TEST( e->spec_idx!=UINT_MAX );
  }
}

/* The block was just staged and claims its lane's map, which finishes
   any clean still pending on the map. */
static void
lthash_claim_lane_map( fd_sched_t *       sched,
                       fd_sched_block_t * block ) {
  if( FD_UNLIKELY( !sched->lthash_oob ) ) return;
  FD_TEST( block_is_lane_head( sched, block ) );
  fd_sched_lthash_lane_claim( sched->lthash, block->staging_lane, block_to_idx( sched, block ) );
}

/* Clears a chunk of entries from every released lane map. */
static void
lthash_clean_released_maps( fd_sched_t * sched ) {
  if( FD_UNLIKELY( !sched->lthash_oob ) ) return;
  for( ulong lane=0UL; lane<FD_SCHED_MAX_STAGING_LANES; lane++ ) fd_sched_lthash_lane_clean( sched->lthash, lane, FD_SCHED_LTHASH_CLEAN_CHUNK );
}

/* Pops up to max of the accounts that rdisp is still tracking for us,
   such that each gets an addition pseudo transaction.  The block must
   be insert ready.  This is a no-op for an unstaged block, which drains
   when promoted. */
static void
lthash_maybe_drain( fd_sched_t *       sched,
                    fd_sched_block_t * block,
                    ulong              max ) {
  if( FD_UNLIKELY( !sched->lthash_oob ) ) return;
  if( !block->staged || !block->fec_eos || block->lthash_drained ) return;
  ulong bank_idx = block_to_idx( sched, block );
  /* fd_rdisp_add_pseudo_txn() returns 0 for a block that is not insert
     ready, which would cause us to erroneously mark that the block has
     been drained.  A staged block is alone on its lane, so it is insert
     ready by construction, as long as it is in fact the lane's block.
     So we assert being head, which implies being tail. */
  FD_TEST( block_is_lane_head( sched, block ) );
  ulong pop_cnt = 0UL;
  while( pop_cnt<max ) {
    ulong ptxn_idx = fd_rdisp_add_pseudo_txn( sched->rdisp, bank_idx );
    if( FD_UNLIKELY( !ptxn_idx ) ) break;
    block->add_owed_cnt--;
    lthash_add_created( sched, block, ptxn_idx, 0 );
    pop_cnt++;
  }
  if( FD_UNLIKELY( pop_cnt==max ) ) {
    /* The set may hold more, so the next call continues. */
    sched->lthash_draining_cnt += (uint)!block->lthash_draining;
    block->lthash_draining      = 1;
    return;
  }
  sched->lthash_draining_cnt -= (uint)block->lthash_draining;
  block->lthash_draining      = 0;
  block->lthash_drained       = 1;
}

/* Returns the staged block that is draining, the one on the lowest
   lane if several are.  Assumes lthash_draining_cnt is non-zero. */
static fd_sched_block_t *
lthash_find_draining_block( fd_sched_t * sched ) {
  for( ulong lanes=sched->staged_bitset; lanes; lanes=fd_ulong_pop_lsb( lanes ) ) {
    fd_sched_block_t * block = block_pool_ele( sched, sched->staged_head_bank_idx[ fd_ulong_find_lsb( lanes ) ] );
    if( block->lthash_draining ) return block;
  }
  FD_LOG_CRIT(( "invariant violation: %u blocks draining but no staged block is", sched->lthash_draining_cnt ));
}

/* This is paced at up to once per fd_sched_task_next_ready(), when it
   finds no real transaction to dispatch.  This helps overlap the drain
   and the lane map cleaning with exec tile work. */
static inline void
lthash_drain_chunk( fd_sched_t * sched ) {
  if( FD_UNLIKELY( sched->lthash_draining_cnt ) ) lthash_maybe_drain( sched, lthash_find_draining_block( sched ), FD_SCHED_LTHASH_DRAIN_CHUNK );
  lthash_clean_released_maps( sched );
}

/* Is there a lane other than the active block's holding a demotable
   block?  A demotable block is one with nothing to dispatch and nothing
   in flight. */
static int
any_inactive_lane_demotable( fd_sched_t * sched ) {
  for( ulong lanes=sched->staged_bitset; lanes; lanes=fd_ulong_pop_lsb( lanes ) ) {
    int lane_idx = fd_ulong_find_lsb( lanes );
    if( sched->staged_head_bank_idx[ lane_idx ]==sched->active_bank_idx ) continue;
    if( lane_is_demotable( sched, lane_idx ) ) return 1;
  }
  return 0;
}

/* Should a FEC set wait for a staging lane?  Only in the case of a
   block's first FEC set when the block would be staged and every lane
   is occupied.

   Waiting is only safe while every lane will free up on its own.  The
   FEC sets queued behind this waiting one are blocked.  A fec_eos block
   is dispatchable to completion.  A non fec_eos staged block with
   nothing to dispatch and nothing in flight will need more FEC sets,
   which may be stuck in queue behind this waiting one.  Waiting on the
   staged block's lane in the latter case could wedge replay.  Observe
   that the latter block is demotable.  So we can simply let the first
   FEC in.  It will enter unstaged and once no staged block can run,
   try_activate_block demotes the incomplete blocks and promotes this
   unstaged block.  A block may be transiently non-demotable if it still
   has ingested work, but it'll have to either complete and free its
   lane, or run out of work and become demotable. */
static int
fec_waits_for_lane( fd_sched_t * sched,
                    ulong        parent_bank_idx,
                    int          is_first_in_block ) {
  if( FD_LIKELY( !is_first_in_block ) ) return 0;
  if( FD_LIKELY( sched->staged_bitset!=fd_ulong_mask_lsb( FD_SCHED_MAX_STAGING_LANES ) ) ) return 0;
  /* A ULONG_MAX parent index is only used for backfill, where at the
     time of capacity check, the target ancestor is not known yet.  So
     we just assume we'll need a lane in that case.  Any other parent
     index should be valid. */
  int needs_lane = 1;
  if( FD_LIKELY( parent_bank_idx<sched->block_cnt_max ) ) {
    fd_sched_block_t * parent = block_pool_ele( sched, parent_bank_idx );
    FD_TEST( parent->in_sched );
    /* A child of a dying block is dead on arrival and doesn't need a
       lane. */
    if( FD_UNLIKELY( parent->dying ) ) return 0;
    /* A child of an unstaged stageable block enters unstaged. */
    needs_lane = parent->staged || !block_is_stageable( parent );
  }
  return needs_lane && !any_inactive_lane_demotable( sched );
}

/* Returns the free lane a new block should take.  Under out-of-band
   LtHash that is the one with the fewest map entries still to clear.
   Otherwise it is the lowest free lane.  Assumes at least one lane is
   free. */
static int
pick_free_lane( fd_sched_t * sched ) {
  ulong free_lanes = (~sched->staged_bitset)&fd_ulong_mask_lsb( FD_SCHED_MAX_STAGING_LANES );
  FD_TEST( free_lanes );
  int best = fd_ulong_find_lsb( free_lanes );
  if( FD_LIKELY( sched->lthash_oob ) ) {
    ulong best_dirty = fd_sched_lthash_lane_dirty_cnt( sched->lthash, (ulong)best );
    for( ulong lanes=fd_ulong_pop_lsb( free_lanes ); lanes && best_dirty; lanes=fd_ulong_pop_lsb( lanes ) ) {
      int   lane  = fd_ulong_find_lsb( lanes );
      ulong dirty = fd_sched_lthash_lane_dirty_cnt( sched->lthash, (ulong)lane );
      if( dirty<best_dirty ) {
        best = lane;
        best_dirty = dirty;
      }
    }
  }
  return best;
}

/* The block owes the addition of an account, a write that rdisp did not
   see through a transaction at parse time and was just told of through
   fd_rdisp_add_writable(), whose return value is rv.  The caller has
   brought the account's entry up to date.  See to it that the addition
   gets created whether or not the block has drained. */
static void
lthash_owe_addition( fd_sched_t *       sched,
                     fd_sched_block_t * block,
                     int                rv ) {
  ulong bank_idx = block_to_idx( sched, block );
  if( FD_LIKELY( rv==1 ) ) {
    sched->metrics->lthash_first_write_cnt++;
    block->add_owed_cnt++;
    if( block->lthash_drained ) {
      /* Re-drain.  We might not get another chance to create a pseudo
         transaction for it, if this were for example a late ALT
         expansion for an already fec_eos block.  A block still draining
         pops it with the rest. */
      block->lthash_drained = 0;
      lthash_maybe_drain( sched, block, FD_SCHED_LTHASH_DRAIN_CHUNK );
    }
    return;
  }
  if( FD_LIKELY( rv==0 ) ) {
    /* We got lucky.  This account is already tracked by rdisp, which
       essentially deduped the addition for us.  We can later instruct
       rdisp to create a pseudo transaction for the account, and it'll
       capture the final value of the account. */
    sched->metrics->lthash_coalesced_cnt++;
    return;
  }

  /* A staged block is alone on its lane and an unstaged block is insert
     ready as well, so the dispatcher should never refuse a write. */
  FD_LOG_CRIT(( "fd_rdisp_add_writable returned %d for block %lu:%lu", rv, block->slot, bank_idx ));
}

/* For registering account writes that rdisp did not see through a
   transaction at parse time.  Typically, that would come from
   start-of-block processing or an ALT expansion failure. */
static void
lthash_register( fd_sched_t *           sched,
                 fd_sched_block_t *     block,
                 fd_acct_addr_t const * addr ) {
  FD_TEST( block_is_lane_head( sched, block ) );
  int rv = fd_rdisp_add_writable( sched->rdisp, block_to_idx( sched, block ), addr );
  if( FD_LIKELY( rv==1 ) ) lthash_entry_new_write_observed( sched, block, addr );
  lthash_owe_addition( sched, block, rv );
}

static void
lthash_block_init( fd_sched_block_t * block ) {
  block->lthash_in_flight_cnt = 0U;
  block->add_owed_cnt         = 0U;
  block->sub_q_head           = UINT_MAX;
  block->sub_q_tail           = UINT_MAX;
  block->sub_queued_cnt       = 0U;
  block->sub_in_flight_cnt    = 0U;
  block->sub_applied_cnt      = 0U;
  block->add_created_cnt      = 0U;
  block->add_surfaced_cnt     = 0U;
  block->add_done_cnt         = 0U;
  block->add_applied_cnt      = 0U;
  block->add_undone_cnt       = 0U;
  block->lthash_drained       = 0;
  block->lthash_draining      = 0;
}

/* Forgets the block's LtHash progress when it leaves the pipeline:
   finished, abandoned, or demoted.  A demoted block re-derives
   everything if promoted.  An abandoned block may still be draining.
   The dispatcher forgets what is left of its set when the lane empties. */
static void
lthash_block_reset( fd_sched_t *       sched,
                    fd_sched_block_t * block ) {
  if( FD_UNLIKELY( !sched->lthash_oob ) ) return;
  sched->lthash_draining_cnt -= (uint)block->lthash_draining;
  int owns = block_owns_lane_map( sched, block );
  lthash_block_init( block );
  if( FD_LIKELY( owns ) ) fd_sched_lthash_lane_release( sched->lthash, block->staging_lane );
  fd_lthash_zero( sched->lthash_delta+block_to_idx( sched, block ) );
}

static void
lthash_metrics_check( fd_sched_t * sched ) {
  if( FD_UNLIKELY( !sched->lthash_oob ) ) return;
  fd_sched_metrics_t const * m = sched->metrics;
  ulong add_owed_cnt = 0UL, add_pending_cnt = 0UL, add_delta_cnt = 0UL, sub_queued_cnt = 0UL, sub_in_flight_cnt = 0UL, sub_delta_cnt = 0UL, task_in_flight_cnt = 0UL;
  for( ulong i=0UL; i<sched->block_cnt_max; i++ ) {
    fd_sched_block_t const * block = sched->block_pool+i;
    if( !block->in_sched ) continue;
    add_owed_cnt       += block->add_owed_cnt;
    add_pending_cnt    += block->add_created_cnt-block->add_surfaced_cnt;
    add_delta_cnt      += block->add_applied_cnt-block->add_undone_cnt;
    sub_queued_cnt     += block->sub_queued_cnt;
    sub_in_flight_cnt  += block->sub_in_flight_cnt;
    sub_delta_cnt      += block->sub_applied_cnt;
    task_in_flight_cnt += block->lthash_in_flight_cnt;
  }
  ulong add_on_tile_cnt = 0UL, sub_on_tile_cnt = 0UL, task_on_tile_cnt = 0UL;
  for( ulong busy = (~sched->lthash_ready_bitset[ 0 ])&fd_ulong_mask_lsb( (int)sched->exec_cnt ); busy; busy = fd_ulong_pop_lsb( busy ) ) {
    fd_sched_lthash_batch_t const * rec = sched->lthash_inflight+fd_ulong_find_lsb( busy );
    if( rec->kind==FD_SCHED_TT_LTHASH_ADD ) add_on_tile_cnt += rec->cnt;
    else                                    sub_on_tile_cnt += rec->cnt;
    task_on_tile_cnt++;
  }
  ulong add_held_cnt = sched->lthash_add_batch->cnt;
  FD_TEST( task_in_flight_cnt==task_on_tile_cnt );
  FD_TEST( sub_in_flight_cnt==sub_on_tile_cnt );
  FD_TEST( m->lthash_parsed_writable_cnt+m->lthash_start_reg_cnt+m->lthash_late_reg_cnt+m->lthash_demote_reg_cnt+m->lthash_spec_given_up_cnt==m->lthash_first_write_cnt+m->lthash_coalesced_cnt );
  FD_TEST( m->lthash_first_write_cnt==m->lthash_add_created_cnt+add_owed_cnt+m->lthash_discarded_add_owed_cnt );
  FD_TEST( m->lthash_add_created_cnt==m->lthash_add_surfaced_cnt+add_pending_cnt+m->lthash_discarded_add_pending_cnt );
  FD_TEST( m->lthash_add_surfaced_cnt==m->lthash_add_surfaced_stale_cnt+m->lthash_spec_given_up_cnt+m->lthash_add_dispatched_cnt+add_held_cnt+m->lthash_discarded_add_held_cnt );
  FD_TEST( m->lthash_add_dispatched_cnt==m->lthash_add_dispatched_stale_cnt+m->lthash_add_applied_cnt+add_on_tile_cnt );
  FD_TEST( m->lthash_add_applied_cnt-m->lthash_add_undone_cnt==m->lthash_frozen_cnt+add_delta_cnt+m->lthash_discarded_add_applied_cnt );
  FD_TEST( m->lthash_entry_cnt==m->lthash_sub_dispatched_cnt+sub_queued_cnt+m->lthash_discarded_sub_queued_cnt );
  FD_TEST( m->lthash_sub_dispatched_cnt==m->lthash_sub_applied_cnt+sub_on_tile_cnt );
  FD_TEST( m->lthash_sub_applied_cnt==m->lthash_frozen_cnt+sub_delta_cnt+m->lthash_discarded_sub_applied_cnt );
}

/* Rolls the block's LtHash progress back before it leaves its lane.
   Each account goes back into rdisp.  When we later promote the block,
   and re-derived with exactly one subtraction and one addition.
   Rehashing a demoted block's progress is the price of keeping the lane
   map per lane. */
static void
lthash_demote( fd_sched_t *       sched,
               fd_sched_block_t * block ) {
  if( FD_UNLIKELY( !sched->lthash_oob ) ) return;
  ulong bank_idx = block_to_idx( sched, block );
  ulong lane     = block->staging_lane;
  FD_TEST( !block->sub_queued_cnt && !block->sub_in_flight_cnt && !block->lthash_in_flight_cnt && block->add_created_cnt==block->add_done_cnt );
  /* A draining block has fec_eos set and has not signaled BLOCK_END,
     so block_will_signal_end keeps it dispatchable and it is never
     demotable. */
  FD_TEST( !block->lthash_draining );

  /* Owed additions are respected by rdisp demotion.  In addition, we
     need to stick the writable accounts that we are tracking back into
     rdisp. */
  uint add_owed_cnt = block->add_owed_cnt;
  if( block_owns_lane_map( sched, block ) ) {
    for( fd_sched_lthash_iter_t it = fd_sched_lthash_iter_init( sched->lthash, lane );
         !fd_sched_lthash_iter_done( sched->lthash, lane, it );
         it = fd_sched_lthash_iter_next( sched->lthash, lane, it ) ) {
      fd_sched_lthash_entry_t * e = fd_sched_lthash_iter_ele( sched->lthash, lane, it );
      /* A demotable block has nothing queued or in flight, so every
         entry should be SUB_DONE with no pending or dispatched
         addition. */
      FD_TEST( e->sub_state==FD_SCHED_LTHASH_SUB_DONE && (e->add_state==FD_SCHED_LTHASH_ADD_NONE || e->add_state==FD_SCHED_LTHASH_ADD_DONE) );
      int r = fd_rdisp_add_writable( sched->rdisp, bank_idx, &e->acct );
       /* A staged block is alone on its lane, so it is insert ready. */
      if( FD_UNLIKELY( r<0 ) ) FD_LOG_CRIT(( "fd_rdisp_add_writable failed for demoted block %lu:%lu", block->slot, bank_idx ));
      /* r==0 means rdisp already knows about the account, aka the
         account is already owed an addition.  We don't count that as a
         coalesce so lthash_coalesced_cnt nicely excludes demotion and
         only counts coalescing under normal operation. */
      sched->metrics->lthash_demote_reg_cnt  += (uint)(r==1);
      sched->metrics->lthash_first_write_cnt += (ulong)(r==1);
      add_owed_cnt                           += (uint)(r==1);
    }
  }
  /* Of the five discarded counters only the two delta counters below
     apply here.  The check above ensures nothing queued and nothing
     unsurfaced.  The owed additions are not lost, since rdisp will
     carry them through demotion, and they stay in the live counter. */
  sched->metrics->lthash_discarded_sub_applied_cnt += block->sub_applied_cnt;
  sched->metrics->lthash_discarded_add_applied_cnt += block->add_applied_cnt-block->add_undone_cnt;
  lthash_block_reset( sched, block );
  block->add_owed_cnt = add_owed_cnt;
}

static inline void
lthash_batch_init( fd_sched_block_t *        block,
                   fd_sched_lthash_batch_t * batch,
                   ulong                     bank_idx,
                   ulong                     kind ) {
  batch->bank_idx = bank_idx;
  batch->cnt      = 0UL;
  batch->lane     = (uint)block->staging_lane;
  batch->kind     = (uchar)kind;
}

static inline void
lthash_batch_append( fd_sched_t *              sched,
                     fd_sched_lthash_batch_t * batch,
                     fd_sched_lthash_entry_t * e,
                     ulong                     ptxn_idx ) {
  FD_TEST( batch->cnt<FD_SCHED_LTHASH_BATCH_MAX );
  ulong i = batch->cnt++;
  batch->entry_idx[ i ] = (uint)fd_sched_lthash_entry_idx( sched->lthash, batch->lane, e );
  batch->ptxn_idx [ i ] = (uint)ptxn_idx;
  batch->accts    [ i ] = e->acct;
}

static void
lthash_dispatch( fd_sched_t *                    sched,
                 fd_sched_block_t *              block,
                 fd_sched_lthash_batch_t const * batch,
                 int                             exec_tile_idx,
                 fd_sched_task_t *               out ) {
  FD_TEST( batch->cnt && batch->cnt<=FD_SCHED_LTHASH_BATCH_MAX );
  fd_sched_lthash_batch_t * rec = sched->lthash_inflight+exec_tile_idx;
  if( rec!=batch ) { /* FIXME optimize for end-of-block additions */
    rec->bank_idx = batch->bank_idx;
    rec->cnt      = batch->cnt;
    rec->lane     = batch->lane;
    rec->kind     = batch->kind;
    fd_memcpy( rec->entry_idx, batch->entry_idx, batch->cnt*sizeof(uint)           );
    fd_memcpy( rec->ptxn_idx,  batch->ptxn_idx,  batch->cnt*sizeof(uint)           );
    fd_memcpy( rec->accts,     batch->accts,     batch->cnt*sizeof(fd_acct_addr_t) );
  }

  out->task_type        = rec->kind;
  out->lthash->bank_idx = rec->bank_idx;
  out->lthash->exec_idx = (ulong)exec_tile_idx;
  out->lthash->cnt      = rec->cnt;
  out->lthash->accts    = rec->accts;

  sched->lthash_ready_bitset[ 0 ] = fd_ulong_clear_bit( sched->lthash_ready_bitset[ 0 ], exec_tile_idx );
  sched->tile_to_bank_idx[ exec_tile_idx ] = rec->bank_idx;
  block->lthash_in_flight_cnt++;
  if( rec->kind==FD_SCHED_TT_LTHASH_ADD ) {
    sched->metrics->lthash_add_dispatched_cnt += rec->cnt;
    sched->metrics->lthash_add_task_cnt++;
  } else {
    sched->metrics->lthash_sub_dispatched_cnt += rec->cnt;
    sched->metrics->lthash_sub_task_cnt++;
  }
  exec_busy_check( sched, block );
}

/* The addition pseudo transaction ptxn_idx is no longer its account's
   pseudo transaction of record, because the account was written again
   after the pseudo transaction was created.  Complete the pseudo
   transaction without hashing. */
static void
lthash_add_complete_stale( fd_sched_t *       sched,
                           fd_sched_block_t * block,
                           ulong              ptxn_idx ) {
  block->add_done_cnt++;
  fd_rdisp_complete_txn( sched->rdisp, ptxn_idx, 1 );
}

/* A pseudo transaction surfaced from fd_rdisp_get_next_ready() for the
   active block.  If it is still the account's pseudo transaction of
   record, mark its entry ADD_DISPATCHED, meaning it has left the
   dispatcher whether or not it will be staged for batching, and return
   the entry.  Otherwise the account has a later rewrite, so complete
   the pseudo transaction without hashing and return NULL. */
static fd_sched_lthash_entry_t *
lthash_surface( fd_sched_t *       sched,
                fd_sched_block_t * block,
                ulong              bank_idx,
                ulong              ptxn_idx ) {
  block->add_surfaced_cnt++;
  sched->metrics->lthash_add_surfaced_cnt++;
  fd_acct_addr_t acct[ 1 ];
  fd_rdisp_pseudo_txn_to_addr( sched->rdisp, ptxn_idx, acct );
  fd_sched_lthash_entry_t * e = fd_sched_lthash_query( sched->lthash, block->staging_lane, acct );
  if( FD_UNLIKELY( !e ) ) {
    /* Every pseudo transaction of a head block must have an entry. */
    sched->print_buf_sz = 0UL;
    print_all( sched, block );
    FD_LOG_NOTICE(( "%s", sched->print_buf ));
    FD_LOG_CRIT(( "invariant violation: pseudo transaction 0x%lx of block %lu:%lu has no entry", ptxn_idx, block->slot, bank_idx ));
  }
  FD_TEST( e->bank_idx==(uint)bank_idx );
  if( FD_UNLIKELY( e->ptxn_idx!=(uint)ptxn_idx ) ) {
    sched->metrics->lthash_add_surfaced_stale_cnt++;
    lthash_add_complete_stale( sched, block, ptxn_idx );
    return NULL;
  }
  FD_TEST( e->add_state==FD_SCHED_LTHASH_ADD_PENDING );
  e->add_state = (uchar)FD_SCHED_LTHASH_ADD_DISPATCHED;
  return e;
}

static void
lthash_dispatch_one_add( fd_sched_t *              sched,
                         fd_sched_block_t *        block,
                         ulong                     bank_idx,
                         fd_sched_lthash_entry_t * e,
                         ulong                     ptxn_idx,
                         int                       exec_tile_idx,
                         fd_sched_task_t *         out ) {
  fd_sched_lthash_batch_t * rec = sched->lthash_inflight+exec_tile_idx;
  lthash_batch_init( block, rec, bank_idx, FD_SCHED_TT_LTHASH_ADD );
  lthash_batch_append( sched, rec, e, ptxn_idx );
  lthash_dispatch( sched, block, rec, exec_tile_idx, out );
}

/* A speculative addition that surfaced when the block may no longer
   speculate on it, or when the idleness policy would not let it onto a
   tile, is given up.  The surfaced pseudo transaction is completed
   without hashing.  Its entry is rewritten, which frees the speculation
   entry, and the account goes back to the dispatcher as written, the
   way any write does, so the block owes the addition again.  No
   transaction actually rewrote the account, so this is neither a stale
   addition nor an invalidated speculation for metric purposes. */
static void
lthash_spec_give_up( fd_sched_t *              sched,
                     fd_sched_block_t *        block,
                     ulong                     bank_idx,
                     fd_sched_lthash_entry_t * e,
                     ulong                     ptxn_idx ) {
  sched->metrics->lthash_spec_given_up_cnt++;
  /* Completed first, so that it is no longer the account's last
     reference in the lane should the addition be force created below,
     which dedups against that. */
  lthash_add_complete_stale( sched, block, ptxn_idx );
  fd_sched_lthash_entry_rewrite( sched->lthash, e, sched->lthash_delta+bank_idx );
  lthash_owe_addition( sched, block, fd_rdisp_add_writable( sched->rdisp, bank_idx, &e->acct ) );
}

static void
lthash_dispatch_held_batch( fd_sched_t *       sched,
                            fd_sched_block_t * block,
                            ulong              bank_idx,
                            int                exec_tile_idx,
                            fd_sched_task_t *  out ) {
  fd_sched_lthash_batch_t * batch = sched->lthash_add_batch;
  /* The held batch belongs to the active block.  Its additions are
     surfaced and not done, so block_is_in_flight holds for the block,
     and a block in flight is not deactivated, demoted or pruned and
     does not signal BLOCK_END.  try_activate_block returns early while
     a block is active, so no other block takes its place behind the
     batch.  The one way out is abandon, which releases the batch where
     it marks the block dying.  So a held batch is either dispatched or
     released before its block goes anywhere. */
  FD_TEST( batch->cnt && batch->kind==FD_SCHED_TT_LTHASH_ADD && batch->bank_idx==bank_idx && batch->lane==(uint)block->staging_lane );

  for( ulong i=0UL; i<batch->cnt; i++ ) {
    fd_sched_lthash_entry_t * e = fd_sched_lthash_entry( sched->lthash, batch->lane, batch->entry_idx[ i ] );
    if( FD_UNLIKELY( e->ptxn_idx!=batch->ptxn_idx[ i ] || e->add_state!=FD_SCHED_LTHASH_ADD_DISPATCHED ) ) {
      /* A non speculative addition cannot become stale after it has
         surfaced.  See more detailed reasoning in fd_sched_lthash.h.
         So no batched pseudo transaction can actually be invalidated by
         a rewrite. */
      sched->print_buf_sz = 0UL;
      print_all( sched, block );
      FD_LOG_NOTICE(( "%s", sched->print_buf ));
      FD_LOG_CRIT(( "invariant violation: held addition %lu of %lu of block %lu:%lu was rewritten, ticket 0x%x, entry 0x%x state %u", i, batch->cnt, block->slot, bank_idx, batch->ptxn_idx[ i ], e->ptxn_idx, (uint)e->add_state ));
    }
  }
  lthash_dispatch( sched, block, batch, exec_tile_idx, out );
  batch->cnt = 0UL;
}

static void
lthash_release_held_batch( fd_sched_t *       sched,
                           fd_sched_block_t * block ) {
  if( FD_UNLIKELY( !sched->lthash_oob ) ) return;
  fd_sched_lthash_batch_t * batch = sched->lthash_add_batch;
  if( FD_LIKELY( !batch->cnt || batch->bank_idx!=block_to_idx( sched, block ) ) ) return;
  for( ulong i=0UL; i<batch->cnt; i++ ) {
    fd_sched_lthash_entry_t * e = fd_sched_lthash_entry( sched->lthash, batch->lane, batch->entry_idx[ i ] );
    if( FD_LIKELY( e->ptxn_idx==batch->ptxn_idx[ i ] ) ) {
      e->ptxn_idx  = 0U;
      e->add_state = (uchar)FD_SCHED_LTHASH_ADD_NONE;
    }
    block->add_done_cnt++;
    fd_rdisp_complete_txn( sched->rdisp, (ulong)batch->ptxn_idx[ i ], 1 );
  }
  sched->metrics->lthash_discarded_add_held_cnt += (uint)batch->cnt;
  batch->cnt = 0UL;
}

/* Dispatches up to cap of the block's oldest queued subtractions as one
   task to the highest idle tile in ready_bitset, if more than threshold
   tiles are idle.  cap is in [1, FD_SCHED_LTHASH_BATCH_MAX].  Returns 1
   if a task was written to out, 0 otherwise. */
static int
lthash_dispatch_sub( fd_sched_t *       sched,
                     fd_sched_block_t * block,
                     ulong              bank_idx,
                     ulong              ready_bitset,
                     int                threshold,
                     ulong              cap,
                     fd_sched_task_t *  out ) {
  if( FD_UNLIKELY( !block->sub_queued_cnt ) ) return 0;
  if( FD_UNLIKELY( fd_ulong_popcnt( ready_bitset )<=threshold ) ) return 0;

  int   exec_tile_idx = fd_ulong_find_msb( ready_bitset );
  ulong lane          = block->staging_lane;
  fd_sched_lthash_batch_t * batch = sched->lthash_inflight+exec_tile_idx;
  lthash_batch_init( block, batch, bank_idx, FD_SCHED_TT_LTHASH_SUB );
  while( block->sub_queued_cnt && batch->cnt<cap ) {
    uint entry_idx = block->sub_q_head;
    FD_TEST( entry_idx!=UINT_MAX );
    fd_sched_lthash_entry_t * e = fd_sched_lthash_entry( sched->lthash, lane, entry_idx );
    FD_TEST( e->sub_state==FD_SCHED_LTHASH_SUB_QUEUED && e->bank_idx==(uint)bank_idx );

    block->sub_q_head = e->q_next;
    if( FD_UNLIKELY( block->sub_q_head==UINT_MAX ) ) block->sub_q_tail = UINT_MAX;
    e->q_next    = UINT_MAX;
    e->sub_state = (uchar)FD_SCHED_LTHASH_SUB_DISPATCHED;
    block->sub_queued_cnt--;
    block->sub_in_flight_cnt++;
    lthash_batch_append( sched, batch, e, 0UL );
  }
  lthash_dispatch( sched, block, batch, exec_tile_idx, out );
  return 1;
}

/* The block is assumed to be active and has absolutely no other type of
   task queued.  The block is also assumed to satisfy
   block_may_speculate().  A speculation that lands behind an in-flight
   writer pauses speculation until that writer completes.

   Returns 1 with a task in out, or 0 when a pseudo transaction was
   created but waits on an in-flight writer, so the caller returns
   without a task, or -1 when speculation does not apply and the caller
   proceeds. */
static inline int
lthash_speculate( fd_sched_t *       sched,
                  fd_sched_block_t * block,
                  ulong              bank_idx,
                  ulong              ready_bitset,
                  fd_sched_task_t *  out ) {
  /* Thanks to block_may_speculate(), we can assume that the block
     doesn't have fec_eos set, is insert ready at head of lane, owes an
     addition, and has a free speculation entry. */

  /* There is a pending speculation.  With fec_eos clear there has been
     no drain, so every unsurfaced pseudo transaction here is a
     speculation. */
  uint spec_pending = block->add_created_cnt-block->add_surfaced_cnt;
  if( spec_pending ) {
    /* In fact, there should only be one pseudo transaction pending,
       because we speculate one addition at a time. */
    FD_TEST( spec_pending==1U );
    return -1;
  }

  if( fd_ulong_popcnt( ready_bitset )<=idle_reserve( sched, block ) ) return -1;

  ulong ptxn_idx = fd_rdisp_add_pseudo_txn( sched->rdisp, bank_idx );
  if( FD_UNLIKELY( !ptxn_idx ) ) FD_LOG_CRIT(( "invariant violation: block %lu:%lu owes %u additions but fd_rdisp_add_pseudo_txn returned none", block->slot, bank_idx, block->add_owed_cnt ));
  sched->metrics->lthash_spec_cnt++;
  block->add_owed_cnt--;
  lthash_add_created( sched, block, ptxn_idx, 1 );

  /* We expect to get either the only pseudo transaction, the one we
     just instructed rdisp to create, or nothing because it is blocked
     by an in-flight write.  There should otherwise be no task queued,
     especially no other pseudo transaction queued. */
  ulong idx = fd_rdisp_get_next_ready( sched->rdisp, bank_idx );
  if( FD_LIKELY( idx==ptxn_idx ) ) {
    fd_sched_lthash_entry_t * e = lthash_surface( sched, block, bank_idx, idx );
    FD_TEST( e );
    lthash_dispatch_one_add( sched, block, bank_idx, e, idx, fd_ulong_find_msb( ready_bitset ), out );
    return 1;
  }
  if( FD_UNLIKELY( idx ) ) FD_LOG_CRIT(( "invariant violation: fd_rdisp_get_next_ready returned 0x%lx instead of pseudo transaction 0x%lx of block %lu:%lu", idx, ptxn_idx, block->slot, bank_idx ));

  /* Pseudo transaction pending behind an in-flight writer.  It'll be
     eligible for surfacing once that writer completes. */
  return 0;
}


/* Public functions. */

ulong
fd_sched_align( void ) {
  return fd_ulong_max( alignof(fd_sched_t),
         fd_ulong_max( fd_rdisp_align(),
         fd_ulong_max( alignof(fd_sched_block_t), 64UL ))); /* Minimally cache line aligned. */
}

/* The depth every pool is sized at, which is the configured depth plus
   the pseudo transaction reserve under out-of-band LtHash.  Returns 0
   if the result exceeds what the dispatcher and the txn bitsets
   allow. */
static inline ulong
sched_depth_internal( ulong depth,
                      int   lthash_oob ) {
  ulong depth_internal = depth + fd_ulong_if( !!lthash_oob, FD_SCHED_LTHASH_RESERVE, 0UL );
  return fd_ulong_if( depth_internal>FD_SCHED_MAX_DEPTH, 0UL, depth_internal );
}

/* Sizes of the out-of-band LtHash regions, all zero when the feature
   is off so the footprint is unchanged. */
static inline ulong
sched_lthash_footprint( int lthash_oob ) {
  return fd_ulong_if( !!lthash_oob, fd_sched_lthash_footprint( FD_RDISP_MAX_WRITERS_PER_BLOCK, FD_SCHED_LTHASH_SPEC_MAX ), 0UL );
}

static inline ulong
sched_lthash_delta_sz( ulong block_cnt_max,
                       int   lthash_oob ) {
  return fd_ulong_if( !!lthash_oob, block_cnt_max*sizeof(fd_lthash_value_t), 0UL );
}

static inline ulong
sched_lthash_batch_sz( int lthash_oob ) {
  /* One batch per exec tile, plus one staging area for the addition
     batch being assembled or held. */
  return fd_ulong_if( !!lthash_oob, (FD_SCHED_MAX_EXEC_TILE_CNT+1UL)*sizeof(fd_sched_lthash_batch_t), 0UL );
}

ulong
fd_sched_footprint( ulong depth,
                    ulong block_cnt_max,
                    ulong max_shreds_per_block,
                    ulong max_txn_per_slot,
                    int   lthash_oob ) {
  if( FD_UNLIKELY( depth<FD_SCHED_MIN_DEPTH || depth>FD_SCHED_MAX_DEPTH ) ) return 0UL; /* bad depth */
  ulong depth_i = sched_depth_internal( depth, lthash_oob );
  if( FD_UNLIKELY( !depth_i ) ) return 0UL; /* reserve pushes depth past the dispatcher's limit */
  if( FD_UNLIKELY( !block_cnt_max ) ) return 0UL; /* bad block_cnt_max */
  if( FD_UNLIKELY( depth_i>UINT_MAX-1UL ) ) return 0UL; /* mblk_pool use uint as pointers */
  if( FD_UNLIKELY( !max_shreds_per_block || max_shreds_per_block>UINT_MAX ) ) return 0UL; /* shred_cnt is uint */
  if( FD_UNLIKELY( !max_txn_per_slot     || max_txn_per_slot    >UINT_MAX ) ) return 0UL; /* txn_parsed_cnt is uint */

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_sched_align(),             sizeof(fd_sched_t)                                 );
  l = FD_LAYOUT_APPEND( l, fd_rdisp_align(),             fd_rdisp_footprint( depth_i, block_cnt_max )       ); /* dispatcher */
  l = FD_LAYOUT_APPEND( l, alignof(fd_sched_block_t),    block_cnt_max*sizeof(fd_sched_block_t)             ); /* block pool */
  l = FD_LAYOUT_APPEND( l, alignof(ushort),              block_cnt_max*max_shreds_per_block*sizeof(ushort)  ); /* shred_sz */
  l = FD_LAYOUT_APPEND( l, ref_q_align(),                ref_q_footprint( block_cnt_max )                   );
  l = FD_LAYOUT_APPEND( l, alignof(fd_txn_p_t),          depth_i*sizeof(fd_txn_p_t)                         ); /* txn_pool */
  l = FD_LAYOUT_APPEND( l, alignof(fd_sched_txn_info_t), depth_i*sizeof(fd_sched_txn_info_t)                ); /* txn_info_pool */
  l = FD_LAYOUT_APPEND( l, alignof(fd_sched_mblk_t),     depth_i*sizeof(fd_sched_mblk_t)                    ); /* mblk_pool */
  l = FD_LAYOUT_APPEND( l, fd_sched_lthash_align(),      sched_lthash_footprint( lthash_oob )               ); /* lthash */
  l = FD_LAYOUT_APPEND( l, alignof(fd_lthash_value_t),   sched_lthash_delta_sz( block_cnt_max, lthash_oob ) ); /* lthash_delta */
  l = FD_LAYOUT_APPEND( l, alignof(ulong),               sched_lthash_batch_sz( lthash_oob )                ); /* lthash_inflight, lthash_add_batch */
  return FD_LAYOUT_FINI( l, fd_sched_align() );
}

void *
fd_sched_new( void *     mem,
              fd_rng_t * rng,
              ulong      depth,
              ulong      block_cnt_max,
              ulong      max_shreds_per_block,
              ulong      max_txn_per_slot,
              ulong      exec_cnt,
              int        is_alpenglow,
              int        lthash_oob ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !rng ) ) {
    FD_LOG_WARNING(( "NULL rng" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_sched_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem (%p)", mem ));
    return NULL;
  }

  if( FD_UNLIKELY( depth<FD_SCHED_MIN_DEPTH || depth>FD_SCHED_MAX_DEPTH ) ) {
    FD_LOG_WARNING(( "bad depth (%lu)", depth ));
    return NULL;
  }

  ulong depth_i = sched_depth_internal( depth, lthash_oob );
  if( FD_UNLIKELY( !depth_i ) ) {
    FD_LOG_WARNING(( "bad depth (%lu) with lthash reserve (%lu)", depth, FD_SCHED_LTHASH_RESERVE ));
    return NULL;
  }

  if( FD_UNLIKELY( !block_cnt_max ) ) {
    FD_LOG_WARNING(( "bad block_cnt_max (%lu)", block_cnt_max ));
    return NULL;
  }

  if( FD_UNLIKELY( depth_i>UINT_MAX-1UL ) ) {
    FD_LOG_WARNING(( "bad depth (%lu)", depth ));
    return NULL;
  }

  if( FD_UNLIKELY( !max_shreds_per_block || max_shreds_per_block>UINT_MAX ) ) {
    FD_LOG_WARNING(( "bad max_shreds_per_block (%lu)", max_shreds_per_block ));
    return NULL;
  }

  if( FD_UNLIKELY( !max_txn_per_slot || max_txn_per_slot>UINT_MAX ) ) {
    FD_LOG_WARNING(( "bad max_txn_per_slot (%lu)", max_txn_per_slot ));
    return NULL;
  }

  if( FD_UNLIKELY( !exec_cnt || exec_cnt>FD_SCHED_MAX_EXEC_TILE_CNT ) ) {
    FD_LOG_WARNING(( "bad exec_cnt (%lu)", exec_cnt ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_sched_t *          sched          = FD_SCRATCH_ALLOC_APPEND( l, fd_sched_align(),             sizeof(fd_sched_t)                                 );
  void *                _rdisp         = FD_SCRATCH_ALLOC_APPEND( l, fd_rdisp_align(),             fd_rdisp_footprint( depth_i, block_cnt_max )       );
  void *                _bpool         = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sched_block_t),    block_cnt_max*sizeof(fd_sched_block_t)             );
  /* */                                  FD_SCRATCH_ALLOC_APPEND( l, alignof(ushort),              block_cnt_max*max_shreds_per_block*sizeof(ushort)  );
  void *                _ref_q         = FD_SCRATCH_ALLOC_APPEND( l, ref_q_align(),                ref_q_footprint( block_cnt_max )                   );
  fd_txn_p_t *          _txn_pool      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txn_p_t),          depth_i*sizeof(fd_txn_p_t)                         );
  fd_sched_txn_info_t * _txn_info_pool = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sched_txn_info_t), depth_i*sizeof(fd_sched_txn_info_t)                );
  fd_sched_mblk_t *     _mblk_pool     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sched_mblk_t),     depth_i*sizeof(fd_sched_mblk_t)                    );
  void *                _lthash        = FD_SCRATCH_ALLOC_APPEND( l, fd_sched_lthash_align(),      sched_lthash_footprint( lthash_oob )               );
  void *                _lthash_delta  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_lthash_value_t),   sched_lthash_delta_sz( block_cnt_max, lthash_oob ) );
  void *                _lthash_batch  = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),               sched_lthash_batch_sz( lthash_oob )                );
  FD_SCRATCH_ALLOC_FINI( l, fd_sched_align() );

  sched->txn_pool      = _txn_pool;
  sched->txn_info_pool = _txn_info_pool;
  sched->mblk_pool     = _mblk_pool;

  fd_rdisp_new( _rdisp, depth_i, block_cnt_max, fd_rng_ulong( rng ) );

  if( FD_LIKELY( lthash_oob ) ) {
    FD_TEST( fd_sched_lthash_new( _lthash, FD_RDISP_MAX_WRITERS_PER_BLOCK, FD_SCHED_LTHASH_SPEC_MAX, fd_rng_ulong( rng ) ) );
    fd_memset( _lthash_delta, 0, sched_lthash_delta_sz( block_cnt_max, lthash_oob ) );
    fd_memset( _lthash_batch, 0, sched_lthash_batch_sz( lthash_oob ) );
  }

  fd_sched_block_t * bpool = (fd_sched_block_t *)_bpool;
  for( ulong i=0; i<block_cnt_max; i++ ) {
    bpool[ i ].in_sched = 0;
    lthash_block_init( bpool+i );
    mblk_slist_new( bpool[ i ].mblks_unhashed );
    mblk_slist_new( bpool[ i ].mblks_hashing_in_progress );
    mblk_slist_new( bpool[ i ].mblks_mixin_in_progress );
  }

  FD_TEST( fd_chkdup_new( sched->chkdup, rng ) );

  fd_memset( sched->metrics, 0, sizeof(fd_sched_metrics_t) );
  sched->txn_in_flight_last_tick  = LONG_MAX;
  sched->next_ready_last_tick     = LONG_MAX;
  sched->next_ready_last_bank_idx = ULONG_MAX;

  sched->is_alpenglow           = is_alpenglow;
  sched->canary                 = FD_SCHED_MAGIC;
  sched->depth                  = depth_i;
  sched->lthash_oob             = !!lthash_oob;
  sched->lthash_draining_cnt    = 0U;
  sched->lthash_reserve         = depth_i-depth;
  sched->block_cnt_max          = block_cnt_max;
  sched->max_shreds_per_block   = max_shreds_per_block;
  sched->max_txn_per_slot       = max_txn_per_slot;
  sched->max_mblk_per_slot      = fd_ulong_min( FD_SCHED_MAX_MBLK_PER_SLOT*max_shreds_per_block/FD_SHRED_BLK_MAX, UINT_MAX ); /* mblk_cnt is uint */
  sched->exec_cnt               = exec_cnt;
  sched->poh_simd_max           = fd_sha256_simd_lane_max(); FD_CHECK_ERR( sched->poh_simd_max<=FD_SCHED_POH_PARA, "overly wide PoH SHA batch" );
  sched->poh_simd_min           = fd_sha256_simd_lane_min();
  sched->bypass_poh_verify      = 0;
  sched->bypass_alut_resolution = 0;
  sched->root_idx               = ULONG_MAX;
  sched->active_bank_idx        = ULONG_MAX;
  sched->last_active_bank_idx   = ULONG_MAX;
  sched->staged_bitset          = 0UL;
  for( ulong l=0UL; l<FD_SCHED_MAX_STAGING_LANES; l++ ) sched->staged_head_bank_idx[ l ] = ULONG_MAX;
  sched->staged_popcnt_wmk      = 0UL;

  sched->txn_exec_ready_bitset[ 0 ]  = fd_ulong_mask_lsb( (int)exec_cnt );
  sched->sigverify_ready_bitset[ 0 ] = fd_ulong_mask_lsb( (int)exec_cnt );
  sched->poh_ready_bitset[ 0 ]       = fd_ulong_mask_lsb( (int)exec_cnt );
  sched->cert_ready_bitset[ 0 ]      = fd_ulong_mask_lsb( (int)exec_cnt );
  sched->lthash_ready_bitset[ 0 ]    = fd_ulong_mask_lsb( (int)exec_cnt );

  sched->txn_pool_free_cnt = depth_i-1UL; /* -1 because index 0 is unusable as a sentinel reserved by the dispatcher */

  for( ulong i=0UL; i<depth_i-1UL; i++ ) sched->mblk_pool[ i ].next = (uint)(i+1UL);
  sched->mblk_pool[ depth_i-1UL ].next = UINT_MAX;
  sched->mblk_pool_free_head = 0U;
  sched->mblk_pool_free_cnt  = depth_i;

  txn_bitset_new( sched->exec_done_set );
  txn_bitset_new( sched->sigverify_done_set );
  txn_bitset_new( sched->poh_mixin_done_set );

  sched->block_pool_popcnt = 0UL;

  ref_q_new( _ref_q, block_cnt_max );

  return sched;
}

fd_sched_t *
fd_sched_join( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  fd_sched_t * sched         = (fd_sched_t *)mem;
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  ulong        depth                = sched->depth; /* inflated */
  ulong        block_cnt_max        = sched->block_cnt_max;
  ulong        max_shreds_per_block = sched->max_shreds_per_block;
  int          lthash_oob           = sched->lthash_oob;

  FD_SCRATCH_ALLOC_INIT( l, mem );
  /*                        */ FD_SCRATCH_ALLOC_APPEND( l, fd_sched_align(),             sizeof(fd_sched_t)                                 );
  void *           _rdisp    = FD_SCRATCH_ALLOC_APPEND( l, fd_rdisp_align(),             fd_rdisp_footprint( depth, block_cnt_max )         );
  void *           _bpool    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sched_block_t),    block_cnt_max*sizeof(fd_sched_block_t)             );
  void *           _shred_sz = FD_SCRATCH_ALLOC_APPEND( l, alignof(ushort),              block_cnt_max*max_shreds_per_block*sizeof(ushort)  );
  void *           _ref_q    = FD_SCRATCH_ALLOC_APPEND( l, ref_q_align(),                ref_q_footprint( block_cnt_max )                   );
  /*                        */ FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txn_p_t),          depth*sizeof(fd_txn_p_t)                           );
  /*                        */ FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sched_txn_info_t), depth*sizeof(fd_sched_txn_info_t)                  );
  /*                        */ FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sched_mblk_t),     depth*sizeof(fd_sched_mblk_t)                      );
  void *           _lthash   = FD_SCRATCH_ALLOC_APPEND( l, fd_sched_lthash_align(),      sched_lthash_footprint( lthash_oob )               );
  void *           _delta    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_lthash_value_t),   sched_lthash_delta_sz( block_cnt_max, lthash_oob ) );
  void *           _batch    = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),               sched_lthash_batch_sz( lthash_oob )                );
  FD_SCRATCH_ALLOC_FINI( l, fd_sched_align() );

  sched->rdisp      = fd_rdisp_join( _rdisp );
  sched->ref_q      = ref_q_join( _ref_q );
  sched->block_pool = _bpool;
  sched->shred_sz   = _shred_sz;
  if( FD_LIKELY( lthash_oob ) ) {
    sched->lthash           = fd_sched_lthash_join( _lthash );
    sched->lthash_delta     = (fd_lthash_value_t *)_delta;
    sched->lthash_inflight  = (fd_sched_lthash_batch_t *)_batch;
    sched->lthash_add_batch = sched->lthash_inflight+FD_SCHED_MAX_EXEC_TILE_CNT;
    FD_TEST( sched->lthash );
  } else {
    sched->lthash           = NULL;
    sched->lthash_delta     = NULL;
    sched->lthash_inflight  = NULL;
    sched->lthash_add_batch = NULL;
  }

  for( ulong i=0; i<block_cnt_max; i++ ) {
    mblk_slist_join( sched->block_pool[ i ].mblks_unhashed );
    mblk_slist_join( sched->block_pool[ i ].mblks_hashing_in_progress );
    mblk_slist_join( sched->block_pool[ i ].mblks_mixin_in_progress );
  }

  txn_bitset_join( sched->exec_done_set );
  txn_bitset_join( sched->sigverify_done_set );
  txn_bitset_join( sched->poh_mixin_done_set );

  return sched;
}

int
fd_sched_fec_can_ingest( fd_sched_t * sched, fd_sched_fec_t * fec ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  FD_TEST( fec->bank_idx<sched->block_cnt_max );
  FD_TEST( fec->parent_bank_idx<sched->block_cnt_max );
  if( FD_UNLIKELY( fec_waits_for_lane( sched, fec->parent_bank_idx, fec->is_first_in_block ) ) ) {
    sched->metrics->lane_wait_cnt++;
    return 0;
  }

  if( FD_UNLIKELY( fec->fec->data_sz>FD_SCHED_MAX_PAYLOAD_PER_FEC ) ) {
    sched->print_buf_sz = 0UL;
    print_metrics( sched );
    print_sched( sched );
    FD_LOG_NOTICE(( "%s", sched->print_buf ));
    FD_LOG_CRIT(( "invalid FEC set: fec->data_sz %u, slot %lu, parent slot %lu", fec->fec->data_sz, fec->slot, fec->parent_slot ));
  }

  ulong fec_buf_sz = 0UL;
  fd_sched_block_t * block = block_pool_ele( sched, fec->bank_idx );
  if( FD_LIKELY( !fec->is_first_in_block ) ) {
    fec_buf_sz += block->fec_buf_sz-block->fec_buf_soff;
  } else {
    /* No residual data as this is a fresh new block. */
  }
  /* Addition is safe and won't overflow because we checked the FEC set
     size above. */
  fec_buf_sz += fec->fec->data_sz;
  /* Assuming every transaction is min size, do we have enough free
     entries in the txn pool?  For a more precise txn count, we would
     have to do some parsing.

     The LtHash reserve is never given to transactions. */
  ulong txn_pool_avail_cnt = fd_ulong_if( sched->txn_pool_free_cnt>sched->lthash_reserve, sched->txn_pool_free_cnt-sched->lthash_reserve, 0UL );
  return txn_pool_avail_cnt>=fec_buf_sz/FD_TXN_MIN_SERIALIZED_SZ && sched->mblk_pool_free_cnt>=fec_buf_sz/sizeof(fd_microblock_hdr_t);
}

ulong
fd_sched_can_ingest_cnt( fd_sched_t * sched ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  /* Worst case, we need one byte from the incoming data to extract a
     transaction out of the residual data, and the rest of the incoming
     data contributes toward min sized transactions. */
  ulong txn_pool_avail_cnt = fd_ulong_if( sched->txn_pool_free_cnt>sched->lthash_reserve, sched->txn_pool_free_cnt-sched->lthash_reserve, 0UL );
  return fd_ulong_min( txn_pool_avail_cnt/FD_SCHED_MAX_TXN_PER_FEC, sched->mblk_pool_free_cnt/FD_SCHED_MAX_MBLK_PER_FEC );
}

int
fd_sched_fec_waits_for_lane( fd_sched_t * sched,
                             ulong        parent_bank_idx,
                             int          is_first_in_block ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  if( FD_LIKELY( !fec_waits_for_lane( sched, parent_bank_idx, is_first_in_block ) ) ) return 0;
  sched->metrics->lane_wait_cnt++;
  return 1;
}

int
fd_sched_is_drained( fd_sched_t * sched ) {
  int nothing_inflight = sched->exec_cnt==(ulong)fd_ulong_popcnt( sched->txn_exec_ready_bitset[ 0 ]&sched->sigverify_ready_bitset[ 0 ]&sched->poh_ready_bitset[ 0 ]&sched->cert_ready_bitset[ 0 ]&sched->lthash_ready_bitset[ 0 ] );
  int nothing_queued = sched->active_bank_idx==ULONG_MAX;
  return nothing_inflight && nothing_queued;
}

ulong
fd_sched_cert_dispatch( fd_sched_t * sched,
                        ulong        bank_idx,
                        ulong        cnt ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  FD_TEST( bank_idx==sched->active_bank_idx );
  fd_sched_block_t * block = block_pool_ele( sched, bank_idx );
  FD_TEST( block->block_end_signaled && !block->block_end_done );
  ulong idle    = sched->txn_exec_ready_bitset[ 0 ]&sched->sigverify_ready_bitset[ 0 ]&sched->poh_ready_bitset[ 0 ]&sched->cert_ready_bitset[ 0 ]&sched->lthash_ready_bitset[ 0 ];
  ulong claimed = 0UL;
  for( ; idle && cnt; cnt--, idle=fd_ulong_pop_lsb( idle ) ) {
    int t = fd_ulong_find_lsb( idle );
    claimed = fd_ulong_set_bit( claimed, t );
    sched->tile_to_bank_idx[ t ] = bank_idx;
    block->cert_in_flight_cnt++;
  }
  sched->cert_ready_bitset[ 0 ] &= ~claimed;
  return claimed;
}

int
fd_sched_block_start_pending( fd_sched_t * sched ) {
  return sched->active_bank_idx!=ULONG_MAX && !block_pool_ele( sched, sched->active_bank_idx )->block_start_signaled;
}

FD_WARN_UNUSED int
fd_sched_fec_ingest( fd_sched_t *     sched,
                     fd_sched_fec_t * fec ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  FD_TEST( fec->bank_idx<sched->block_cnt_max );
  FD_TEST( fec->parent_bank_idx<sched->block_cnt_max );
  FD_TEST( ref_q_empty( sched->ref_q ) );

  fd_sched_block_t * block = block_pool_ele( sched, fec->bank_idx );

  if( FD_UNLIKELY( fec->fec->data_sz>FD_SCHED_MAX_PAYLOAD_PER_FEC ) ) {
    sched->print_buf_sz = 0UL;
    print_all( sched, block );
    FD_LOG_NOTICE(( "%s", sched->print_buf ));
    FD_LOG_CRIT(( "invalid FEC set: fec->data_sz %u, slot %lu, parent slot %lu", fec->fec->data_sz, fec->slot, fec->parent_slot ));
  }

  sched->metrics->fec_cnt++;

  if( FD_UNLIKELY( fec->is_first_in_block ) ) {
    /* This is a new block. */
    add_block( sched, fec->bank_idx, fec->parent_bank_idx );
    block->slot        = fec->slot;
    block->parent_slot = fec->parent_slot;

    if( FD_UNLIKELY( block->dying ) ) {
      /* The child of a dead block is also dead.  We added it to our
         fork tree just so we could track an entire lineage of dead
         children and propagate the dead property to the entire lineage,
         in case there were frags for more than one dead children
         in-flight at the time the parent was abandoned.  That being
         said, we shouldn't need to add the dead child to the
         dispatcher. */
      sched->metrics->block_added_dead_ood_cnt++;

      /* Release the refcnt right away since we don't intend to replay
         it at all.  We do this so its bank does not linger and stall
         root advancement until the next root notify. */
      subtree_release_refcnt( sched, block );

      /* Ignore the FEC set for a dead block. */
      sched->metrics->bytes_dropped_cnt += fec->fec->data_sz;
      return 0;
    }

    /* A block whose parent is staged or done takes a free lane of its
       own.  A child of an unstaged stageable parent will be unstaged
       too.  This is not only lazy, sparing a promotion of the parent
       right now, but an invariant that keeps a lane shortage from
       deadlocking replay, since a staged block then never has an
       unstaged parent that still has to run.  See the lane eviction
       comments in try_activate_block(). */
    fd_sched_block_t * parent_block = block_pool_ele( sched, fec->parent_bank_idx );
    int needs_lane = parent_block->staged || !block_is_stageable( parent_block );
    if( FD_LIKELY( needs_lane && sched->staged_bitset!=fd_ulong_mask_lsb( FD_SCHED_MAX_STAGING_LANES ) ) ) {
      /* A lane is free. */
      int lane_idx = pick_free_lane( sched );
      sched->staged_bitset = fd_ulong_set_bit( sched->staged_bitset, lane_idx );
      sched->staged_head_bank_idx[ lane_idx ] = fec->bank_idx;
      sched->staged_popcnt_wmk = fd_ulong_max( sched->staged_popcnt_wmk, (ulong)fd_ulong_popcnt( sched->staged_bitset ) );
      block->in_rdisp     = 1;
      block->staged       = 1;
      block->staging_lane = (ulong)lane_idx;
      fd_rdisp_add_block( sched->rdisp, fec->bank_idx, block->staging_lane );
      lthash_claim_lane_map( sched, block );
      sched->metrics->block_added_cnt++;
      sched->metrics->block_added_staged_cnt++;
      FD_LOG_DEBUG(( "block %lu:%lu entered lane %lu: add", block->slot, fec->bank_idx, block->staging_lane ));
    } else {
      /* The parent is unstaged, or no lane is free.  The block will be
         unstaged until it is promoted. */
      block->in_rdisp = 1;
      block->staged   = 0;
      fd_rdisp_add_block( sched->rdisp, fec->bank_idx, FD_RDISP_UNSTAGED );
      sched->metrics->block_added_cnt++;
      sched->metrics->block_added_unstaged_cnt++;
      FD_LOG_DEBUG(( "block %lu:%lu entered lane unstaged: add", block->slot, fec->bank_idx ));
    }
  }

  block->txn_pool_max_popcnt   = fd_ulong_max( block->txn_pool_max_popcnt, sched->depth - sched->txn_pool_free_cnt - 1UL );
  block->mblk_pool_max_popcnt  = fd_ulong_max( block->mblk_pool_max_popcnt, sched->depth - sched->mblk_pool_free_cnt );
  block->block_pool_max_popcnt = fd_ulong_max( block->block_pool_max_popcnt, sched->block_pool_popcnt );

  if( FD_UNLIKELY( block->dying ) ) {
    /* Ignore the FEC set for a dead block. */
    sched->metrics->bytes_dropped_cnt += fec->fec->data_sz;
    return 1;
  }

  if( FD_UNLIKELY( !block->in_rdisp ) ) {
    /* Invariant: block must be in the dispatcher at this point. */
    sched->print_buf_sz = 0UL;
    print_all( sched, block );
    FD_LOG_NOTICE(( "%s", sched->print_buf ));
    FD_LOG_CRIT(( "invariant violation: block->in_rdisp==0, slot %lu, parent slot %lu",
                  block->slot, block->parent_slot ));
  }

  if( FD_UNLIKELY( block->fec_eos ) ) {
    /* This means something is wrong upstream.  We're getting more FEC
       sets for a block that has already ended, or so we were told. */
    sched->print_buf_sz = 0UL;
    print_all( sched, block );
    FD_LOG_NOTICE(( "%s", sched->print_buf ));
    FD_LOG_CRIT(( "invariant violation: block->fec_eos set but getting more FEC sets, slot %lu, parent slot %lu", fec->slot, fec->parent_slot ));
  }
  if( FD_UNLIKELY( block->fec_eob ) ) {
    /* fec_eob is only ever set from is_last_in_batch, and the parser is
       expected to finish a batch in full upon getting the FEC set that
       ends the batch.  An incomplete parse is caught eagerly below,
       which marks the block dying and is caught above.  Getting here
       means the eager check below regressed. */
    sched->print_buf_sz = 0UL;
    print_all( sched, block );
    FD_LOG_NOTICE(( "%s", sched->print_buf ));
    FD_LOG_CRIT(( "invariant violation: block->fec_eob set but getting more FEC sets, slot %lu, parent slot %lu", fec->slot, fec->parent_slot ));
  }
  if( FD_UNLIKELY( block->child_idx!=ULONG_MAX ) ) {
    /* This means something is wrong upstream.  FEC sets are not being
       delivered in replay order.  We got a child block FEC set before
       this block was completely delivered. */
    sched->print_buf_sz = 0UL;
    print_all( sched, block );
    fd_sched_block_t * child_block = block_pool_ele( sched, block->child_idx );
    print_block_debug( sched, child_block );
    FD_LOG_NOTICE(( "%s", sched->print_buf ));
    FD_LOG_CRIT(( "invariant violation: block->child_idx %lu, slot %lu, parent slot %lu", block->child_idx, fec->slot, fec->parent_slot ));
  }

  FD_TEST( block->fec_buf_sz>=block->fec_buf_soff );
  if( FD_LIKELY( block->fec_buf_sz>block->fec_buf_soff ) ) {
    /* If there is residual data from the previous FEC set within the
       same batch, we move it to the beginning of the buffer and append
       the new FEC set. */
    memmove( block->fec_buf, block->fec_buf+block->fec_buf_soff, block->fec_buf_sz-block->fec_buf_soff );
  }
  block->fec_buf_boff += block->fec_buf_soff;
  block->fec_buf_sz   -= block->fec_buf_soff;
  block->fec_buf_soff  = 0;
  /* Addition is safe and won't overflow because we checked the FEC
     set size above. */
  if( FD_UNLIKELY( block->fec_buf_sz+fec->fec->data_sz>FD_SCHED_MAX_FEC_BUF_SZ ) ) {
    /* The residual carried over from the previous parse is bounded: it
       can only be a partial transaction or a microblock/batch header
       that straddles a FEC set boundary.  Any trailing bytes past the
       last microblock within the same batch are discarded by the
       parser, so they never contribute to the residual.  So residual <=
       max(sizeof(ulong), sizeof(fd_microblock_hdr_t), FD_TXN_MTU), and
       the buffer is sized to always fit the residual plus a single FEC
       set.  Otherwise, it's a bad block.  Instead of crashing, we
       should refuse to replay down the fork. */
    FD_LOG_INFO(( "bad block: UNPARSEABLE_CONTENT, fec_buf_sz %u, fec->data_sz %u, slot %lu, parent slot %lu", block->fec_buf_sz, fec->fec->data_sz, fec->slot, fec->parent_slot ));
    handle_bad_block( sched, block, FD_SCHED_DEAD_REASON_UNPARSEABLE_CONTENT );
    sched->metrics->bytes_dropped_cnt += fec->fec->data_sz;
    return 0;
  }

  /* Append the new FEC set to the end of the buffer. */
  fd_memcpy( block->fec_buf+block->fec_buf_sz, fec->data, fec->fec->data_sz );
  block->fec_buf_sz += (uint)fec->fec->data_sz;
  sched->metrics->bytes_ingested_cnt += fec->fec->data_sz;

  block->fec_eob = fec->is_last_in_batch;
  block->fec_eos = fec->is_last_in_block;

  ushort * shred_sz = sched->shred_sz + fec->bank_idx*sched->max_shreds_per_block;
  ulong tracked_shred_cnt = fd_ulong_min( fec->shred_cnt, FD_FEC_SHRED_CNT );
  uint  tracked_data_sz   = 0U;
  for( ulong i=0UL; i<tracked_shred_cnt; i++ ) tracked_data_sz += fec->fec->shred_sz[ i ];
  if( FD_LIKELY( fec->shred_cnt<=FD_FEC_SHRED_CNT ) ) FD_TEST( tracked_data_sz==fec->fec->data_sz );
  else                                                FD_TEST( tracked_data_sz<=fec->fec->data_sz );

  uint prev_shred_off = 0U;
  for( ulong i=0; i<fec->shred_cnt; i++ ) {
    FD_TEST( block->shred_cnt<sched->max_shreds_per_block );
    uint shred_off;
    if( FD_LIKELY( i<FD_FEC_SHRED_CNT ) ) {
      shred_off = prev_shred_off + fec->fec->shred_sz[ i ];
    } else if( FD_UNLIKELY( i!=fec->shred_cnt-1UL ) ) {
      /* We don't track shred boundaries after 32 shreds, assume they're
         sized uniformly */
      ulong num_overflow_shreds = fec->shred_cnt-FD_FEC_SHRED_CNT;
      ulong overflow_idx        = i-FD_FEC_SHRED_CNT;
      ulong overflow_data_sz    = (ulong)fec->fec->data_sz-tracked_data_sz;
      shred_off = tracked_data_sz + (uint)(overflow_data_sz / num_overflow_shreds * (overflow_idx + 1UL));
    } else {
      shred_off = (uint)fec->fec->data_sz;
    }
    FD_TEST( shred_off>=prev_shred_off && shred_off-prev_shred_off<=USHORT_MAX );
    shred_sz[ block->shred_cnt++ ] = (ushort)(shred_off-prev_shred_off);
    prev_shred_off = shred_off;
  }

  block->fec_completed_ns = fec->completed_ns;

  int err = fd_sched_parse( sched, block, fec->alut_ctx );

  if( FD_UNLIKELY( err!=FD_SCHED_DEAD_REASON_NONE ) ) {
    handle_bad_block( sched, block, err );
    sched->metrics->bytes_dropped_cnt += block->fec_buf_sz-block->fec_buf_soff;
    return 0;
  }

  if( FD_UNLIKELY( (fec->is_last_in_batch||fec->is_last_in_block) && (block->txns_rem||block->mblks_rem||block->fec_eob) ) ) {
    /* A malformed block that fails to parse out exactly as many
       transactions and microblocks as it should.

       Upon getting a last-in-batch FEC, everything in the ongoing batch
       should completely parse, and the eob flag should be reset.  There
       should be no go around for a last-in-batch FEC. */
    FD_LOG_INFO(( "bad block: SHORT_BLOCK, bytes_rem %u, txns_rem %lu, mblks_rem %lu, fec_eob %d, slot %lu, parent slot %lu", block->fec_buf_sz-block->fec_buf_soff, block->txns_rem, block->mblks_rem, block->fec_eob, block->slot, block->parent_slot ));
    handle_bad_block( sched, block, FD_SCHED_DEAD_REASON_SHORT_BLOCK );
    return 0;
  }

  if( FD_UNLIKELY( block->fec_eos && !block->last_mblk_is_tick ) ) {
    /* The last microblock should be a tick.

       Note that this early parse-time detection could cause us to throw
       a slightly different error from Agave, in the case that there are
       too few ticks, since the tick count check precedes the trailing
       entry check in Agave.  That being said, ultimately a
       TRAILING_ENTRY renders a block invalid, regardless of anything
       else. */
    FD_LOG_INFO(( "bad block: TRAILING_ENTRY, slot %lu, parent slot %lu, mblk_cnt %u", block->slot, block->parent_slot, block->mblk_cnt ));
    handle_bad_block( sched, block, FD_SCHED_DEAD_REASON_TRAILING_ENTRY );
    return 0;
  }

  if( FD_UNLIKELY( block->fec_eos && sched->is_alpenglow ) ) {
    int dead_reason = ag_on_final( block );
    if( FD_UNLIKELY( dead_reason!=FD_SCHED_DEAD_REASON_NONE ) ) {
      handle_bad_block( sched, block, dead_reason );
      return 0;
    }
  }

  /* We just received a FEC set, which may have made all transactions in
     a partially parsed microblock available.  If this were a malformed
     block that ends in a non-tick microblock, there's not going to be a
     hashing task from the missing ending tick to drain the mixin queue.
     So we try to drain the mixin queue right here.  Another option is
     to drain it at dispatch time, when we are about to dispatch the end
     of block signal, right before the check for whether block should
     end. */
  int mixin_res;
  while( (mixin_res=maybe_mixin( sched, block )) ) {
    if( FD_UNLIKELY( mixin_res==-1 ) ) {
      handle_bad_block( sched, block, FD_SCHED_DEAD_REASON_ENTRY_HASH_MISMATCH_INGEST );
      return 0;
    }
    FD_TEST( mixin_res==1||mixin_res==2 );
  }

  /* Every account the block intends to write to has now been observed,
     so give each a pseudo transaction for its LtHash addition.  A first
     chunk is popped here and the rest from fd_sched_task_next_ready,
     see lthash_drain_chunk. */
  if( FD_UNLIKELY( fec->is_last_in_block ) ) lthash_maybe_drain( sched, block, FD_SCHED_LTHASH_DRAIN_CHUNK );

  /* Check if we need to set the active block. */
  check_or_set_active_block( sched );

  return 1;
}

ulong
fd_sched_task_next_ready( fd_sched_t * sched, fd_sched_task_t * out ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  FD_TEST( ref_q_empty( sched->ref_q ) );

  ulong exec_ready_bitset0 = sched->txn_exec_ready_bitset[ 0 ];
  ulong exec_fully_ready_bitset = sched->sigverify_ready_bitset[ 0 ] & sched->poh_ready_bitset[ 0 ] & sched->cert_ready_bitset[ 0 ] & sched->lthash_ready_bitset[ 0 ] & exec_ready_bitset0;
  if( FD_UNLIKELY( !exec_fully_ready_bitset ) ) {
    /* Early exit if no exec tiles available.  Also let's make some
       progress on a pending drain */
    lthash_drain_chunk( sched );
    return 0UL;
  }

  if( FD_UNLIKELY( sched->active_bank_idx==ULONG_MAX ) ) {
    /* No need to try activating a block.  If we're in this state,
       there's truly nothing to execute.  We will activate something
       when we ingest a FEC set with transactions. */
    lthash_clean_released_maps( sched );
    return 0UL;
  }

  out->task_type = FD_SCHED_TT_NULL;

  /* We could in theory reevaluate staging lane allocation here and do
     promotion/demotion as needed.  It's a policy decision to minimize
     fork churn for now and just execute down the same active fork. */

  ulong bank_idx = sched->active_bank_idx;
  fd_sched_block_t * block = block_pool_ele( sched, bank_idx );
  if( FD_UNLIKELY( block_should_deactivate( sched, block ) ) ) {
    sched->print_buf_sz = 0UL;
    print_all( sched, block );
    FD_LOG_NOTICE(( "%s", sched->print_buf ));
    FD_LOG_CRIT(( "invariant violation: active block %lu:%lu is not activatable nor has anything in-flight", block->slot, sched->active_bank_idx ));
  }

  block->txn_pool_max_popcnt   = fd_ulong_max( block->txn_pool_max_popcnt, sched->depth - sched->txn_pool_free_cnt - 1UL );
  block->mblk_pool_max_popcnt  = fd_ulong_max( block->mblk_pool_max_popcnt, sched->depth - sched->mblk_pool_free_cnt );
  block->block_pool_max_popcnt = fd_ulong_max( block->block_pool_max_popcnt, sched->block_pool_popcnt );

  if( FD_UNLIKELY( !block->block_start_signaled ) ) {
    out->task_type = FD_SCHED_TT_BLOCK_START;
    out->block_start->bank_idx        = bank_idx;
    out->block_start->parent_bank_idx = block->parent_idx;
    out->block_start->slot            = block->slot;
    block->block_start_signaled = 1;
    sched->next_ready_last_tick     = fd_tickcount();
    sched->next_ready_last_bank_idx = bank_idx;
    return 1UL;
  }

  /* Transactions, PoH and sigverify take the lowest idle tile.  LtHash
     batches take the highest. */
  ulong exec_tile_idx0 = fd_ulong_if( !!exec_fully_ready_bitset, (ulong)fd_ulong_find_lsb( exec_fully_ready_bitset ), ULONG_MAX );
  ulong exec_tile_idx1 = fd_ulong_if( !!exec_fully_ready_bitset, (ulong)fd_ulong_find_msb( exec_fully_ready_bitset ), ULONG_MAX );
  ulong idle_cnt       = (ulong)fd_ulong_popcnt( exec_fully_ready_bitset );

  /* Every task but a transaction leaves reserve tiles idle, a hash
     batch lthash_reserve.  A hash batch carries at most lthash_cap
     accounts. */
  int   reserve        = idle_reserve( sched, block );
  int   lthash_reserve = lthash_idle_reserve( sched, block );
  ulong lthash_cap     = fd_ulong_if( block->txn_exec_in_flight_cnt>0U, FD_SCHED_LTHASH_BATCH_BUSY_MAX, FD_SCHED_LTHASH_BATCH_MAX );

  ulong exec_queued_cnt = block->txn_parsed_cnt-block->txn_exec_in_flight_cnt-block->txn_exec_done_cnt;
  int   add_unsurfaced  = block->add_created_cnt>block->add_surfaced_cnt; /* Addition pseudo transactions are queued in rdisp along with real transactions. */
  int   add_held        = sched->lthash_oob && sched->lthash_add_batch->cnt>0UL;
  ulong txn_idx = 0UL;
  if( FD_LIKELY( (exec_queued_cnt>0UL || add_unsurfaced || add_held) && idle_cnt ) ) { /* Optimize for no fork switching. */
    /* Transaction execution has the highest priority.  Current mainnet
       block times are very much dominated by critical path transaction
       execution.  To achieve the fastest block replay speed, we can't
       afford to make any mistake in critical path dispatching.  Any
       deviation from perfect critical path dispatching is basically
       irrecoverable.  As such, we try to keep all the exec tiles busy
       with transaction execution, but we allow at most one transaction
       to be in-flight per exec tile.  This is to ensure that whenever a
       critical path transaction completes, we have at least one exec
       tile, e.g. the one that just completed said transaction, readily
       available to continue executing down the critical path. */
    ulong appended_cnt = 0UL; /* Additions this poll batched. */
    txn_idx = fd_rdisp_get_next_ready( sched->rdisp, bank_idx );
    while( FD_UNLIKELY( txn_idx & FD_RDISP_LTHASH_PSEUDO_TXN ) ) {
      /* A pseudo transaction surfaced.  By rdisp's scoring policy we
         know that this implies no real transaction is ready. */
      fd_sched_lthash_entry_t * e = lthash_surface( sched, block, bank_idx, txn_idx );
      if( FD_LIKELY( e ) ) {
        /* ... and the addition is not stale. */
        fd_sched_lthash_batch_t * batch = sched->lthash_add_batch;
        if( FD_UNLIKELY( e->spec_idx!=UINT_MAX ) ) {
          /* This is a speculative addition that was transiently waiting
             on a writer.  While the block may still speculate, the
             speculation goes out under the same idleness policy as
             lthash_speculate(), and could be given up rather than
             forced onto the last idle tile.  Once the block is complete
             it is given up outright.  Giving up creates an addition
             sequenced behind every real transaction, as desired.  If we
             did a speculation here, there's a small chance it might be
             undone. */
          if( FD_LIKELY( !block->fec_eos && idle_cnt>(ulong)reserve ) ) {
            lthash_dispatch_one_add( sched, block, bank_idx, e, txn_idx, (int)exec_tile_idx1, out );
            sched->metrics->lthash_add_batch_held_cnt += (ulong)(batch->cnt>0UL);
            sched->next_ready_last_tick     = fd_tickcount();
            sched->next_ready_last_bank_idx = bank_idx;
            return 1UL;
          }
          lthash_spec_give_up( sched, block, bank_idx, e, txn_idx );
        } else {
          if( FD_UNLIKELY( !batch->cnt ) ) lthash_batch_init( block, batch, bank_idx, FD_SCHED_TT_LTHASH_ADD );
          lthash_batch_append( sched, batch, e, txn_idx );
          appended_cnt++;
          if( FD_UNLIKELY( batch->cnt==FD_SCHED_LTHASH_BATCH_MAX ) ) {
            /* A full batch goes out even if we're down to the last idle
               tile, since the next poll could give us an addition and
               we'll have no space to batch it. */
            lthash_dispatch_held_batch( sched, block, bank_idx, (int)exec_tile_idx1, out );
            sched->next_ready_last_tick     = fd_tickcount();
            sched->next_ready_last_bank_idx = bank_idx;
            return 1UL;
          }
          if( FD_UNLIKELY( batch->cnt>=lthash_cap ) ) {
            /* The batch is big enough to go out.  The addition just
               appended implies no transaction is ready, otherwise rdisp
               would have returned the transaction instead of the
               addition.  So we're not leaving critical path work on the
               table. */
            txn_idx = 0UL;
            break;
          }
        }
      }
      txn_idx = fd_rdisp_get_next_ready( sched->rdisp, bank_idx );
    }
    if( FD_UNLIKELY( sched->lthash_oob && sched->lthash_add_batch->cnt ) ) {
      if( FD_LIKELY( !txn_idx ) ) {
        /* Nothing is ready behind the batch, or the batch is at its
           cap. */
        if( FD_LIKELY( idle_cnt>(ulong)lthash_reserve ) ) {
          lthash_dispatch_held_batch( sched, block, bank_idx, (int)exec_tile_idx1, out );
          /* No real transaction was ready, so let's make some
             progress on a pending drain. */
          lthash_drain_chunk( sched );
          sched->next_ready_last_tick     = fd_tickcount();
          sched->next_ready_last_bank_idx = bank_idx;
          return 1UL;
        }
        /* Too few idle tiles for a hash batch.  The batch stays held
           and goes out from a later call, once a poll finds nothing
           ready and enough tiles are idle. */
        sched->metrics->lthash_add_batch_wait_idle_cnt++;
      } else if( appended_cnt ) {
        /* A real transaction surfaced after we've batched some
           additions in this poll. */
        sched->metrics->lthash_add_batch_held_cnt++;
      }
    }
    if( FD_UNLIKELY( txn_idx==0UL && exec_queued_cnt>0UL ) ) {
      /* There are transactions queued but none ready for execution.
         This implies that there must be in-flight transactions on whose
         completion the queued transactions depend.  Additionally, a
         queued transaction may also be waiting on a dispatched
         speculative addition pseudo transaction. */
      if( FD_UNLIKELY( !block->txn_exec_in_flight_cnt && block->add_surfaced_cnt==block->add_done_cnt ) ) {
        sched->print_buf_sz = 0UL;
        print_all( sched, block );
        FD_LOG_NOTICE(( "%s", sched->print_buf ));
        FD_LOG_CRIT(( "invariant violation: no ready transaction found but block->txn_exec_in_flight_cnt==0" ));
      }

      /* Next up are PoH tasks.  Same dispatching policy as sigverify
         tasks. */
      ulong poh_ready_bitset = exec_fully_ready_bitset;
      ulong poh_hashing_queued_cnt = block->mblk_cnt-block->poh_mblk_in_flight_cnt-block->poh_hashing_done_cnt;
      int   poh_threshold = reserve;
      if( FD_LIKELY( poh_hashing_queued_cnt>0UL && fd_ulong_popcnt( poh_ready_bitset )>poh_threshold ) ) {
        ulong max_cnt = poh_batch_max_cnt( sched, poh_hashing_queued_cnt, (ulong)fd_ulong_popcnt( poh_ready_bitset ), (ulong)poh_threshold );
        dispatch_poh( sched, block, bank_idx, fd_ulong_find_lsb( poh_ready_bitset ), max_cnt, out );
        sched->next_ready_last_tick     = fd_tickcount();
        sched->next_ready_last_bank_idx = bank_idx;
        return 1UL;
      }

      /* Dispatch more sigverify tasks to completely idle tiles over the
         reserve, at most one in flight per tile. */
      ulong sigverify_ready_bitset = exec_fully_ready_bitset;
      ulong sigverify_queued_cnt = block->txn_parsed_cnt-block->txn_sigverify_in_flight_cnt-block->txn_sigverify_done_cnt;
      if( FD_LIKELY( sigverify_queued_cnt>0UL && fd_ulong_popcnt( sigverify_ready_bitset )>reserve ) ) {
        dispatch_sigverify( sched, block, bank_idx, fd_ulong_find_lsb( sigverify_ready_bitset ), out );
        sched->next_ready_last_tick = sched->txn_info_pool[ out->txn_sigverify->txn_idx ].tick_sigverify_disp = fd_tickcount();
        sched->next_ready_last_bank_idx = bank_idx;
        return 1UL;
      }

      /* Next up are LtHash subtractions, under the hash batch reserve.
         No real transaction was ready, so let's make some progress on
         a pending drain. */
      lthash_drain_chunk( sched );
      if( FD_UNLIKELY( lthash_dispatch_sub( sched, block, bank_idx, exec_fully_ready_bitset, lthash_reserve, lthash_cap, out ) ) ) {
        sched->next_ready_last_tick     = fd_tickcount();
        sched->next_ready_last_bank_idx = bank_idx;
        return 1UL;
      }
      return 0UL;
    }
  }
  if( FD_LIKELY( txn_idx ) ) {
    out->task_type = FD_SCHED_TT_TXN_EXEC;
    out->txn_exec->txn_idx  = txn_idx;
    out->txn_exec->bank_idx = bank_idx;
    out->txn_exec->slot     = block->slot;
    out->txn_exec->exec_idx = exec_tile_idx0;
    FD_TEST( out->txn_exec->exec_idx!=ULONG_MAX );

    long now = fd_tickcount();
    ulong delta = (ulong)(now-sched->txn_in_flight_last_tick);
    ulong txn_exec_busy_cnt = sched->exec_cnt-(ulong)fd_ulong_popcnt( exec_ready_bitset0 );
    sched->metrics->txn_none_in_flight_tickcount     += fd_ulong_if( txn_exec_busy_cnt==0UL && sched->txn_in_flight_last_tick!=LONG_MAX, delta, 0UL );
    sched->metrics->txn_weighted_in_flight_tickcount += fd_ulong_if( txn_exec_busy_cnt!=0UL, delta, 0UL );
    sched->metrics->txn_weighted_in_flight_cnt       += delta*txn_exec_busy_cnt;
    sched->txn_in_flight_last_tick = now;

    sched->txn_info_pool[ out->txn_exec->txn_idx ].tick_exec_disp = now;
    sched->txn_info_pool[ out->txn_exec->txn_idx ].exec_tile_idx  = exec_tile_idx0;

    sched->txn_exec_ready_bitset[ 0 ] = fd_ulong_clear_bit( exec_ready_bitset0, (int)exec_tile_idx0);
    sched->tile_to_bank_idx[ exec_tile_idx0 ] = bank_idx;

    block->txn_exec_in_flight_cnt++;
    sched->metrics->txn_max_in_flight_cnt = fd_uint_max( sched->metrics->txn_max_in_flight_cnt, block->txn_exec_in_flight_cnt );

    exec_busy_check( sched, block );
    sched->next_ready_last_tick     = now;
    sched->next_ready_last_bank_idx = bank_idx;
    return 1UL;
  }

  /* At this point txn_queued_cnt==0.  Any unsurfaced addition waits on
     an in-flight writer. */

  /* Next up are PoH tasks.  Same dispatching policy as sigverify. */
  ulong poh_ready_bitset = exec_fully_ready_bitset;
  ulong poh_hashing_queued_cnt = block->mblk_cnt-block->poh_mblk_in_flight_cnt-block->poh_hashing_done_cnt;
  int   poh_threshold = reserve;
  if( FD_LIKELY( poh_hashing_queued_cnt>0UL && fd_ulong_popcnt( poh_ready_bitset )>poh_threshold ) ) {
    ulong max_cnt = poh_batch_max_cnt( sched, poh_hashing_queued_cnt, (ulong)fd_ulong_popcnt( poh_ready_bitset ), (ulong)poh_threshold );
    dispatch_poh( sched, block, bank_idx, fd_ulong_find_lsb( poh_ready_bitset ), max_cnt, out );
    sched->next_ready_last_tick     = fd_tickcount();
    sched->next_ready_last_bank_idx = bank_idx;
    return 1UL;
  }

  /* Try to dispatch a sigverify task to a qualified idle tile. */
  ulong sigverify_ready_bitset = exec_fully_ready_bitset;
  ulong sigverify_queued_cnt = block->txn_parsed_cnt-block->txn_sigverify_in_flight_cnt-block->txn_sigverify_done_cnt;
  if( FD_LIKELY( sigverify_queued_cnt>0UL && fd_ulong_popcnt( sigverify_ready_bitset )>reserve ) ) {
    dispatch_sigverify( sched, block, bank_idx, fd_ulong_find_lsb( sigverify_ready_bitset ), out );
    sched->next_ready_last_tick     = sched->txn_info_pool[ out->txn_sigverify->txn_idx ].tick_sigverify_disp = fd_tickcount();
    sched->next_ready_last_bank_idx = bank_idx;
    return 1UL;
  }

  /* Next up are LtHash subtractions, under the hash batch reserve.
     Same as above, let's make some progress on a pending drain. */
  lthash_drain_chunk( sched );
  if( FD_UNLIKELY( lthash_dispatch_sub( sched, block, bank_idx, exec_fully_ready_bitset, lthash_reserve, lthash_cap, out ) ) ) {
    sched->next_ready_last_tick     = fd_tickcount();
    sched->next_ready_last_bank_idx = bank_idx;
    return 1UL;
  }

  /* Absolutely nothing else left to dispatch.  If the block is alone in
     its lane and is still receiving FEC sets, we will spend the idle
     tiles on speculative additions.  Speculation is the lowest priority
     work there is, though.  So if nothing of the block is in flight and
     another lane head is ready with must-do work, yield. */
  int may_speculate = block_may_speculate( sched, block, 1UL );
  if( FD_LIKELY( may_speculate ) ) {
    if( FD_UNLIKELY( !block_is_in_flight( block ) && other_lane_has_real_work( sched, block ) ) ) {
      FD_LOG_DEBUG(( "reset active_bank_idx %lu: speculation yields", sched->active_bank_idx ));
      sched->last_active_bank_idx = sched->active_bank_idx;
      sched->active_bank_idx = ULONG_MAX;
      sched->metrics->lthash_spec_yield_cnt++;
      try_activate_block( sched );
      return 0UL;
    }
    int spec = lthash_speculate( sched, block, bank_idx, exec_fully_ready_bitset, out );
    if( FD_UNLIKELY( spec>=0 ) ) {
      if( spec ) {
        sched->next_ready_last_tick     = fd_tickcount();
        sched->next_ready_last_bank_idx = bank_idx;
      }
      return (ulong)spec;
    }
  }

  /* A lane set still draining keeps the block from ending, see
     block_lthash_settled, and this call popped a chunk above, so it is
     done.  Without this return, a head whose subtractions and additions
     are all done while its set is not yet empty, because the chunks
     went to another lane's draining block or the chunks are smaller
     than the subtraction batches, would trip the in-flight check
     below. */
  if( FD_UNLIKELY( block->lthash_draining ) ) return 0UL;

  if( FD_UNLIKELY( block_should_signal_end( block ) ) ) {
    FD_TEST( block->block_start_signaled );
    if( FD_UNLIKELY( block->lthash_oob && block->add_owed_cnt ) ) {
      sched->print_buf_sz = 0UL;
      print_all( sched, block );
      FD_LOG_NOTICE(( "%s", sched->print_buf ));
      FD_LOG_CRIT(( "invariant violation: block %lu:%lu ends owing %u additions", block->slot, bank_idx, block->add_owed_cnt ));
    }
    int tick_reason = verify_ticks_final( block );
    if( FD_UNLIKELY( tick_reason!=FD_SCHED_DEAD_REASON_NONE ) ) {
      /* Tick verification can't be done at parse time (except for
         TRAILING_ENTRY), because we may not know the expected number of
         hashes yet.  It can't be driven by transaction dispatch or
         completion, because the block may be empty.  Similarly, it can't
         be driven by PoH hashing, because a bad block may simply not
         have any microblocks. */
      handle_bad_block( sched, block, tick_reason );
      out->task_type = FD_SCHED_TT_MARK_DEAD;
      out->mark_dead->bank_idx = bank_idx;
      sched->next_ready_last_tick     = fd_tickcount();
      sched->next_ready_last_bank_idx = bank_idx;
      return 1UL;
    }
    out->task_type = FD_SCHED_TT_BLOCK_END;
    out->block_end->bank_idx = bank_idx;
    block->block_end_signaled = 1;
    FD_TEST( block->refcnt );
    block->refcnt = 0;
    FD_TEST( ref_q_avail( sched->ref_q ) );
    ref_q_push_tail( sched->ref_q, bank_idx );
    sched->next_ready_last_tick     = fd_tickcount();
    sched->next_ready_last_bank_idx = bank_idx;
    return 1UL;
  }

  /* Nothing queued for the active block.  If we haven't received all
     the FEC sets for it, then return and wait for more FEC sets, while
     there are in-flight transactions.  This is a policy decision to
     minimize fork churn and allow for executing down the current fork
     as much as we can.  If we have received all the FEC sets for it,
     then we'd still like to return and wait for the in-flight
     transactions to retire, before switching to a different block.

     Either way, there should be in-flight transactions.  We deactivate
     the active block the moment we exhausted transactions from it.

     We don't assert block_is_in_flight() here because there might be
     in-flight tasks from dying blocks that are preventing us from
     dispatching anything momentarily.  So we assert the global exec
     tile busy count.  This doesn't lose too much assertion coverage
     since dying blocks are few and far between. */
  ulong total_exec_busy_cnt = sched->exec_cnt-(ulong)fd_ulong_popcnt( exec_fully_ready_bitset );
  if( FD_UNLIKELY( !total_exec_busy_cnt ) ) {
    sched->print_buf_sz = 0UL;
    print_all( sched, block );
    FD_LOG_NOTICE(( "%s", sched->print_buf ));
    FD_LOG_CRIT(( "invariant violation: expected in-flight tasks but none found" ));
  }

  return 0UL;
}

int
fd_sched_task_done( fd_sched_t * sched, ulong task_type, ulong txn_idx, ulong exec_idx, void * data ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );

  ulong bank_idx = ULONG_MAX;
  switch( task_type ) {
    case FD_SCHED_TT_BLOCK_START:
    case FD_SCHED_TT_BLOCK_END: {
      (void)txn_idx;
      (void)data;
      bank_idx = sched->active_bank_idx;
      break;
    }
    case FD_SCHED_TT_TXN_EXEC:
    case FD_SCHED_TT_TXN_SIGVERIFY: {
      (void)data;
      FD_TEST( txn_idx < sched->depth );
      bank_idx = sched->tile_to_bank_idx[ exec_idx ];
      break;
    }
    case FD_SCHED_TT_POH_HASH:
    case FD_SCHED_TT_CERT_VERIFY: {
      (void)txn_idx;
      bank_idx = sched->tile_to_bank_idx[ exec_idx ];
      break;
    }
    case FD_SCHED_TT_LTHASH_SUB:
    case FD_SCHED_TT_LTHASH_ADD: {
      /* Like any other tile task, an LtHash task keeps its block in the
         scheduler and the dispatcher until it lands.  block_is_in_flight
         counts it, which gates abandon, demotion and pruning, and
         BLOCK_END waits on it, so the block checks below hold for a
         result of either kind. */
      FD_TEST( sched->lthash_oob );
      FD_TEST( exec_idx<sched->exec_cnt );
      FD_TEST( data );
      bank_idx = sched->tile_to_bank_idx[ exec_idx ];
      break;
    }
    default: FD_LOG_CRIT(( "unsupported task_type %lu", task_type ));
  }
  fd_sched_block_t * block = block_pool_ele( sched, bank_idx );

  if( FD_UNLIKELY( !block->in_sched ) ) {
    FD_LOG_CRIT(( "invariant violation: block->in_sched==0, block %lu:%lu, parent slot %lu",
                  block->slot, bank_idx, block->parent_slot ));
  }
  if( FD_UNLIKELY( !block->staged ) ) {
    /* Invariant: only staged blocks can have in-flight transactions. */
    FD_LOG_CRIT(( "invariant violation: block->staged==0, block %lu:%lu, parent slot %lu",
                  block->slot, bank_idx, block->parent_slot ));
  }
  if( FD_UNLIKELY( !block->in_rdisp ) ) {
    /* Invariant: staged blocks must be in the dispatcher. */
    FD_LOG_CRIT(( "invariant violation: block->in_rdisp==0, block %lu:%lu, parent slot %lu",
                  block->slot, bank_idx, block->parent_slot ));
  }

  block->txn_pool_max_popcnt   = fd_ulong_max( block->txn_pool_max_popcnt, sched->depth - sched->txn_pool_free_cnt - 1UL );
  block->mblk_pool_max_popcnt  = fd_ulong_max( block->mblk_pool_max_popcnt, sched->depth - sched->mblk_pool_free_cnt );
  block->block_pool_max_popcnt = fd_ulong_max( block->block_pool_max_popcnt, sched->block_pool_popcnt );

  int exec_tile_idx = (int)exec_idx;

  switch( task_type ) {
    case FD_SCHED_TT_BLOCK_START: {
      FD_TEST( !block->block_start_done );
      block->block_start_done = 1;
      break;
    }
    case FD_SCHED_TT_BLOCK_END: {
      /* It may seem redundant to be invoking task_done() on these
         somewhat fake tasks.  But these are necessary to drive state
         transition for empty blocks or slow blocks. */
      FD_TEST( !block->block_end_done );
      block->block_end_done = 1;
      sched->print_buf_sz = 0UL;
      print_block_metrics( sched, block );
      FD_LOG_DEBUG(( "block %lu:%lu replayed fully: %s", block->slot, bank_idx, sched->print_buf ));
      break;
    }
    case FD_SCHED_TT_TXN_EXEC: {
      long now = fd_tickcount();
      ulong delta = (ulong)(now-sched->txn_in_flight_last_tick);
      ulong txn_exec_busy_cnt = sched->exec_cnt-(ulong)fd_ulong_popcnt( sched->txn_exec_ready_bitset[ 0 ] );
      sched->metrics->txn_weighted_in_flight_tickcount += delta;
      sched->metrics->txn_weighted_in_flight_cnt       += delta*txn_exec_busy_cnt;
      sched->txn_in_flight_last_tick = now;

      sched->txn_info_pool[ txn_idx ].tick_exec_done = now;

      block->txn_exec_done_cnt++;
      block->txn_exec_in_flight_cnt--;
      FD_TEST( !fd_ulong_extract_bit( sched->txn_exec_ready_bitset[ 0 ], exec_tile_idx ) );
      sched->txn_exec_ready_bitset[ 0 ] = fd_ulong_set_bit( sched->txn_exec_ready_bitset[ 0 ], exec_tile_idx );
      sched->metrics->txn_exec_done_cnt++;
      txn_bitset_insert( sched->exec_done_set, txn_idx );
      sched->txn_info_pool[ txn_idx ].flags |= FD_SCHED_TXN_EXEC_DONE;
      if( FD_UNLIKELY( (sched->txn_info_pool[ txn_idx ].flags&FD_SCHED_TXN_ALT_UNRESOLVED) && data ) ) {
        fd_sched_txn_alts_t const * alts = fd_type_pun_const( data );
        for( ulong i=0UL; i<alts->cnt; i++ ) lthash_register( sched, block, alts->addrs+i );
        sched->metrics->lthash_late_reg_cnt += (uint)alts->cnt;
      }
      if( txn_bitset_test( sched->sigverify_done_set, txn_idx ) && txn_bitset_test( sched->poh_mixin_done_set, txn_idx ) ) {
        /* Release the txn_idx if all tasks on it are done.  This is
           guaranteed to only happen once per transaction because
           whichever one completed first would not release. */
        if( FD_UNLIKELY( block->txn_idx_tail==(uint)txn_idx ) ) block->txn_idx_tail = 0U;
        fd_rdisp_complete_txn( sched->rdisp, txn_idx, 1 );
        sched->txn_pool_free_cnt++;
        block->txn_done_cnt++;
        sched->metrics->txn_done_cnt++;
      } else {
        fd_rdisp_complete_txn( sched->rdisp, txn_idx, 0 );
      }
      break;
    }
    case FD_SCHED_TT_TXN_SIGVERIFY: {
      sched->txn_info_pool[ txn_idx ].tick_sigverify_done = fd_tickcount();
      block->txn_sigverify_done_cnt++;
      block->txn_sigverify_in_flight_cnt--;
      FD_TEST( !fd_ulong_extract_bit( sched->sigverify_ready_bitset[ 0 ], exec_tile_idx ) );
      sched->sigverify_ready_bitset[ 0 ] = fd_ulong_set_bit( sched->sigverify_ready_bitset[ 0 ], exec_tile_idx );
      sched->metrics->txn_sigverify_done_cnt++;
      txn_bitset_insert( sched->sigverify_done_set, txn_idx );
      sched->txn_info_pool[ txn_idx ].flags |= FD_SCHED_TXN_SIGVERIFY_DONE;
      if( txn_bitset_test( sched->exec_done_set, txn_idx ) && txn_bitset_test( sched->poh_mixin_done_set, txn_idx ) ) {
        /* Release the txn_idx if all tasks on it are done.  This is
           guaranteed to only happen once per transaction because
           whichever one completed first would not release. */
        if( FD_UNLIKELY( block->txn_idx_tail==(uint)txn_idx ) ) block->txn_idx_tail = 0U;
        fd_rdisp_complete_txn( sched->rdisp, txn_idx, 1 );
        sched->txn_pool_free_cnt++;
        block->txn_done_cnt++;
        sched->metrics->txn_done_cnt++;
      }
      break;
    }
    case FD_SCHED_TT_POH_HASH: {
      block->poh_hashing_in_flight_cnt--;
      FD_TEST( !fd_ulong_extract_bit( sched->poh_ready_bitset[ 0 ], exec_tile_idx ) );
      sched->poh_ready_bitset[ 0 ] = fd_ulong_set_bit( sched->poh_ready_bitset[ 0 ], exec_tile_idx );
      fd_execrp_poh_hash_done_msg_t * msg = fd_type_pun( data );
      FD_TEST( msg->cnt && msg->cnt<=FD_EXECRP_POH_PARA );
      fd_sched_poh_hash_t const * task = sched->poh_inflight+exec_tile_idx;
      FD_TEST( msg->cnt==task->cnt );

      /* Once the block is found to be bad, the remaining elements are
         put back on a list so that they get freed along with the
         block. */
      int dead_reason = FD_SCHED_DEAD_REASON_NONE;
      for( ulong i=0UL; i<msg->cnt; i++ ) {
        block->poh_mblk_in_flight_cnt--;
        uint mblk_idx = (uint)task->mblk_idx[ i ];
        fd_sched_mblk_t * mblk = sched->mblk_pool+mblk_idx;
        mblk->curr_hashcnt += task->hashcnt;
        memcpy( mblk->curr_hash, msg->hash+i, sizeof(fd_hash_t) );
        if( FD_UNLIKELY( dead_reason!=FD_SCHED_DEAD_REASON_NONE ) || mblk->curr_hashcnt<mblk->hashcnt ) {
          mblk_slist_idx_push_tail( block->mblks_hashing_in_progress, mblk_idx, sched->mblk_pool );
          continue;
        }
        dead_reason = poh_retire_mblk( sched, block, mblk_idx );
      }
      if( FD_LIKELY( dead_reason==FD_SCHED_DEAD_REASON_NONE ) ) dead_reason = poh_retire_ready_mblks( sched, block );
      if( FD_UNLIKELY( dead_reason!=FD_SCHED_DEAD_REASON_NONE ) ) {
        handle_bad_block( sched, block, dead_reason );
        return dead_reason;
      }
      break;
    }
    case FD_SCHED_TT_CERT_VERIFY: {
      FD_TEST( block->cert_in_flight_cnt );
      block->cert_in_flight_cnt--;
      FD_TEST( !fd_ulong_extract_bit( sched->cert_ready_bitset[ 0 ], exec_tile_idx ) );
      sched->cert_ready_bitset[ 0 ] = fd_ulong_set_bit( sched->cert_ready_bitset[ 0 ], exec_tile_idx );
      break;
    }
    case FD_SCHED_TT_LTHASH_SUB: {
      /* A subtraction is never invalidated.  The parent is frozen, so
         the value does not depend on when it ran. */
      fd_sched_lthash_batch_t const * rec = sched->lthash_inflight+exec_tile_idx;
      FD_TEST( rec->kind==FD_SCHED_TT_LTHASH_SUB && rec->bank_idx==bank_idx && rec->cnt && rec->cnt<=FD_SCHED_LTHASH_BATCH_MAX );
      for( ulong i=0UL; i<rec->cnt; i++ ) {
        fd_sched_lthash_entry_t * e = fd_sched_lthash_entry( sched->lthash, rec->lane, rec->entry_idx[ i ] );
        FD_TEST( e->sub_state==FD_SCHED_LTHASH_SUB_DISPATCHED && e->bank_idx==(uint)bank_idx );
        e->sub_state = (uchar)FD_SCHED_LTHASH_SUB_DONE;
      }
      fd_lthash_sub( sched->lthash_delta+bank_idx, fd_type_pun_const( data ) );
      block->sub_in_flight_cnt -= (uint)rec->cnt;
      block->sub_applied_cnt   += (uint)rec->cnt;
      block->lthash_in_flight_cnt--;
      sched->metrics->lthash_sub_applied_cnt += rec->cnt;
      FD_TEST( !fd_ulong_extract_bit( sched->lthash_ready_bitset[ 0 ], exec_tile_idx ) );
      sched->lthash_ready_bitset[ 0 ] = fd_ulong_set_bit( sched->lthash_ready_bitset[ 0 ], exec_tile_idx );
      break;
    }
    case FD_SCHED_TT_LTHASH_ADD: {
      fd_sched_lthash_batch_t const * rec = sched->lthash_inflight+exec_tile_idx;
      FD_TEST( rec->kind==FD_SCHED_TT_LTHASH_ADD && rec->bank_idx==bank_idx && rec->cnt && rec->cnt<=FD_SCHED_LTHASH_BATCH_MAX );
      /* Entries live until the lane is reset, so the record's entries
         are still these accounts'. */
      ulong stale_cnt = 0UL;
      for( ulong i=0UL; i<rec->cnt; i++ ) {
        fd_sched_lthash_entry_t * e = fd_sched_lthash_entry( sched->lthash, rec->lane, rec->entry_idx[ i ] );
        FD_TEST( e->bank_idx==(uint)bank_idx );
        /* We found out that the account is gonna be rewritten while the
           batch was on the tile, so its value is not final.  Its
           speculation entry, if any, was freed by the rewrite. */
        stale_cnt += (ulong)(rec->ptxn_idx[ i ]!=e->ptxn_idx);
      }
      if( FD_UNLIKELY( stale_cnt ) ) {
        /* Stale hash.  Drop it. */
        if( FD_UNLIKELY( rec->cnt>1UL ) ) {
          /* We're given one sum for a whole batch, so a stale entry
             spoils the batch.  While it might seem like we need to
             handle this case, we actually don't.  A speculative
             addition is the only kind of addition that can be stale
             after it has surfaced, and a speculative addition goes out
             alone.  See more detailed reasoning in fd_sched_lthash.h.
             So getting a stale batch would imply an invariant
             violation.

             This lets a stale batch of one account to be silently
             dropped when it ought to be an invariant violation too. */
          sched->print_buf_sz = 0UL;
          print_all( sched, block );
          FD_LOG_NOTICE(( "%s", sched->print_buf ));
          FD_LOG_CRIT(( "invariant violation: %lu of %lu batched additions of block %lu:%lu were rewritten on the tile", stale_cnt, rec->cnt, block->slot, bank_idx ));
        }
        sched->metrics->lthash_add_dispatched_stale_cnt++;
      } else {
        /* Good hash.  Fold it in. */
        fd_lthash_add( sched->lthash_delta+bank_idx, fd_type_pun_const( data ) );
        for( ulong i=0UL; i<rec->cnt; i++ ) {
          fd_sched_lthash_entry_t * e = fd_sched_lthash_entry( sched->lthash, rec->lane, rec->entry_idx[ i ] );
          FD_TEST( e->add_state==FD_SCHED_LTHASH_ADD_DISPATCHED );
          if( e->spec_idx!=UINT_MAX ) {
            /* A speculative addition is always sent individually. */
            FD_TEST( rec->cnt==1UL );
            fd_memcpy( fd_sched_lthash_spec_entry( sched->lthash, e->spec_idx ), data, sizeof(fd_lthash_value_t) );
            sched->metrics->lthash_spec_applied_cnt++;
          }
          e->add_state = (uchar)FD_SCHED_LTHASH_ADD_DONE;
          e->ptxn_idx  = 0U;
        }
        block->add_applied_cnt += (uint)rec->cnt;
        sched->metrics->lthash_add_applied_cnt += rec->cnt;
      }
      block->add_done_cnt += (uint)rec->cnt;
      for( ulong i=0UL; i<rec->cnt; i++ ) fd_rdisp_complete_txn( sched->rdisp, (ulong)rec->ptxn_idx[ i ], 1 );
      block->lthash_in_flight_cnt--;
      FD_TEST( !fd_ulong_extract_bit( sched->lthash_ready_bitset[ 0 ], exec_tile_idx ) );
      sched->lthash_ready_bitset[ 0 ] = fd_ulong_set_bit( sched->lthash_ready_bitset[ 0 ], exec_tile_idx );
      break;
    }
  }

  if( FD_UNLIKELY( block->dying && !block_is_in_flight( block ) ) ) {
    if( FD_UNLIKELY( sched->active_bank_idx==bank_idx ) ) {
      FD_LOG_CRIT(( "invariant violation: active block %lu:%lu shouldn't be dying, parent slot %lu",
                    block->slot, bank_idx, block->parent_slot ));
    }
    FD_LOG_DEBUG(( "dying block %lu:%lu drained", block->slot, bank_idx ));
    subtree_abandon( sched, block );
    try_activate_block( sched );
    return 0;
  }

  if( FD_UNLIKELY( !block->dying && sched->active_bank_idx!=bank_idx ) ) {
    /* Block is not dead.  So we should be actively replaying it. */
    fd_sched_block_t * active_block = block_pool_ele( sched, sched->active_bank_idx );
    FD_LOG_CRIT(( "invariant violation: sched->active_bank_idx %lu, slot %lu, parent slot %lu, bank_idx %lu, slot %lu, parent slot %lu",
                  sched->active_bank_idx, active_block->slot, active_block->parent_slot,
                  bank_idx, block->slot, block->parent_slot ));
  }

  maybe_switch_block( sched, bank_idx );

  return 0;
}

void
fd_sched_block_abandon( fd_sched_t * sched, ulong bank_idx, int cause ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  FD_TEST( bank_idx<sched->block_cnt_max );

  fd_sched_block_t * block = block_pool_ele( sched, bank_idx );
  if( FD_UNLIKELY( !block->in_sched ) ) {
    FD_LOG_CRIT(( "invariant violation: block->in_sched==0, block %lu:%lu, parent slot %lu",
                  block->slot, bank_idx, block->parent_slot ));
  }

  if( FD_LIKELY( cause==FD_SCHED_ABANDON_DISCARDED && !block->dying ) ) block->discarded = 1;

  FD_LOG_INFO(( "abandoning block %lu:%lu", block->slot, bank_idx ));
  sched->print_buf_sz = 0UL;
  print_all( sched, block );
  FD_LOG_DEBUG(( "%s", sched->print_buf ));

  subtree_abandon( sched, block );
  try_activate_block( sched );
}

int
fd_sched_get_dead_reason( fd_sched_t * sched, ulong bank_idx ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  FD_TEST( bank_idx<sched->block_cnt_max );
  fd_sched_block_t * block = block_pool_ele( sched, bank_idx );
  if( FD_UNLIKELY( !block->in_sched ) ) return FD_SCHED_DEAD_REASON_NONE;
  return block->dead_reason;
}

int
fd_sched_block_is_discarded( fd_sched_t * sched, ulong bank_idx ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  FD_TEST( bank_idx<sched->block_cnt_max );
  fd_sched_block_t * block = block_pool_ele( sched, bank_idx );
  if( FD_UNLIKELY( !block->in_sched ) ) return 0;
  return (int)block->discarded;
}

void
fd_sched_cancel( fd_sched_t * sched, ulong bank_idx ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  FD_TEST( bank_idx<sched->block_cnt_max );

  fd_sched_block_t * block = block_pool_ele( sched, bank_idx );
  if( FD_UNLIKELY( !block->in_sched ) ) return;
  FD_LOG_INFO(( "canceling subtree at block %lu:%lu", block->slot, bank_idx ));
  fd_sched_block_t * parent = block_pool_ele( sched, block->parent_idx );
  if( FD_LIKELY( parent ) ) {
    /* Splice the block out of its parent's children list. */
    ulong block_idx = block_to_idx( sched, block );
    ulong * idx_p = &parent->child_idx;
    while( *idx_p!=block_idx ) {
      idx_p = &(block_pool_ele( sched, *idx_p )->sibling_idx);
    }
    *idx_p = block->sibling_idx;
  }
  subtree_prune( sched, bank_idx, ULONG_MAX );
}

void
fd_sched_block_add_done( fd_sched_t * sched, ulong bank_idx, ulong parent_bank_idx, ulong slot ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  FD_TEST( bank_idx<sched->block_cnt_max );

  fd_sched_block_t * block = block_pool_ele( sched, bank_idx );
  add_block( sched, bank_idx, parent_bank_idx );
  block->slot                   = slot;
  block->fec_eos                = 1;
  block->block_start_signaled   = 1;
  block->block_end_signaled     = 1;
  block->block_start_done       = 1;
  block->block_end_done         = 1;
  block->refcnt                 = 0;
  if( FD_LIKELY( parent_bank_idx!=ULONG_MAX ) ) {
    fd_sched_block_t * parent_block = block_pool_ele( sched, parent_bank_idx );
    block->parent_slot = parent_block->slot;
  }
  if( FD_UNLIKELY( parent_bank_idx==ULONG_MAX ) ) {
    /* Assumes that a NULL parent implies the snapshot slot. */
    block->parent_slot = ULONG_MAX;
    block->rooted      = 1;
    sched->root_idx    = bank_idx;
  }
}

void
fd_sched_advance_root( fd_sched_t * sched, ulong root_idx ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  FD_TEST( root_idx<sched->block_cnt_max );
  FD_TEST( sched->root_idx<sched->block_cnt_max );
  FD_TEST( ref_q_empty( sched->ref_q ) );

  fd_sched_block_t * new_root = block_pool_ele( sched, root_idx );
  fd_sched_block_t * old_root = block_pool_ele( sched, sched->root_idx );
  if( FD_UNLIKELY( !old_root->rooted ) ) {
    FD_LOG_CRIT(( "invariant violation: old_root is not rooted, slot %lu, parent slot %lu",
                  old_root->slot, old_root->parent_slot ));
  }

  /* Early exit if the new root is the same as the old root. */
  if( FD_UNLIKELY( root_idx==sched->root_idx ) ) {
    FD_LOG_INFO(( "new root is the same as the old root, slot %lu, parent slot %lu",
                  new_root->slot, new_root->parent_slot ));
    return;
  }

  subtree_prune( sched, sched->root_idx, root_idx );

  new_root->parent_idx = ULONG_MAX;
  sched->root_idx = root_idx;
}

void
fd_sched_root_notify( fd_sched_t * sched, ulong root_idx ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  FD_TEST( root_idx<sched->block_cnt_max );
  FD_TEST( sched->root_idx<sched->block_cnt_max );
  FD_TEST( ref_q_empty( sched->ref_q ) );

  fd_sched_block_t * block    = block_pool_ele( sched, root_idx );
  fd_sched_block_t * old_root = block_pool_ele( sched, sched->root_idx );
  if( FD_UNLIKELY( !old_root->rooted ) ) {
    FD_LOG_CRIT(( "invariant violation: old_root is not rooted, slot %lu, parent slot %lu",
                  old_root->slot, old_root->parent_slot ));
  }

  /* Early exit if the new root is the same as the old root. */
  if( FD_UNLIKELY( root_idx==sched->root_idx ) ) {
    FD_LOG_INFO(( "new root is the same as the old root, slot %lu, parent slot %lu",
                  block->slot, block->parent_slot ));
    return;
  }

  /* Mark every node from the new root up through its parents to the
     old root as being rooted. */
  fd_sched_block_t * curr = block;
  fd_sched_block_t * prev = NULL;
  while( curr ) {
    if( FD_UNLIKELY( !block_is_done( curr ) ) ) {
      FD_LOG_CRIT(( "invariant violation: rooting a block that is not done, slot %lu, parent slot %lu",
                    curr->slot, curr->parent_slot ));
    }
    if( FD_UNLIKELY( curr->dying ) ) {
      FD_LOG_CRIT(( "invariant violation: rooting a block that is dying, slot %lu, parent slot %lu",
                    curr->slot, curr->parent_slot ));
    }
    if( FD_UNLIKELY( curr->staged ) ) {
      FD_LOG_CRIT(( "invariant violation: rooting a block that is staged, slot %lu, parent slot %lu",
                    curr->slot, curr->parent_slot ));
    }
    if( FD_UNLIKELY( curr->in_rdisp ) ) {
      FD_LOG_CRIT(( "invariant violation: rooting a block that is in the dispatcher, slot %lu, parent slot %lu",
                    curr->slot, curr->parent_slot ));
    }
    curr->rooted = 1;
    prev = curr;
    curr = block_pool_ele( sched, curr->parent_idx );
  }

  /* If we didn't reach the old root, the new root is not a descendant. */
  if( FD_UNLIKELY( prev!=old_root ) ) {
    FD_LOG_CRIT(( "invariant violation: new root is not a descendant of old root, new root slot %lu, parent slot %lu, old root slot %lu, parent slot %lu",
                  block->slot, block->parent_slot, old_root->slot, old_root->parent_slot ));
  }

  ulong old_active_bank_idx    = sched->active_bank_idx;
  uint  old_deactivate_abandon = sched->metrics->deactivate_abandoned_cnt;

  /* Now traverse from old root towards new root, and abandon all
     minority forks. */
  curr = old_root;
  while( curr && curr->rooted && curr!=block ) { /* curr!=block to avoid abandoning good forks. */
    fd_sched_block_t * rooted_child_block = NULL;
    ulong              child_idx          = curr->child_idx;
    while( child_idx!=ULONG_MAX ) {
      fd_sched_block_t * child = block_pool_ele( sched, child_idx );
      child_idx = child->sibling_idx;
      if( child->rooted ) {
        rooted_child_block = child;
      } else {
        /* This is a minority fork.  Consensus converged elsewhere, so
           the fork is discarded rather than invalid.  Mark the subtree
           root as discarded so subtree_abandon() propagates the flag
           down.

           Gated on the block not already going down.  A block that is
           already dying was abandoned for a reason of its own, either
           sched's own verdict or runtime's verdict on its validity, and
           losing the fork choice race afterwards must not re-label it
           discarded. */
        if( FD_LIKELY( !child->dying ) ) child->discarded = 1;

        ulong abandoned_cnt = sched->metrics->block_abandoned_cnt;
        subtree_abandon( sched, child );
        abandoned_cnt = sched->metrics->block_abandoned_cnt-abandoned_cnt;
        if( FD_UNLIKELY( abandoned_cnt ) ) FD_LOG_DEBUG(( "abandoned %lu blocks on minority fork starting at block %lu:%lu", abandoned_cnt, child->slot, block_to_idx( sched, child ) ));
      }
    }
    curr = rooted_child_block;
  }

  /* If the active block got abandoned, we need to reset it. */
  if( sched->active_bank_idx==ULONG_MAX ) {
    /* Count a minority-fork deactivation once, as MinorityFork only */
    sched->metrics->deactivate_abandoned_cnt  = old_deactivate_abandon;
    sched->metrics->deactivate_pruned_cnt    += fd_uint_if( old_active_bank_idx!=ULONG_MAX, 1U, 0U );
    try_activate_block( sched );
  }
}

ulong
fd_sched_pruned_block_next( fd_sched_t * sched ) {
  if( !ref_q_empty( sched->ref_q ) ) {
    ulong bank_idx = ref_q_pop_head( sched->ref_q );
    return bank_idx;
  }
  return ULONG_MAX;
}

void
fd_sched_set_poh_params( fd_sched_t * sched, ulong bank_idx, ulong tick_height, ulong max_tick_height, ulong hashes_per_tick, fd_hash_t const * start_poh ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  FD_TEST( bank_idx<sched->block_cnt_max );
  FD_TEST( max_tick_height>tick_height );
  fd_sched_block_t * block = block_pool_ele( sched, bank_idx );
  block->tick_height = tick_height;
  block->max_tick_height = max_tick_height;
  block->hashes_per_tick = hashes_per_tick;
  #if FD_SCHED_SKIP_POH
  /* No-op. */
  (void)start_poh;
  #else
  if( FD_LIKELY( block->mblk_cnt ) ) {
    /* Fix up the first mblk's curr_hash. */
    FD_TEST( block->mblk_unhashed_cnt );
    FD_TEST( !mblk_slist_is_empty( block->mblks_unhashed, sched->mblk_pool ) );
    FD_TEST( !block->mblk_freed_cnt );
    fd_sched_mblk_t * first_mblk = sched->mblk_pool + mblk_slist_idx_peek_head( block->mblks_unhashed, sched->mblk_pool );
    memcpy( first_mblk->curr_hash, start_poh, sizeof(fd_hash_t) );
  } else {
    memcpy( block->poh_hash, start_poh, sizeof(fd_hash_t) );
  }
  #endif
}

void
fd_sched_set_bypass_poh_verify( fd_sched_t * sched, int bypass_poh_verify ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  sched->bypass_poh_verify = !!bypass_poh_verify;
}

void
fd_sched_set_bypass_alut_resolution( fd_sched_t * sched, int bypass_alut_resolution ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  sched->bypass_alut_resolution = !!bypass_alut_resolution;
}

fd_txn_p_t *
fd_sched_get_txn( fd_sched_t * sched, ulong txn_idx ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  if( FD_UNLIKELY( txn_idx>=sched->depth ) ) {
    return NULL;
  }
  return sched->txn_pool+txn_idx;
}

fd_sched_txn_info_t *
fd_sched_get_txn_info( fd_sched_t * sched, ulong txn_idx ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  if( FD_UNLIKELY( txn_idx>=sched->depth ) ) {
    return NULL;
  }
  return sched->txn_info_pool+txn_idx;
}

fd_hash_t *
fd_sched_get_poh( fd_sched_t * sched, ulong bank_idx ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  FD_TEST( bank_idx<sched->block_cnt_max );
  fd_sched_block_t * block = block_pool_ele( sched, bank_idx );
  FD_TEST( block->fec_eos );
  FD_TEST( block->mblk_cnt );
  return block->poh_hash;
}

uint
fd_sched_get_shred_cnt( fd_sched_t * sched, ulong bank_idx ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  FD_TEST( bank_idx<sched->block_cnt_max );
  fd_sched_block_t * block = block_pool_ele( sched, bank_idx );
  return block->shred_cnt;
}

fd_block_footer_t const *
fd_sched_get_footer( fd_sched_t * sched, ulong bank_idx ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  FD_TEST( bank_idx<sched->block_cnt_max );
  fd_sched_block_t * block = block_pool_ele( sched, bank_idx );
  return block->footer_seen ? &block->footer : NULL;
}

fd_lthash_value_t const *
fd_sched_lthash_delta( fd_sched_t * sched, ulong bank_idx ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  FD_TEST( bank_idx<sched->block_cnt_max );
  if( FD_UNLIKELY( !sched->lthash_oob ) ) return NULL;
  fd_sched_block_t * block = block_pool_ele( sched, bank_idx );
  /* The delta accumulates from the block's first LtHash task on and is
     final once BLOCK_END is signaled.  Completing BLOCK_END zeroes it. */
  FD_TEST( block->in_sched && !block->block_end_done );
  return sched->lthash_delta+bank_idx;
}

void
fd_sched_block_start_writes( fd_sched_t * sched, ulong bank_idx, fd_acct_addr_t const * addrs, ulong cnt ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  FD_TEST( bank_idx<sched->block_cnt_max );
  if( FD_UNLIKELY( !sched->lthash_oob ) ) return;
  fd_sched_block_t * block = block_pool_ele( sched, bank_idx );
  FD_TEST( block->in_sched && block->staged && block->in_rdisp );
  /* We expect this to run during BLOCK_START processing, before any
     real transaction of the block is dispatched. */
  FD_TEST( block->block_start_signaled && !block->block_start_done );
  FD_TEST( !block->txn_exec_in_flight_cnt && !block->txn_exec_done_cnt );
  for( ulong i=0UL; i<cnt; i++ ) lthash_register( sched, block, addrs+i );
  sched->metrics->lthash_start_reg_cnt += (uint)cnt;
}

void
fd_sched_metrics_write( fd_sched_t *            sched,
                        fd_clock_tile_t const * clock ) {
  FD_MGAUGE_SET( REPLAY, SCHED_ACTIVE_BANK_INDEX, sched->active_bank_idx );
  FD_MGAUGE_SET( REPLAY, SCHED_LAST_DISPATCH_BANK_INDEX, sched->next_ready_last_bank_idx );
  FD_MGAUGE_SET( REPLAY, SCHED_LAST_DISPATCH_TIME, sched->next_ready_last_tick==LONG_MAX ? 0UL : (ulong)fd_clock_tile_tickcount_to_wallclock( clock, sched->next_ready_last_tick ) );
  FD_MGAUGE_SET( REPLAY, SCHED_STAGING_LANE_USED, (ulong)fd_ulong_popcnt( sched->staged_bitset ) );
  FD_MGAUGE_SET( REPLAY, SCHED_STAGING_LANE_PEAK, sched->staged_popcnt_wmk );
  ulong staging_lane_head_bank_idx[ FD_METRICS_ENUM_STAGING_LANE_CNT ];
  for( ulong lane=0UL; lane<FD_METRICS_ENUM_STAGING_LANE_CNT; lane++ ) {
    staging_lane_head_bank_idx[ lane ] = fd_ulong_if( fd_ulong_extract_bit( sched->staged_bitset, (int)lane ), sched->staged_head_bank_idx[ lane ], ULONG_MAX );
  }
  FD_MGAUGE_ENUM_COPY( REPLAY, SCHED_STAGING_LANE_HEAD_BANK_INDEX, staging_lane_head_bank_idx );
  FD_MGAUGE_SET( REPLAY, SCHED_TXN_POOL_USED, sched->depth-sched->txn_pool_free_cnt-1UL );
  FD_MGAUGE_SET( REPLAY, SCHED_TXN_POOL_CAPACITY, sched->depth-1UL );
  FD_MGAUGE_SET( REPLAY, SCHED_MICROBLOCK_POOL_USED, sched->depth-sched->mblk_pool_free_cnt );
  FD_MGAUGE_SET( REPLAY, SCHED_MICROBLOCK_POOL_CAPACITY, sched->depth );
  FD_MGAUGE_SET( REPLAY, SCHED_BLOCK_POOL_USED, sched->block_pool_popcnt );
  FD_MGAUGE_SET( REPLAY, SCHED_BLOCK_POOL_CAPACITY, sched->block_cnt_max );

  fd_sched_metrics_t const * m = sched->metrics;

  ulong sched_block_added[ FD_METRICS_ENUM_SCHED_BLOCK_STAGING_STATE_CNT ];
  sched_block_added[ FD_METRICS_ENUM_SCHED_BLOCK_STAGING_STATE_V_STAGED_IDX   ] = m->block_added_staged_cnt;
  sched_block_added[ FD_METRICS_ENUM_SCHED_BLOCK_STAGING_STATE_V_UNSTAGED_IDX ] = m->block_added_unstaged_cnt;
  sched_block_added[ FD_METRICS_ENUM_SCHED_BLOCK_STAGING_STATE_V_DEAD_IDX     ] = m->block_added_dead_ood_cnt;
  FD_MCNT_ENUM_COPY( REPLAY, SCHED_BLOCK_ADDED, sched_block_added );
  FD_MCNT_SET( REPLAY, SCHED_BLOCK_REPLAYED, m->block_removed_cnt );
  FD_MCNT_SET( REPLAY, SCHED_BLOCK_ABANDONED, m->block_abandoned_cnt );
  FD_MCNT_SET( REPLAY, SCHED_BLOCK_REJECTED, m->block_bad_cnt );
  FD_MCNT_SET( REPLAY, SCHED_BLOCK_PROMOTED, m->block_promoted_cnt );
  FD_MCNT_SET( REPLAY, SCHED_BLOCK_DEMOTED, m->block_demoted_cnt );
  ulong sched_deactivate[ FD_METRICS_ENUM_SCHED_DEACTIVATE_REASON_CNT ];
  sched_deactivate[ FD_METRICS_ENUM_SCHED_DEACTIVATE_REASON_V_NO_CHILD_IDX      ] = m->deactivate_no_child_cnt;
  sched_deactivate[ FD_METRICS_ENUM_SCHED_DEACTIVATE_REASON_V_NO_WORK_IDX       ] = m->deactivate_no_txn_cnt;
  sched_deactivate[ FD_METRICS_ENUM_SCHED_DEACTIVATE_REASON_V_ABANDONED_IDX     ] = m->deactivate_abandoned_cnt;
  sched_deactivate[ FD_METRICS_ENUM_SCHED_DEACTIVATE_REASON_V_MINORITY_FORK_IDX ] = m->deactivate_pruned_cnt;
  sched_deactivate[ FD_METRICS_ENUM_SCHED_DEACTIVATE_REASON_V_SPEC_YIELD_IDX    ] = m->lthash_spec_yield_cnt;
  FD_MCNT_ENUM_COPY( REPLAY, SCHED_BLOCK_DEACTIVATED, sched_deactivate );
  FD_MCNT_SET( REPLAY, SCHED_LANE_SWITCHED, m->lane_switch_cnt );
  FD_MCNT_SET( REPLAY, SCHED_LANE_PROMOTED, m->lane_promoted_cnt );
  FD_MCNT_SET( REPLAY, SCHED_LANE_DEMOTED, m->lane_demoted_cnt );
  FD_MCNT_SET( REPLAY, SCHED_LANE_WAITED, m->lane_wait_cnt );
  FD_MCNT_SET( REPLAY, SCHED_FORK_OBSERVED, m->fork_observed_cnt );
  ulong sched_alut[ FD_METRICS_ENUM_SCHED_LUT_RESOLVE_RESULT_CNT ];
  sched_alut[ FD_METRICS_ENUM_SCHED_LUT_RESOLVE_RESULT_V_SUCCESS_IDX ] = m->alut_success_cnt;
  sched_alut[ FD_METRICS_ENUM_SCHED_LUT_RESOLVE_RESULT_V_FAILED_IDX  ] = m->alut_serializing_cnt;
  FD_MCNT_ENUM_COPY( REPLAY, SCHED_TXN_LUT_RESOLVE_ATTEMPTED, sched_alut );
  FD_MCNT_SET( REPLAY, SCHED_TXN_PARSED_ABANDONED, m->txn_abandoned_parsed_cnt );
  FD_MCNT_SET( REPLAY, SCHED_TXN_EXECUTED_ABANDONED, m->txn_abandoned_exec_done_cnt );
  FD_MCNT_SET( REPLAY, SCHED_TXN_DONE_ABANDONED, m->txn_abandoned_done_cnt );
  FD_MCNT_SET( REPLAY, SCHED_TXN_IN_FLIGHT_INTEGRAL_NANOS, m->txn_weighted_in_flight_cnt );
  FD_MCNT_SET( REPLAY, SCHED_TXN_BUSY_DURATION_NANOS, m->txn_weighted_in_flight_tickcount );
  FD_MCNT_SET( REPLAY, SCHED_TXN_IDLE_DURATION_NANOS, m->txn_none_in_flight_tickcount );
  FD_MCNT_SET( REPLAY, SCHED_TXN_PARSED, m->txn_parsed_cnt );
  FD_MCNT_SET( REPLAY, SCHED_TXN_EXECUTED, m->txn_exec_done_cnt );
  FD_MCNT_SET( REPLAY, SCHED_TXN_SIGNATURE_VERIFIED, m->txn_sigverify_done_cnt );
  FD_MCNT_SET( REPLAY, SCHED_TXN_POH_MIXED, m->txn_mixin_done_cnt );
  FD_MCNT_SET( REPLAY, SCHED_TXN_DONE, m->txn_done_cnt );
  FD_MCNT_SET( REPLAY, SCHED_MICROBLOCK_PARSED, m->mblk_parsed_cnt );
  FD_MCNT_SET( REPLAY, SCHED_MICROBLOCK_HASHED, m->mblk_poh_hashed_cnt );
  FD_MCNT_SET( REPLAY, SCHED_MICROBLOCK_DONE, m->mblk_poh_done_cnt );
  FD_MCNT_SET( REPLAY, SCHED_INGESTED_BYTES, m->bytes_ingested_cnt );
  FD_MCNT_SET( REPLAY, SCHED_TRAILING_SKIPPED_BYTES, m->bytes_ingested_unparsed_cnt );
  FD_MCNT_SET( REPLAY, SCHED_DROPPED_BYTES, m->bytes_dropped_cnt );
  FD_MCNT_SET( REPLAY, SCHED_FEC_INGESTED, m->fec_cnt );

  ulong lthash_write[ FD_METRICS_ENUM_SCHED_LTHASH_WRITE_TYPE_CNT ];
  lthash_write[ FD_METRICS_ENUM_SCHED_LTHASH_WRITE_TYPE_V_PARSED_IDX     ] = m->lthash_parsed_writable_cnt;
  lthash_write[ FD_METRICS_ENUM_SCHED_LTHASH_WRITE_TYPE_V_START_REG_IDX  ] = m->lthash_start_reg_cnt;
  lthash_write[ FD_METRICS_ENUM_SCHED_LTHASH_WRITE_TYPE_V_LATE_REG_IDX   ] = m->lthash_late_reg_cnt;
  lthash_write[ FD_METRICS_ENUM_SCHED_LTHASH_WRITE_TYPE_V_DEMOTE_REG_IDX ] = m->lthash_demote_reg_cnt;
  FD_MCNT_ENUM_COPY( REPLAY, SCHED_LTHASH_WRITE_OBSERVED_BY_TYPE, lthash_write );
  ulong lthash_handled[ FD_METRICS_ENUM_SCHED_LTHASH_WRITE_RESULT_CNT ];
  lthash_handled[ FD_METRICS_ENUM_SCHED_LTHASH_WRITE_RESULT_V_FIRST_WRITE_IDX ] = m->lthash_first_write_cnt;
  lthash_handled[ FD_METRICS_ENUM_SCHED_LTHASH_WRITE_RESULT_V_COALESCED_IDX   ] = m->lthash_coalesced_cnt;
  FD_MCNT_ENUM_COPY( REPLAY, SCHED_LTHASH_WRITE_OBSERVED, lthash_handled );
  FD_MCNT_SET( REPLAY, SCHED_LTHASH_ADD_CREATED,         m->lthash_add_created_cnt );
  FD_MCNT_SET( REPLAY, SCHED_LTHASH_ADD_SURFACED,        m->lthash_add_surfaced_cnt );
  FD_MCNT_SET( REPLAY, SCHED_LTHASH_ADD_STALE_SURFACED,  m->lthash_add_surfaced_stale_cnt );
  FD_MCNT_SET( REPLAY, SCHED_LTHASH_ADD_DISPATCHED,      m->lthash_add_dispatched_cnt );
  FD_MCNT_SET( REPLAY, SCHED_LTHASH_ADD_STALE_DROPPED,   m->lthash_add_dispatched_stale_cnt );
  FD_MCNT_SET( REPLAY, SCHED_LTHASH_ADD_APPLIED,         m->lthash_add_applied_cnt );
  FD_MCNT_SET( REPLAY, SCHED_LTHASH_ADD_UNDONE,          m->lthash_add_undone_cnt );
  FD_MCNT_SET( REPLAY, SCHED_LTHASH_SPEC_CREATED,        m->lthash_spec_cnt );
  FD_MCNT_SET( REPLAY, SCHED_LTHASH_SPEC_APPLIED,        m->lthash_spec_applied_cnt );
  FD_MCNT_SET( REPLAY, SCHED_LTHASH_SPEC_INVALIDATED,    m->lthash_spec_stale_cnt );
  FD_MCNT_SET( REPLAY, SCHED_LTHASH_SUB_OWED,            m->lthash_entry_cnt );
  FD_MCNT_SET( REPLAY, SCHED_LTHASH_SUB_DISPATCHED,      m->lthash_sub_dispatched_cnt );
  FD_MCNT_SET( REPLAY, SCHED_LTHASH_SUB_APPLIED,         m->lthash_sub_applied_cnt );
  FD_MCNT_SET( REPLAY, SCHED_LTHASH_ACCOUNT_FROZEN,      m->lthash_frozen_cnt );
  ulong lthash_dropped[ FD_METRICS_ENUM_SCHED_LTHASH_WORK_TYPE_CNT ];
  lthash_dropped[ FD_METRICS_ENUM_SCHED_LTHASH_WORK_TYPE_V_ADD_OWED_IDX    ] = m->lthash_discarded_add_owed_cnt;
  lthash_dropped[ FD_METRICS_ENUM_SCHED_LTHASH_WORK_TYPE_V_ADD_PENDING_IDX ] = m->lthash_discarded_add_pending_cnt;
  lthash_dropped[ FD_METRICS_ENUM_SCHED_LTHASH_WORK_TYPE_V_ADD_APPLIED_IDX ] = m->lthash_discarded_add_applied_cnt;
  lthash_dropped[ FD_METRICS_ENUM_SCHED_LTHASH_WORK_TYPE_V_SUB_QUEUED_IDX  ] = m->lthash_discarded_sub_queued_cnt;
  lthash_dropped[ FD_METRICS_ENUM_SCHED_LTHASH_WORK_TYPE_V_SUB_APPLIED_IDX ] = m->lthash_discarded_sub_applied_cnt;
  lthash_dropped[ FD_METRICS_ENUM_SCHED_LTHASH_WORK_TYPE_V_ADD_HELD_IDX    ] = m->lthash_discarded_add_held_cnt;
  FD_MCNT_ENUM_COPY( REPLAY, SCHED_LTHASH_WORK_DROPPED, lthash_dropped );
  FD_MCNT_SET( REPLAY, SCHED_LTHASH_POOL_FULL_DEACTIVATED, m->lthash_pool_full_cnt );
  ulong lthash_task[ FD_METRICS_ENUM_SCHED_LTHASH_TASK_TYPE_CNT ];
  lthash_task[ FD_METRICS_ENUM_SCHED_LTHASH_TASK_TYPE_V_SUB_IDX ] = m->lthash_sub_task_cnt;
  lthash_task[ FD_METRICS_ENUM_SCHED_LTHASH_TASK_TYPE_V_ADD_IDX ] = m->lthash_add_task_cnt;
  FD_MCNT_ENUM_COPY( REPLAY, SCHED_LTHASH_TASK_DISPATCHED, lthash_task );
  FD_MCNT_SET( REPLAY, SCHED_LTHASH_BATCH_HELD,        m->lthash_add_batch_held_cnt );
  FD_MCNT_SET( REPLAY, SCHED_LTHASH_BATCH_IDLE_WAITED, m->lthash_add_batch_wait_idle_cnt );
}

char *
fd_sched_get_state_cstr( fd_sched_t * sched ) {
  lthash_metrics_check( sched );
  sched->print_buf_sz = 0UL;
  print_metrics( sched );
  print_sched( sched );
  return sched->print_buf;
}

void * fd_sched_leave ( fd_sched_t * sched ) { return sched; }
void * fd_sched_delete( void * mem         ) { return   mem; }


/* Internal helpers. */

static void
add_block( fd_sched_t * sched,
           ulong        bank_idx,
           ulong        parent_bank_idx ) {
  fd_sched_block_t * block = block_pool_ele( sched, bank_idx );
  FD_TEST( !block->in_sched );
  sched->block_pool_popcnt++;

  block->txn_parsed_cnt              = 0U;
  block->txn_exec_in_flight_cnt      = 0U;
  block->txn_exec_done_cnt           = 0U;
  block->txn_sigverify_in_flight_cnt = 0U;
  block->txn_sigverify_done_cnt      = 0U;
  block->poh_hashing_in_flight_cnt   = 0U;
  block->poh_mblk_in_flight_cnt      = 0U;
  block->poh_hashing_done_cnt        = 0U;
  block->poh_hash_cmp_done_cnt       = 0U;
  block->cert_in_flight_cnt          = 0U;
  block->txn_done_cnt                = 0U;
  block->shred_cnt                   = 0U;
  block->shred_scan_idx              = 0U;
  block->shred_scan_off              = 0U;
  block->mblk_cnt                    = 0U;
  block->mblk_freed_cnt              = 0U;
  block->mblk_tick_cnt               = 0U;
  block->mblk_unhashed_cnt           = 0U;
  block->hashcnt                     = 0UL;
  block->dead_reason                 = FD_SCHED_DEAD_REASON_NONE;
  block->txn_pool_max_popcnt         = sched->depth - sched->txn_pool_free_cnt - 1UL;
  block->mblk_pool_max_popcnt        = sched->depth - sched->mblk_pool_free_cnt;
  block->block_pool_max_popcnt       = sched->block_pool_popcnt;
  block->txn_idx_tail                = 0U;
  block->txn_sigverify_next_idx      = 0U;
  block->parse_mblk_idx              = UINT_MAX;

  mblk_slist_remove_all( block->mblks_unhashed, sched->mblk_pool );
  mblk_slist_remove_all( block->mblks_hashing_in_progress, sched->mblk_pool );
  mblk_slist_remove_all( block->mblks_mixin_in_progress, sched->mblk_pool );
  block->last_mblk_is_tick            = 0;
  block->tick_hashcnt_wmk             = 0UL;
  block->curr_tick_hashcnt            = 0UL;
  block->tick_height                  = ULONG_MAX;
  block->max_tick_height              = ULONG_MAX;
  block->hashes_per_tick              = ULONG_MAX;
  block->inconsistent_hashes_per_tick = 0;
  block->zero_hash_tick               = 0;

  block->header_seen        = 0;
  block->genesis_cert_seen  = 0;
  block->update_parent_seen = 0;
  block->footer_seen        = 0;
  block->alpentick_seen     = 0;

  block->mblks_rem        = 0UL;
  block->txns_rem         = 0UL;
  block->fec_buf_sz       = 0U;
  block->fec_buf_boff     = 0U;
  block->fec_buf_soff     = 0U;
  block->poison_cnt       = 0U;
  block->poison_serialize = 0;
  block->fec_eob          = 0;
  block->fec_sob          = 1;

  block->fec_eos              = 0;
  block->rooted               = 0;
  block->dying                = 0;
  block->discarded            = 0;
  block->fec_completed_ns     = 0L;
  block->refcnt               = 1;
  block->in_sched             = 1;
  block->in_rdisp             = 0;
  block->block_start_signaled = 0;
  block->block_end_signaled   = 0;
  block->block_start_done     = 0;
  block->block_end_done       = 0;
  block->staged               = 0;
  block->lthash_oob           = (uint)!!sched->lthash_oob;
  if( FD_LIKELY( sched->lthash_oob ) ) {
    FD_TEST( !block->add_owed_cnt && !block->add_created_cnt && !block->sub_queued_cnt && !block->sub_in_flight_cnt && !block->sub_applied_cnt && !block->lthash_in_flight_cnt && !block->lthash_drained && !block->lthash_draining );
    // FD_TEST( fd_lthash_is_zero( sched->lthash_delta+bank_idx ) );
  }

  block->luf_depth = 0UL;

  /* New leaf node, no child, no sibling. */
  block->child_idx   = ULONG_MAX;
  block->sibling_idx = ULONG_MAX;
  block->parent_idx  = ULONG_MAX;

  if( FD_UNLIKELY( parent_bank_idx==ULONG_MAX ) ) {
    return;
  }

  /* node->parent link */
  fd_sched_block_t * parent_block = block_pool_ele( sched, parent_bank_idx );
  block->parent_idx = parent_bank_idx;

  /* parent->node and sibling->node links */
  ulong child_idx = bank_idx;
  if( FD_LIKELY( parent_block->child_idx==ULONG_MAX ) ) { /* Optimize for no forking. */
    parent_block->child_idx = child_idx;
  } else {
    fd_sched_block_t * curr_block = block_pool_ele( sched, parent_block->child_idx );
    while( curr_block->sibling_idx!=ULONG_MAX ) {
      curr_block = block_pool_ele( sched, curr_block->sibling_idx );
    }
    curr_block->sibling_idx = child_idx;
    sched->metrics->fork_observed_cnt++;
  }

  if( FD_UNLIKELY( parent_block->dying ) ) {
    record_lineage_death( block, parent_block );
    block->dying = 1;
  }
}

/* Alpenglow block structure.  agave's BlockComponentProcessor rules
   an Alpenglow block invalid unless its components are laid out as

     header | [genesis cert] | entries* | [update parent] | entries* | footer | alpentick

   with exactly one header and one footer, and the alpentick as the
   final component.  The helpers below drive the same state machine off
   the batches sched parses. */

static int
ag_on_marker( fd_sched_t *              sched,
              fd_sched_block_t *        block,
              fd_block_marker_t const * marker ) {
  (void)sched;
  switch( marker->kind ) {

  case FD_BLOCK_MARKER_KIND_HEADER:
    if( FD_UNLIKELY( block->header_seen ) ) {
      FD_LOG_INFO(( "bad block: MULTIPLE_BLOCK_HEADERS, slot %lu, parent slot %lu", block->slot, block->parent_slot ));
      return FD_SCHED_DEAD_REASON_MULTIPLE_BLOCK_HEADERS;
    }
    /* Checking for shred header and parent_slot mismatch occurs at the
       rotor level, so it does not need to be checked in sched.  We do
       this because currently replay tile never sees shred headers. */
    block->header_seen = 1;
    return FD_SCHED_DEAD_REASON_NONE;

  case FD_BLOCK_MARKER_KIND_GENESIS_CERT:
    if( FD_UNLIKELY( !block->header_seen ) ) {
      FD_LOG_INFO(( "bad block: MISSING_PARENT_MARKER, slot %lu, parent slot %lu, genesis cert before header", block->slot, block->parent_slot ));
      return FD_SCHED_DEAD_REASON_MISSING_PARENT_MARKER;
    }
    if( FD_UNLIKELY( block->mblk_cnt || block->genesis_cert_seen || block->footer_seen ) ) {
      FD_LOG_INFO(( "bad block: GENESIS_CERT_OUT_OF_ORDER, slot %lu, parent slot %lu", block->slot, block->parent_slot ));
      return FD_SCHED_DEAD_REASON_GENESIS_CERT_OUT_OF_ORDER;
    }
    block->genesis_cert_seen = 1;
    return FD_SCHED_DEAD_REASON_NONE;

  case FD_BLOCK_MARKER_KIND_FOOTER:
    if( FD_UNLIKELY( !block->header_seen ) ) {
      FD_LOG_INFO(( "bad block: MISSING_PARENT_MARKER, slot %lu, parent slot %lu, footer before header", block->slot, block->parent_slot ));
      return FD_SCHED_DEAD_REASON_MISSING_PARENT_MARKER;
    }
    if( FD_UNLIKELY( block->footer_seen ) ) {
      FD_LOG_INFO(( "bad block: MULTIPLE_BLOCK_FOOTERS, slot %lu, parent slot %lu", block->slot, block->parent_slot ));
      return FD_SCHED_DEAD_REASON_MULTIPLE_BLOCK_FOOTERS;
    }
    block->footer      = marker->footer;
    block->footer_seen = 1;
    return FD_SCHED_DEAD_REASON_NONE;

  case FD_BLOCK_MARKER_KIND_UPDATE_PARENT:
    block->update_parent_seen = 1;
    return FD_SCHED_DEAD_REASON_SPURIOUS_UPDATE_PARENT;

  default:
    FD_LOG_INFO(( "bad block: slot %lu, parent slot %lu, unknown block marker kind %u", block->slot, block->parent_slot, marker->kind ));
    return FD_SCHED_DEAD_REASON_BAD_BLOCK_MARKER;
  }
}

/* Called when a batch header declares one or more microblocks. */

static int
ag_on_entry_batch( fd_sched_block_t * block ) {
  if( FD_UNLIKELY( !block->header_seen ) ) {
    FD_LOG_INFO(( "bad block: MISSING_PARENT_MARKER, slot %lu, parent slot %lu, entries before header", block->slot, block->parent_slot ));
    return FD_SCHED_DEAD_REASON_MISSING_PARENT_MARKER;
  }
  if( FD_UNLIKELY( block->alpentick_seen ) ) {
    FD_LOG_INFO(( "bad block: ENTRY_AFTER_BLOCK_FOOTER, slot %lu, parent slot %lu, batch after alpentick", block->slot, block->parent_slot ));
    return FD_SCHED_DEAD_REASON_ENTRY_AFTER_BLOCK_FOOTER;
  }
  /* Only the alpentick may follow the footer: a batch of exactly one
     microblock which must turn out to be a tick (checked when its
     header parses). */
  if( FD_UNLIKELY( block->footer_seen && block->mblks_rem!=1UL ) ) {
    FD_LOG_INFO(( "bad block: ENTRY_AFTER_BLOCK_FOOTER, slot %lu, parent slot %lu, batch of %lu microblocks after footer", block->slot, block->parent_slot, block->mblks_rem ));
    return FD_SCHED_DEAD_REASON_ENTRY_AFTER_BLOCK_FOOTER;
  }
  return FD_SCHED_DEAD_REASON_NONE;
}

static int
ag_on_final( fd_sched_block_t * block ) {
  if( FD_UNLIKELY( !block->footer_seen ) ) {
    FD_LOG_INFO(( "bad block: MISSING_BLOCK_FOOTER, slot %lu, parent slot %lu", block->slot, block->parent_slot ));
    return FD_SCHED_DEAD_REASON_MISSING_BLOCK_FOOTER;
  }
  if( FD_UNLIKELY( !block->alpentick_seen ) ) {
    FD_LOG_INFO(( "bad block: INVALID_ALPENTICK_POSITION, slot %lu, parent slot %lu, block ended after footer without alpentick", block->slot, block->parent_slot ));
    return FD_SCHED_DEAD_REASON_INVALID_ALPENTICK_POSITION;
  }
  return FD_SCHED_DEAD_REASON_NONE;
}

/* Agave invokes verify_ticks() anywhere between once per slot and once
   per entry batch, before transactions are parsed or dispatched for
   execution.  We can't do quite the same thing due to out-of-order
   scheduling and the fact that we allow parsing to run well ahead of
   block boundaries.  Out-of-order scheduling is good, so is overlapping
   parsing with execution.  The easiest thing for us would be to just
   delay verify_ticks() wholesale till the end of a slot, except that
   this opens us up to bogus tick and hash counts, potentially causing
   runaway consumption of compute cycles.  Of all the checks that are
   performed in verify_ticks(), two types are relevant to mitigating
   this risk.  One is constraining the number of ticks, and the other is
   constraining the number of hashes per tick.  So we implement these
   checks here, and perform them on the fly as eagerly as possible.

   Returns FD_SCHED_DEAD_REASON_NONE (0) on success, else the
   FD_SCHED_DEAD_REASON_* the block should be ruled invalid for.  Does
   not modify the block. */
static int
verify_ticks_eager( fd_sched_block_t * block ) {
  FD_TEST( block->hashes_per_tick!=ULONG_MAX ); /* PoH params initialized. */

  if( FD_UNLIKELY( block->mblk_tick_cnt+block->tick_height>block->max_tick_height ) ) {
    FD_LOG_INFO(( "bad block: TOO_MANY_TICKS, slot %lu, parent slot %lu, tick_cnt %u, tick_height %lu, max_tick_height %lu", block->slot, block->parent_slot, block->mblk_tick_cnt, block->tick_height, block->max_tick_height ));
    return FD_SCHED_DEAD_REASON_TOO_MANY_TICKS;
  }
  if( FD_UNLIKELY( block->hashes_per_tick>1UL && block->zero_hash_tick ) ) {
    FD_LOG_INFO(( "bad block: ZERO_HASH_TICK, slot %lu, parent slot %lu, has at least one zero hash tick", block->slot, block->parent_slot ));
    return FD_SCHED_DEAD_REASON_ZERO_HASH_TICK;
  }
  if( FD_UNLIKELY( block->hashes_per_tick>1UL && block->mblk_tick_cnt && (block->hashes_per_tick!=block->tick_hashcnt_wmk||block->inconsistent_hashes_per_tick) ) ) {
    FD_LOG_INFO(( "bad block: WRONG_HASHES_PER_TICK, slot %lu, parent slot %lu, expected %lu, got %lu", block->slot, block->parent_slot, block->hashes_per_tick, block->tick_hashcnt_wmk ));
    return FD_SCHED_DEAD_REASON_WRONG_HASHES_PER_TICK;
  }
  if( FD_UNLIKELY( block->hashes_per_tick>1UL && block->curr_tick_hashcnt>block->hashes_per_tick ) ) { /* >1 to ignore low power hashing or no hashing cases */
    /* We couldn't really check this at parse time because we may not
       have the expected hashes per tick value yet.  We couldn't delay
       this till after all PoH hashing is done, because this would be a
       DoS vector.  This can't be merged with the above check, because a
       malformed block might not end with a tick.  As in, a block might
       end with a non-tick microblock with a high hashcnt.  Note that
       checking the hashcnt between ticks transitively places an upper
       bound on the hashcnt of individual microblocks, thus mitigating
       the DoS vector. */
    FD_LOG_INFO(( "bad block: TICK_HASHES_OVERFLOW, slot %lu, parent slot %lu, observed cumulative tick_hashcnt %lu, expected %lu", block->slot, block->parent_slot, block->curr_tick_hashcnt, block->hashes_per_tick ));
    return FD_SCHED_DEAD_REASON_TICK_HASHES_OVERFLOW;
  }

  return FD_SCHED_DEAD_REASON_NONE;
}

/* https://github.com/anza-xyz/agave/blob/v3.0.6/ledger/src/blockstore_processor.rs#L1057

   The only check we don't do here is TRAILING_ENTRY, which can be done
   independently when we parse the final FEC set of a block.

   Returns FD_SCHED_DEAD_REASON_NONE (0) on success, else the
   FD_SCHED_DEAD_REASON_* the block should be ruled invalid for.  Does
   not modify the block. */
static int
verify_ticks_final( fd_sched_block_t * block ) {
  FD_TEST( block->fec_eos );

  if( FD_UNLIKELY( block->mblk_tick_cnt+block->tick_height<block->max_tick_height ) ) {
    FD_LOG_INFO(( "bad block: TOO_FEW_TICKS, slot %lu, parent slot %lu, tick_cnt %u, tick_height %lu, max_tick_height %lu", block->slot, block->parent_slot, block->mblk_tick_cnt, block->tick_height, block->max_tick_height ));
    return FD_SCHED_DEAD_REASON_TOO_FEW_TICKS;
  }

  return verify_ticks_eager( block );
}

int
fd_sched_block_verify_ticks( fd_sched_t * sched,
                             ulong        bank_idx,
                             ulong        tick_height,
                             ulong        max_tick_height,
                             ulong        hashes_per_tick ) {
  FD_TEST( sched->canary==FD_SCHED_MAGIC );
  FD_TEST( bank_idx<sched->block_cnt_max );
  FD_TEST( max_tick_height>tick_height );
  fd_sched_block_t * block = block_pool_ele( sched, bank_idx );
  /* Set the tick window directly; skip fd_sched_set_poh_params
     PoH fixup, unneeded here and unsafe to repeat per FEC set. */
  block->tick_height     = tick_height;
  block->max_tick_height = max_tick_height;
  block->hashes_per_tick = hashes_per_tick;
  /* fec_eos => slot fully ingested, so the TOO_FEW check is meaningful
     too. */
  return block->fec_eos ? verify_ticks_final( block ) : verify_ticks_eager( block );
}

#define CHECK( cond )  do {           \
  if( FD_UNLIKELY( !(cond) ) ) {      \
    return FD_SCHED_DEAD_REASON_NONE; \
  }                                   \
} while( 0 )

/* CHECK that it is safe to read at least n more bytes. */
#define CHECK_LEFT( n ) CHECK( (n)<=(block->fec_buf_sz-block->fec_buf_soff) )

/* Consume as much as possible from the buffer.  By the end of this
   function, there could be residual data left over in the buffer.  That
   residual has to be either a partially received microblock header or a
   transaction that straddles a FEC set boundary.  These bytes are kept
   and will be concatenated with the next FEC set.  This residual is
   bounded.

   Trailing bytes within a batch are dropped immediately.  These
   trailing bytes can span arbitrarily many FEC sets. */
FD_WARN_UNUSED static int
fd_sched_parse( fd_sched_t * sched, fd_sched_block_t * block, fd_sched_alut_ctx_t * alut_ctx ) {
  while( 1 ) {
    while( block->txns_rem>0UL ) {
      int err = fd_sched_parse_txn( sched, block, alut_ctx );
      if( FD_UNLIKELY( -1==err ) ) return FD_SCHED_DEAD_REASON_NONE;
      else if( FD_UNLIKELY( err ) ) return err;
    }

    if( block->txns_rem==0UL && block->mblks_rem>0UL ) {
      if( FD_UNLIKELY( block->mblk_cnt>=sched->max_mblk_per_slot ) ) {
        /* Microblock count is enforced as invariant
           mblk_cnt+mblks_rem<=max_mblk_per_slot
           when we read the declared count in a batch header.  So we
           shouldn't get here. */
        sched->print_buf_sz = 0UL;
        print_all( sched, block );
        FD_LOG_NOTICE(( "%s", sched->print_buf ));
        FD_LOG_CRIT(( "invariant violation: slot %lu, parent slot %lu, mblks_rem %lu, mblk_cnt %u (%u ticks) >= %lu", block->slot, block->parent_slot, block->mblks_rem, block->mblk_cnt, block->mblk_tick_cnt, sched->max_mblk_per_slot ));
      }

      CHECK_LEFT( sizeof(fd_microblock_hdr_t) );
      fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)fd_type_pun( block->fec_buf+block->fec_buf_soff );
      block->fec_buf_soff      += (uint)sizeof(fd_microblock_hdr_t);

      if( FD_UNLIKELY( hdr->txn_cnt>fd_ulong_sat_sub( sched->max_txn_per_slot, block->txn_parsed_cnt ) ) ) {
        FD_LOG_INFO(( "bad block: TOO_MANY_TXNS, microblock header declared too many transactions, slot %lu, parent slot %lu, txn_parsed_cnt %u, hdr->txn_cnt %lu", block->slot, block->parent_slot, block->txn_parsed_cnt, hdr->txn_cnt ));
        return FD_SCHED_DEAD_REASON_TOO_MANY_TXNS;
      }
      if( FD_UNLIKELY( !sched->is_alpenglow && hdr->hash_cnt>fd_ulong_sat_sub( FD_RUNTIME_MAX_HASHES_PER_TICK, block->curr_tick_hashcnt ) ) ) {
        FD_LOG_INFO(( "bad block: TICK_HASHES_OVERFLOW_INGEST, slot %lu, parent slot %lu, curr_tick_hashcnt %lu, hdr->hash_cnt %lu", block->slot, block->parent_slot, block->curr_tick_hashcnt, hdr->hash_cnt ));
        return FD_SCHED_DEAD_REASON_TICK_HASHES_OVERFLOW_INGEST;
      }
      if( FD_UNLIKELY( sched->is_alpenglow && hdr->hash_cnt!=1UL ) ) {
        FD_LOG_INFO(( "bad block: ALPENGLOW_HASH_CNT, slot %lu, parent slot %lu, mblk idx %u declared hash_cnt %lu", block->slot, block->parent_slot, block->mblk_cnt, hdr->hash_cnt ));
        return FD_SCHED_DEAD_REASON_ALPENGLOW_HASH_CNT;
      }
      if( FD_UNLIKELY( sched->is_alpenglow && block->footer_seen ) ) {
        if( FD_UNLIKELY( hdr->txn_cnt ) ) {
          FD_LOG_INFO(( "bad block: ENTRY_AFTER_BLOCK_FOOTER, slot %lu, parent slot %lu, transaction microblock after footer", block->slot, block->parent_slot ));
          return FD_SCHED_DEAD_REASON_ENTRY_AFTER_BLOCK_FOOTER;
        }
        block->alpentick_seen = 1;
      }

      block->mblks_rem--;
      block->txns_rem = hdr->txn_cnt;

      /* One might think that every microblock needs to have at least
         one hash, otherwise the block should be considered invalid.  A
         vanilla validator certainly produces microblocks that conform
         to this.  But a modded validator could in theory produce
         zero-hash microblocks.  Agave's replay stage will happily take
         those microblocks.  The Agave implementation-defined way of
         doing PoH verify is as follows:

         For a tick microblock, do the same number of hashes as
         specified by the microblock.  Zero hashes are not allowed.

         For a transaction microblock, if the number of hashes specified
         by the microblock is <= 1, then do zero pure hashes, and simply
         do a mixin/record.  Otherwise, do (number of hashes-1) amount
         of pure hashing, and then do a mixin.  However, note that for
         the purposes of tick_verify, the number of hashes specified by
         the microblock is taken verbatim.

         An additional constraint is that Agave expects non-tick
         microblocks to leave the cumulative tick hash count at least
         one away from hashes_per_tick at the end of a batch:
         https://github.com/anza-xyz/agave/blob/v4.0.0-rc.0/entry/src/entry.rs#L672

         Observe that this is not a net new constraint.  Since ticks are
         not allowed to have zero hashes, and ticks have to end at
         exactly hashes_per_tick, this check is redundant.


         Some additional references to Agave:

         On the consumer side, non-tick microblocks can have a zero hash
         count, and the mixin will happen anyways:
         https://github.com/anza-xyz/agave/blob/v4.0.0-rc.0/entry/src/entry.rs#L326
         https://github.com/anza-xyz/agave/blob/v4.0.0-rc.0/entry/src/entry.rs#L542

         Ticks cannot have a zero hash count:
         https://github.com/anza-xyz/agave/blob/v4.1.1/entry/src/entry.rs#L684

         On the producer side, Agave reserves at least one hash for the
         tick, so an Agave produced tick would satisfy the verifier:
         https://github.com/anza-xyz/agave/blob/v4.0.0-rc.0/entry/src/poh.rs#L78
         https://github.com/anza-xyz/agave/blob/v4.0.0-rc.0/entry/src/poh.rs#L101 */
      block->curr_tick_hashcnt = fd_ulong_sat_add( hdr->hash_cnt, block->curr_tick_hashcnt ); /* For tick_verify, take the number of hashes verbatim. */
      sched->metrics->mblk_parsed_cnt++;
      if( FD_UNLIKELY( !hdr->txn_cnt ) ) {
        /* This is a tick microblock. */
        if( FD_UNLIKELY( block->mblk_tick_cnt && block->tick_hashcnt_wmk!=block->curr_tick_hashcnt ) ) {
          block->inconsistent_hashes_per_tick = 1;
          if( FD_LIKELY( block->hashes_per_tick!=ULONG_MAX && block->hashes_per_tick>1UL ) ) {
            /* >1 to ignore low power hashing or hashing disabled */
            FD_LOG_INFO(( "bad block: INCONSISTENT_TICK_HASHES, slot %lu, parent slot %lu, tick idx %u, tick_hashcnt_wmk %lu, curr hashcnt %lu, hashes_per_tick %lu", block->slot, block->parent_slot, block->mblk_tick_cnt, block->tick_hashcnt_wmk, block->curr_tick_hashcnt, block->hashes_per_tick ));
            return FD_SCHED_DEAD_REASON_INCONSISTENT_TICK_HASHES;
          }
        }
        if( FD_UNLIKELY( !hdr->hash_cnt ) ) {
          block->zero_hash_tick = 1;
          if( FD_LIKELY( block->hashes_per_tick!=ULONG_MAX && block->hashes_per_tick>1UL ) ) {
            FD_LOG_INFO(( "bad block: ZERO_HASH_TICK_INGEST, slot %lu, parent slot %lu, tick idx %u has zero hashes", block->slot, block->parent_slot, block->mblk_tick_cnt ));
            return FD_SCHED_DEAD_REASON_ZERO_HASH_TICK_INGEST;
          }
        }
        block->tick_hashcnt_wmk  = fd_ulong_max( block->curr_tick_hashcnt, block->tick_hashcnt_wmk );
        block->curr_tick_hashcnt = 0UL;
        block->mblk_tick_cnt++;
      }

      FD_TEST( sched->mblk_pool_free_cnt ); /* can_ingest should have guaranteed sufficient free capacity. */
      uint mblk_idx = sched->mblk_pool_free_head;
      sched->mblk_pool_free_head = sched->mblk_pool[ mblk_idx ].next;
      sched->mblk_pool_free_cnt--;

      fd_sched_mblk_t * mblk = sched->mblk_pool+mblk_idx;
      mblk->start_txn_idx = block->txn_parsed_cnt;
      mblk->end_txn_idx   = mblk->start_txn_idx+hdr->txn_cnt;
      mblk->curr_txn_idx  = mblk->start_txn_idx;
      mblk->hashcnt       = fd_ulong_sat_sub( hdr->hash_cnt, fd_ulong_if( !hdr->txn_cnt, 0UL, 1UL ) ); /* For pure hashing, implement saturating sub for non-tick microblocks. */
      mblk->curr_hashcnt  = 0UL;
      mblk->curr_sig_cnt  = 0U;
      mblk->mixin_txn_idx = 0U;
      mblk->is_tick       = !hdr->txn_cnt;
      memcpy( mblk->end_hash, hdr->hash, sizeof(fd_hash_t) );
      memcpy( mblk->curr_hash, block->poh_hash, sizeof(fd_hash_t) );
      block->parse_mblk_idx = mblk_idx;

      /* Update block tracking. */
      block->hashcnt += mblk->hashcnt+fd_ulong_if( !hdr->txn_cnt, 0UL, 1UL );
      memcpy( block->poh_hash, hdr->hash, sizeof(fd_hash_t) );
      block->last_mblk_is_tick = mblk->is_tick;
      block->mblk_cnt++;

      #if FD_SCHED_SKIP_POH
      block->poh_hashing_done_cnt++;
      block->poh_hash_cmp_done_cnt++;
      free_mblk( sched, block, mblk_idx );
      #else
      mblk_slist_idx_push_tail( block->mblks_unhashed, mblk_idx, sched->mblk_pool );
      block->mblk_unhashed_cnt++;
      #endif
      continue;
    }
    if( block->txns_rem==0UL && block->mblks_rem==0UL && block->fec_sob ) {
      CHECK_LEFT( sizeof(ulong) );
      FD_TEST( block->fec_buf_soff==0U );
      if( FD_UNLIKELY( sched->is_alpenglow && !FD_LOAD( ulong, block->fec_buf ) && !block->fec_eob ) ) {
        /* Block marker split across FEC sets */
        fd_block_marker_t peek[1];
        if( FD_UNLIKELY( FD_BLOCK_MARKER_DE_ERR_SZ==fd_block_marker_de( peek, block->fec_buf, (ulong)block->fec_buf_sz ) &&
                         block->fec_buf_sz<FD_BLOCK_MARKER_SER_MAX ) ) return FD_SCHED_DEAD_REASON_NONE;
      }
      block->mblks_rem     = FD_LOAD( ulong, block->fec_buf );
      block->fec_buf_soff += (uint)sizeof(ulong);

      if( FD_UNLIKELY( block->mblks_rem>fd_ulong_sat_sub( sched->max_mblk_per_slot, block->mblk_cnt ) ) ) {
        FD_LOG_INFO(( "bad block: TOO_MANY_MICROBLOCKS, slot %lu, parent slot %lu, mblk_cnt %u (%u ticks) + hdr->mblk_cnt %lu >= %lu", block->slot, block->parent_slot, block->mblk_cnt, block->mblk_tick_cnt, block->mblks_rem, sched->max_mblk_per_slot ));
        return FD_SCHED_DEAD_REASON_TOO_MANY_MICROBLOCKS;
      }

      block->fec_sob = 0;

      if( FD_UNLIKELY( !block->mblks_rem && sched->is_alpenglow ) ) {
        /* A zero-microblock batch is a block marker */
        fd_block_marker_t marker[1];
        int err = fd_block_marker_de( marker, block->fec_buf, (ulong)block->fec_buf_sz );
        if( FD_UNLIKELY( err ) ) {
          FD_LOG_INFO(( "bad block: slot %lu, unable to parse block marker (err %d)", block->slot, err ));
          return FD_SCHED_DEAD_REASON_BAD_BLOCK_MARKER;
        }
        int dead_reason = ag_on_marker( sched, block, marker );
        if( FD_UNLIKELY( dead_reason!=FD_SCHED_DEAD_REASON_NONE ) ) return dead_reason;
      } else if( FD_UNLIKELY( block->mblks_rem && sched->is_alpenglow ) ) {
        int dead_reason = ag_on_entry_batch( block );
        if( FD_UNLIKELY( dead_reason!=FD_SCHED_DEAD_REASON_NONE ) ) return dead_reason;
      } else if( FD_UNLIKELY( !block->mblks_rem && !sched->is_alpenglow ) ) {
        FD_LOG_INFO(( "bad block: ZERO_MICROBLOCKS, slot %lu, parent slot %lu, mblk_cnt %u (%u ticks)", block->slot, block->parent_slot, block->mblk_cnt, block->mblk_tick_cnt ));
        return FD_SCHED_DEAD_REASON_ZERO_MICROBLOCKS;
      }
      continue;
    }
    if( block->txns_rem==0UL && block->mblks_rem==0UL ) {
      break;
    }
  }
  if( !block->fec_sob && block->txns_rem==0UL && block->mblks_rem==0UL ) {
    /* All microblocks announced by the current batch header have been
       parsed out.  Anything still in the buffer must be trailing bytes.
       Drop them now because trailing bytes can span many FEC sets and
       accumulating them would overflow the parse buffer.  Any followup
       FEC sets within the same batch will simply be discarded
       wholesale. */
    sched->metrics->bytes_ingested_unparsed_cnt += block->fec_buf_sz-block->fec_buf_soff;
    block->fec_buf_boff += block->fec_buf_sz;
    block->fec_buf_soff  = 0U;
    block->fec_buf_sz    = 0U;
  }
  if( block->fec_eob ) {
    block->fec_sob = 1;
    block->fec_eob = 0;
  }
  return FD_SCHED_DEAD_REASON_NONE;
}

static inline fd_acct_addr_t const *
get_acct( fd_txn_t const * txn, fd_acct_addr_t const * imms, fd_acct_addr_t const * alts, ushort idx ) {
  if( FD_LIKELY( idx<txn->acct_addr_cnt ) ) return imms+idx;
  if( FD_UNLIKELY( !alts )                ) return NULL;
  return alts+(idx-txn->acct_addr_cnt);
}

/* Returns 1 if the transaction write locks any account in the block's
   poison set. */
static int
block_poison_hit( fd_sched_block_t const * block, fd_txn_t const * txn, fd_acct_addr_t const * imms, fd_acct_addr_t const * alts ) {
  if( FD_LIKELY( !block->poison_cnt ) ) return 0;

  for( fd_txn_acct_iter_t iter = fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE ); iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {
    fd_acct_addr_t const * acct = get_acct( txn, imms, alts, (ushort)fd_txn_acct_iter_idx( iter ) );
    /* Shouldn't really happen, since ALT-serializing transactions don't
       enter this function, so all account pubkeys are available. */
    if( FD_UNLIKELY( !acct ) ) return 1;
    for( uint j=0U; j<block->poison_cnt; j++ ) {
      if( FD_UNLIKELY( !memcmp( block->poison[ j ].b, acct->b, 32UL ) ) ) return 1;
    }
  }

  return 0;
}

/* Returns 0 on success, 1 if the poison set overflowed. */
static int
block_poison_insert( fd_sched_t * sched, fd_sched_block_t * block, fd_acct_addr_t const * acct ) {
  for( uint j=0U; j<block->poison_cnt; j++ ) {
    if( FD_UNLIKELY( !memcmp( block->poison[ j ].b, acct->b, 32UL ) ) ) return 0; /* Dedup. */
  }

  if( FD_UNLIKELY( block->poison_cnt>=FD_SCHED_POISON_MAX_ACCT_PER_SLOT ) ) {
    block->poison_serialize = 1;
    sched->metrics->poison_latch_overflow_cnt++;
    return 1;
  }

  block->poison[ block->poison_cnt++ ] = *acct;
  sched->metrics->poison_cnt_wmk = fd_uint_max( sched->metrics->poison_cnt_wmk, block->poison_cnt );
  return 0;
}

/* Adds relevant accounts to the poison set.  This function is
   conservative and stateless.  Account data is not necessarily
   available at insertion time, so we cannot tell which writable account
   is the programdata PDA.  So the rule is simply: if loader v3 appears
   anywhere in the transaction account list, poison every writable
   account of the transaction.

   That is sound because instruction level writability can never exceed
   transaction level writability thanks to CPI rejecting writability
   escalations.  So any account a loader v3 instruction could modify, at
   the top-level or in a CPI, must be transaction level writable.
   Additionally, the loader being in the account keys is necessary for
   any invocation of it. */
static void
block_poison_add( fd_sched_t *           sched,
                  fd_sched_block_t *     block,
                  fd_txn_t const *       txn,
                  fd_acct_addr_t const * imms,
                  fd_acct_addr_t const * alts,
                  ulong                  alt_cnt ) {
  /* The poison set is never consulted again once it enters a
     serializing regime, so there is no point in adding anything to it.
     Returning here also keeps the serializing counters at one increment
     per block. */
  if( FD_UNLIKELY( block->poison_serialize ) ) return;

  /* If we can't expand an ALT, we'd have to conservatively assume
     there's loader v3 listed in it.  And if there also happens to be a
     writable account in an unresolvable ALT, we can't add it and we no
     longer maintain poison list integrity, so we conservatively
     serialize the rest of the block. */
  int alt_unresolvable = alt_cnt && !alts;
  int loader_present = 0;
  for( ushort i=0; i<txn->acct_addr_cnt; i++ ) {
    if( FD_UNLIKELY( !memcmp( imms[ i ].b, fd_solana_bpf_loader_upgradeable_program_id.key, 32UL ) ) ) {
      loader_present = 1;
      break;
    }
  }
  if( !loader_present && !alt_unresolvable ) {
    for( ulong i=0UL; i<alt_cnt; i++ ) {
      if( FD_UNLIKELY( !memcmp( alts[ i ].b, fd_solana_bpf_loader_upgradeable_program_id.key, 32UL ) ) ) {
        loader_present = 1;
        break;
      }
    }
  }
  if( FD_LIKELY( !loader_present && !alt_unresolvable ) ) return;

  for( fd_txn_acct_iter_t iter = fd_txn_acct_iter_init( txn, FD_TXN_ACCT_CAT_WRITABLE ); iter!=fd_txn_acct_iter_end(); iter=fd_txn_acct_iter_next( iter ) ) {
    fd_acct_addr_t const * acct = get_acct( txn, imms, alts, (ushort)fd_txn_acct_iter_idx( iter ) );
    if( FD_UNLIKELY( !acct ) ) {
      block->poison_serialize = 1;
      sched->metrics->poison_latch_alt_cnt++;
      break;
    }
    if( FD_UNLIKELY( block_poison_insert( sched, block, acct ) ) ) break;
  }
}

FD_WARN_UNUSED static int
fd_sched_parse_txn( fd_sched_t * sched, fd_sched_block_t * block, fd_sched_alut_ctx_t * alut_ctx ) {
  fd_txn_t * txn = fd_type_pun( block->txn );

  uchar * payload   = block->fec_buf+block->fec_buf_soff;
  ulong   remaining = block->fec_buf_sz-block->fec_buf_soff;
  ulong   pay_sz    = 0UL;
  ulong   txn_sz    = fd_txn_parse_core( payload,
                                         remaining,
                                         txn,
                                         NULL,
                                         &pay_sz );

  /* Can't parse out a full transaction yet, EAGAIN. */
  if( FD_UNLIKELY( !pay_sz || !txn_sz ) ) return -1;

  /* The pool slots this transaction will land in are cold: warm the
     lines written below (the start of the payload copy, the metadata,
     the start of the parsed txn and the whole info record) while the
     ALUT resolution and the dispatcher insert run.  A hint only. */
  ulong next_idx = fd_rdisp_peek_free_txn( sched->rdisp );
  if( FD_LIKELY( next_idx && next_idx<sched->depth ) ) {
    fd_txn_p_t * next_p = sched->txn_pool+next_idx;
    __builtin_prefetch( next_p->payload,      1, 3 );
    __builtin_prefetch( next_p->payload+64UL, 1, 3 );
    __builtin_prefetch( &next_p->payload_sz,  1, 3 );
    __builtin_prefetch( TXN( next_p ),        1, 3 );
    ulong info_lo = fd_ulong_align_dn( (ulong)(sched->txn_info_pool+next_idx     ), 64UL );
    ulong info_hi = fd_ulong_align_up( (ulong)(sched->txn_info_pool+next_idx+1UL ), 64UL );
    for( ulong line=info_lo; line<info_hi; line+=64UL ) __builtin_prefetch( (void const *)line, 1, 3 );
  }

  if( FD_UNLIKELY( block->txn_parsed_cnt>=sched->max_txn_per_slot ) ) {
    /* Transaction count is enforced as invariant
       txn_parsed_cnt+txns_rem<=max_txn_per_slot
       when we read the declared count in a microblock header.  So we
       shouldn't get here. */
    sched->print_buf_sz = 0UL;
    print_all( sched, block );
    FD_LOG_NOTICE(( "%s", sched->print_buf ));
    FD_LOG_CRIT(( "invariant violation: slot %lu, parent slot %lu, txn_parsed_cnt %u", block->slot, block->parent_slot, block->txn_parsed_cnt ));
  }

  ulong imm_cnt = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );
  ulong alt_cnt = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_ALT );

  /* Try to expand ALUTs. */
  int serializing = 0;
  if( alt_cnt>0UL ) {
    if( FD_UNLIKELY( sched->bypass_alut_resolution ) ) {
      /* test/fuzz: no accdb to query, so treat ALUT txns as serializing. */
      serializing = 1;
    } else {
      /* Copy the slot hashes sysvar out and release the read BEFORE
         resolving the ALTs.  fd_runtime_load_txn_address_lookup_tables
         issues its own fd_accdb_read_one per lookup table, and the accdb
         acquire state is a single non-nestable flag — holding this read
         open across that call would trip the IDLE assertion in
         fd_accdb_acquire.  The slot_hashes view aliases the record data,
         so it must view the copy, not the released record. */
      static uchar slot_hashes_buf[ FD_SYSVAR_SLOT_HASHES_BINCODE_SZ ];
      ulong        slot_hashes_sz = 0UL;
      int          have_slot_hashes = 0;
      fd_acc_t ro = fd_accdb_read_one( alut_ctx->accdb, alut_ctx->fork_id, fd_sysvar_slot_hashes_id.uc );
      if( FD_LIKELY( ro.lamports && ro.data_len<=sizeof(slot_hashes_buf) ) ) {
        fd_memcpy( slot_hashes_buf, ro.data, ro.data_len );
        slot_hashes_sz   = ro.data_len;
        have_slot_hashes = 1;
      }
      fd_accdb_unread_one( alut_ctx->accdb, &ro );

      fd_slot_hashes_t slot_hashes_view[1];
      if( FD_LIKELY( have_slot_hashes &&
                     fd_sysvar_slot_hashes_view( slot_hashes_view, slot_hashes_buf, slot_hashes_sz ) ) ) {
        serializing = !!fd_runtime_load_txn_address_lookup_tables( txn, payload, alut_ctx->accdb, alut_ctx->fork_id, alut_ctx->els, slot_hashes_view, sched->aluts );
        sched->metrics->alut_success_cnt += (uint)!serializing;
      } else {
        serializing = 1;
      }
    }
  }

  /* Capture alt_cnt before it's clamped below.  Poisoning needs to
     distinguish between "no ALT keys" from "ALT keys failed to
     resolve". */
  ulong                  poison_alt_cnt = alt_cnt;
  fd_acct_addr_t const * poison_alts    = (alt_cnt && !serializing) ? sched->aluts : NULL;

  /* Transactions should not have duplicate accounts.
     https://github.com/anza-xyz/agave/blob/v3.1.11/ledger/src/blockstore_processor.rs#L778-L790 */
  fd_acct_addr_t const * imms = fd_txn_get_acct_addrs( txn, payload );
  fd_acct_addr_t * alts = (!alt_cnt||serializing) ? NULL : sched->aluts;
  alt_cnt = alts ? alt_cnt : 0UL;
  if( FD_UNLIKELY( fd_chkdup_check( sched->chkdup, imms, imm_cnt, alts, alt_cnt ) ) ) {
    FD_LOG_INFO(( "bad block: DUPLICATE_ACCOUNT, slot %lu, parent slot %lu, txn_parsed_cnt %u", block->slot, block->parent_slot, block->txn_parsed_cnt ));
    return FD_SCHED_DEAD_REASON_DUPLICATE_ACCOUNT;
  }

  /* After any error return but before poisoning. */
  sched->metrics->alut_serializing_cnt += (uint)serializing;

  /* At this point, we've decided whether the transaction is
     ALT-serializing or not.  If it didn't get serialized by ALT
     expansion failure, check if it should be serialized by poisoning.
     Add to the poison set after checking, so a poisoning transaction
     doesn't get serialized against its own entries.  Adding to the
     poison set is unconditional. */
  if( FD_UNLIKELY( !serializing && ( block->poison_serialize||block_poison_hit( block, txn, imms, poison_alts ) ) ) ) {
    serializing = 1;
    sched->metrics->txn_poisoned_cnt           += block->poison_serialize ? 0U : 1U;
    sched->metrics->txn_poison_serializing_cnt += block->poison_serialize ? 1U : 0U;
  }
  block_poison_add( sched, block, txn, imms, poison_alts, poison_alt_cnt );

  ulong bank_idx = (ulong)(block-sched->block_pool);
  fd_rdisp_neww_t neww[ fd_rdisp_neww_word_cnt ];
  ulong txn_idx  = fd_rdisp_add_txn( sched->rdisp, bank_idx, txn, payload, alts, serializing, sched->lthash_oob ? neww : NULL );
  FD_TEST( txn_idx && txn_idx<sched->depth );
  if( FD_LIKELY( sched->lthash_oob ) ) {
    ulong writable_cnt    = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE )
                          - fd_ulong_if( !alts, fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE_ALT ), 0UL );
    ulong first_write_cnt = fd_rdisp_neww_cnt( neww );
    sched->metrics->lthash_parsed_writable_cnt += writable_cnt;
    sched->metrics->lthash_first_write_cnt     += first_write_cnt;
    sched->metrics->lthash_coalesced_cnt       += writable_cnt-first_write_cnt;
    block->add_owed_cnt                        += (uint)first_write_cnt;
    if( FD_LIKELY( block_owns_lane_map( sched, block ) ) ) {
      for( ulong iter = fd_rdisp_neww_iter_init( neww ); !fd_rdisp_neww_iter_done( iter ); iter=fd_rdisp_neww_iter_next( neww, iter ) ) {
        fd_acct_addr_t const * acct = get_acct( txn, imms, alts, (ushort)iter );
        FD_TEST( acct );
        lthash_entry_new_write_observed( sched, block, acct );
      }
    }
  }

  /* This transaction either needs to be consumed by sigverify or PoH.
     If either of the two are caught up, mark it for consumption.
     Otherwise, link it to the tail of the chain. */

  ulong sigverify_dispatched_cnt = (ulong)block->txn_sigverify_done_cnt + (ulong)block->txn_sigverify_in_flight_cnt;
  int   sigverify_caught_up      = sigverify_dispatched_cnt==block->txn_parsed_cnt;
#if !FD_SCHED_SKIP_POH
  fd_sched_mblk_t * parse_mblk = sched->mblk_pool + block->parse_mblk_idx;
  int poh_caught_up = parse_mblk->curr_txn_idx==block->txn_parsed_cnt;
#endif

  sched->txn_info_pool[ txn_idx ].next_idx = 0U;
  /* Link to the previous transaction. */
  if( FD_LIKELY( block->txn_idx_tail ) ) {
    FD_TEST( block->txn_idx_tail<sched->depth );
    sched->txn_info_pool[ block->txn_idx_tail ].next_idx = (uint)txn_idx;
  }
  /* If either consumer is caught up, update next pointer to the new
     transaction. */
  if( FD_LIKELY( sigverify_caught_up ) ) block->txn_sigverify_next_idx = (uint)txn_idx;
#if !FD_SCHED_SKIP_POH
  if( FD_LIKELY( poh_caught_up ) ) parse_mblk->mixin_txn_idx = (uint)txn_idx;
#endif
  block->txn_idx_tail = (uint)txn_idx;

  sched->metrics->txn_parsed_cnt++;
  sched->txn_pool_free_cnt--;
  fd_txn_p_t * txn_p = sched->txn_pool + txn_idx;
  txn_p->payload_sz  = (ushort)pay_sz;

  txn_p->start_shred_idx = (ushort)fd_uint_min( shred_split( sched, block, block->fec_buf_boff+block->fec_buf_soff ), USHORT_MAX ); /* monitoring-only ushorts; saturate under bench shred counts */
  txn_p->start_shred_idx = fd_ushort_if( txn_p->start_shred_idx>0U, (ushort)(txn_p->start_shred_idx-1U), txn_p->start_shred_idx );
  txn_p->end_shred_idx = (ushort)fd_uint_min( shred_split( sched, block, block->fec_buf_boff+block->fec_buf_soff+(uint)pay_sz ), USHORT_MAX );

  fd_memcpy( txn_p->payload, payload, pay_sz );
  fd_memcpy( TXN(txn_p),     txn,     txn_sz );
  txn_bitset_remove( sched->exec_done_set, txn_idx );
  txn_bitset_remove( sched->sigverify_done_set, txn_idx );
  txn_bitset_remove( sched->poh_mixin_done_set, txn_idx );
  sched->txn_info_pool[ txn_idx ].flags = fd_ulong_if( sched->lthash_oob && poison_alt_cnt && !alts, FD_SCHED_TXN_ALT_UNRESOLVED, 0UL );
  sched->txn_info_pool[ txn_idx ].received_ns = block->fec_completed_ns;
  sched->txn_info_pool[ txn_idx ].txn_err = 0;
  sched->txn_info_pool[ txn_idx ].is_simple_vote = 0;

  sched->txn_info_pool[ txn_idx ].tick_parsed = fd_tickcount();
  sched->txn_info_pool[ txn_idx ].tick_sigverify_disp = LONG_MAX;
  sched->txn_info_pool[ txn_idx ].tick_sigverify_done = LONG_MAX;
  sched->txn_info_pool[ txn_idx ].tick_exec_disp = LONG_MAX;
  sched->txn_info_pool[ txn_idx ].tick_exec_done = LONG_MAX;
  sched->txn_info_pool[ txn_idx ].tick_load_start = LONG_MAX;
  sched->txn_info_pool[ txn_idx ].tick_check_start = LONG_MAX;
  sched->txn_info_pool[ txn_idx ].tick_exec_start = LONG_MAX;
  sched->txn_info_pool[ txn_idx ].tick_commit_start = LONG_MAX;
  sched->txn_info_pool[ txn_idx ].tick_commit_end = LONG_MAX;

  sched->txn_info_pool[ txn_idx ].slot          = block->slot;
  sched->txn_info_pool[ txn_idx ].bank_seq      = ULONG_MAX;
  sched->txn_info_pool[ txn_idx ].index_in_slot  = block->txn_parsed_cnt;
  sched->txn_info_pool[ txn_idx ].exec_tile_idx           = ULONG_MAX;
  sched->txn_info_pool[ txn_idx ].sigverify_exec_tile_idx = ULONG_MAX;
  sched->txn_info_pool[ txn_idx ].compute_units_consumed = 0U;
  sched->txn_info_pool[ txn_idx ].max_compute_units = ULONG_MAX;
  sched->txn_info_pool[ txn_idx ].transaction_fee = 0UL;
  sched->txn_info_pool[ txn_idx ].priority_fee = 0UL;
  sched->txn_info_pool[ txn_idx ].tips = 0UL;
  block->fec_buf_soff += (uint)pay_sz;
  block->txn_parsed_cnt++;
#if FD_SCHED_SKIP_SIGVERIFY
  txn_bitset_insert( sched->sigverify_done_set, txn_idx );
  block->txn_sigverify_done_cnt++;
#endif
#if FD_SCHED_SKIP_POH
  txn_bitset_insert( sched->poh_mixin_done_set, txn_idx );
#endif
  block->txns_rem--;
  return FD_SCHED_DEAD_REASON_NONE;
}

#undef CHECK
#undef CHECK_LEFT

static void
dispatch_sigverify( fd_sched_t * sched, fd_sched_block_t * block, ulong bank_idx, int exec_tile_idx, fd_sched_task_t * out ) {
  /* Dispatch transactions for sigverify in parse order. */
  uint txn_idx = block->txn_sigverify_next_idx;
  FD_TEST( txn_idx && txn_idx<sched->depth );
  out->task_type = FD_SCHED_TT_TXN_SIGVERIFY;
  out->txn_sigverify->bank_idx = bank_idx;
  out->txn_sigverify->txn_idx  = txn_idx;
  out->txn_sigverify->exec_idx = (ulong)exec_tile_idx;
  sched->txn_info_pool[ out->txn_sigverify->txn_idx ].sigverify_exec_tile_idx = (ulong)exec_tile_idx;
  sched->sigverify_ready_bitset[ 0 ] = fd_ulong_clear_bit( sched->sigverify_ready_bitset[ 0 ], exec_tile_idx );
  sched->tile_to_bank_idx[ exec_tile_idx ] = bank_idx;
  block->txn_sigverify_in_flight_cnt++;
  block->txn_sigverify_next_idx = sched->txn_info_pool[ txn_idx ].next_idx;
  exec_ready_bitsets_check( sched );
}

/* Retires a microblock whose PoH hashing has completed, and eagerly
   does as much mixin as possible.  Returns FD_SCHED_DEAD_REASON_NONE on
   success, else the dead reason. */
static int
poh_retire_mblk( fd_sched_t * sched, fd_sched_block_t * block, uint mblk_idx ) {
  fd_sched_mblk_t * mblk = sched->mblk_pool+mblk_idx;
  FD_TEST( mblk->curr_hashcnt==mblk->hashcnt );
  block->poh_hashing_done_cnt++;
  sched->metrics->mblk_poh_hashed_cnt++;
  if( FD_LIKELY( !mblk->is_tick ) ) {
    mblk_slist_idx_push_tail( block->mblks_mixin_in_progress, mblk_idx, sched->mblk_pool );
  } else {
    block->poh_hash_cmp_done_cnt++;
    sched->metrics->mblk_poh_done_cnt++;
    free_mblk( sched, block, mblk_idx );
    if( FD_UNLIKELY( memcmp( mblk->curr_hash, mblk->end_hash, sizeof(fd_hash_t) ) ) ) {
      FD_BASE58_ENCODE_32_BYTES( mblk->curr_hash->hash, our_str );
      FD_BASE58_ENCODE_32_BYTES( mblk->end_hash->hash, ref_str );
      FD_LOG_INFO(( "bad block: TICK_HASH_MISMATCH, mblk %u, ours %s, claimed %s, hashcnt %lu, slot %lu, parent slot %lu", mblk_idx, our_str, ref_str, mblk->hashcnt, block->slot, block->parent_slot ));
      return FD_SCHED_DEAD_REASON_TICK_HASH_MISMATCH;
    }
  }
  int mixin_res;
  while( (mixin_res=maybe_mixin( sched, block )) ) {
    if( FD_UNLIKELY( mixin_res==-1 ) ) return FD_SCHED_DEAD_REASON_ENTRY_HASH_MISMATCH;
    FD_TEST( mixin_res==1||mixin_res==2 );
  }
  return FD_SCHED_DEAD_REASON_NONE;
}

/* Retires microblocks at the head of the unhashed queue that have
   nothing left for PoH to hash.  Returns FD_SCHED_DEAD_REASON_NONE on
   success, else the dead reason. */
static int
poh_retire_ready_mblks( fd_sched_t * sched, fd_sched_block_t * block ) {
  while( block->mblk_unhashed_cnt ) {
    uint mblk_idx = (uint)mblk_slist_idx_peek_head( block->mblks_unhashed, sched->mblk_pool );
    fd_sched_mblk_t * mblk = sched->mblk_pool+mblk_idx;
    if( FD_LIKELY( mblk->curr_hashcnt!=mblk->hashcnt ) ) break;
    mblk_slist_idx_pop_head( block->mblks_unhashed, sched->mblk_pool );
    block->mblk_unhashed_cnt--;
    int dead_reason = poh_retire_mblk( sched, block, mblk_idx );
    if( FD_UNLIKELY( dead_reason!=FD_SCHED_DEAD_REASON_NONE ) ) return dead_reason;
  }
  return verify_ticks_eager( block );
}

/* Assembles a PoH task for the given exec tile.  Assumes there is a
   PoH task available for dispatching.  A microblock with nothing left
   to hash is dispatched as a degenerate zero-hashcnt task, so that it
   retires through fd_sched_task_done like any other PoH task. */
static void
dispatch_poh( fd_sched_t * sched, fd_sched_block_t * block, ulong bank_idx, int exec_tile_idx, ulong max_cnt, fd_sched_task_t * out ) {
  FD_TEST( max_cnt>=1UL && max_cnt<=FD_SCHED_POH_PARA );
  /* Every element of a batch advances by the same hashcnt, so the
     batch hashcnt is the smallest remaining hashcnt of its elements.
     Elements with more work left are re-queued on completion. */
  fd_sched_poh_hash_t * poh = out->poh_hash;
  ulong cnt     = 0UL;
  ulong hashcnt = ULONG_MAX;
  while( cnt<max_cnt ) {
    mblk_slist_t * list;
    if( FD_LIKELY( !mblk_slist_is_empty( block->mblks_hashing_in_progress, sched->mblk_pool ) ) ) {
      /* There's a PoH task in progress, just continue working on that. */
      list = block->mblks_hashing_in_progress;
    } else if( FD_LIKELY( block->mblk_unhashed_cnt ) ) {
      list = block->mblks_unhashed;
    } else {
      break; /* Nothing more to batch. */
    }
    uint mblk_idx = (uint)mblk_slist_idx_pop_head( list, sched->mblk_pool );
    fd_sched_mblk_t * mblk = sched->mblk_pool+mblk_idx;
    ulong hashcnt_todo = mblk->hashcnt-mblk->curr_hashcnt;
    /* A microblock with nothing left to hash can't share a batch with
       one that has work left.  The batch hashcnt would be zero, and the
       latter would never make progress. */
    if( FD_UNLIKELY( cnt && (!hashcnt_todo)!=(!hashcnt) ) ) {
      mblk_slist_idx_push_head( list, mblk_idx, sched->mblk_pool );
      break;
    }
    if( list==block->mblks_unhashed ) block->mblk_unhashed_cnt--;
    hashcnt = fd_ulong_min( hashcnt, hashcnt_todo );
    poh->mblk_idx[ cnt ] = mblk_idx;
    memcpy( poh->hash+cnt, mblk->curr_hash, sizeof(fd_hash_t) );
    cnt++;
    block->poh_mblk_in_flight_cnt++;
  }
  FD_TEST( cnt ); /* poh_hashing_queued_cnt>0 implies at least one queued microblock. */

  /* See FD_SCHED_MAX_POH_HASHES_PER_TASK.  A batch's per iteration
     cost depends on its width. */
  ulong iters_max = FD_SCHED_MAX_POH_HASHES_PER_TASK;
  if( cnt>=sched->poh_simd_min ) iters_max = fd_ulong_max( (FD_SCHED_MAX_POH_HASHES_PER_TASK<<8)/fd_sha256_simd_iter_cost_q8( cnt ), 1UL );
  hashcnt = fd_ulong_min( hashcnt, iters_max );
  out->task_type = FD_SCHED_TT_POH_HASH;
  poh->bank_idx  = bank_idx;
  poh->exec_idx  = (ulong)exec_tile_idx;
  poh->cnt       = cnt;
  poh->hashcnt   = hashcnt;
  sched->poh_inflight[ exec_tile_idx ] = *poh;

  sched->poh_ready_bitset[ 0 ] = fd_ulong_clear_bit( sched->poh_ready_bitset[ 0 ], exec_tile_idx );
  sched->tile_to_bank_idx[ exec_tile_idx ] = bank_idx;
  block->poh_hashing_in_flight_cnt++;
  exec_ready_bitsets_check( sched );
}

/* Does up to one transaction mixin.  Returns 1 if one mixin was done, 2
   if that mixin also completed a microblock, 0 if no transaction mixin
   was available, -1 if there is a PoH verify error. */
FD_WARN_UNUSED static int
maybe_mixin( fd_sched_t * sched, fd_sched_block_t * block ) {
  if( FD_UNLIKELY( mblk_slist_is_empty( block->mblks_mixin_in_progress, sched->mblk_pool ) ) ) return 0;
  FD_TEST( block->poh_hashing_done_cnt-block->poh_hash_cmp_done_cnt>0 );

  /* The microblock we would like to do mixin on is at the head of the
     queue.  It may have had some mixin, it may have never had any
     mixin.  In the case of the former, we should continue to mixin the
     same head microblock until it's done, lest the per-block bmtree
     gets clobbered when we start a new one. */
  ulong mblk_idx = mblk_slist_idx_pop_head( block->mblks_mixin_in_progress, sched->mblk_pool );
  fd_sched_mblk_t * mblk = sched->mblk_pool+mblk_idx;

  if( FD_UNLIKELY( mblk->end_txn_idx>block->txn_parsed_cnt ) ) {
    /* A partially parsed microblock is by definition at the end of the
       FEC stream.  If such a microblock is in progress, there should be
       no other microblock in this block so far that hasn't been
       dispatched, because microblocks are dispatched in parse order. */
    if( FD_UNLIKELY( block->mblk_unhashed_cnt ) ) {
      sched->print_buf_sz = 0UL;
      print_all( sched, block );
      FD_LOG_CRIT(( "invariant violation end_txn_idx %lu: %s", mblk->end_txn_idx, sched->print_buf ));
    }

    /* If we've decided to start mixin on a partially parsed microblock,
       there better be nothing else in-progress.  Otherwise, they might
       clobber the per-block bmtree for mixin. */
    if( FD_UNLIKELY( mblk->curr_txn_idx!=mblk->start_txn_idx && (block->poh_mblk_in_flight_cnt||!mblk_slist_is_empty( block->mblks_hashing_in_progress, sched->mblk_pool )||!mblk_slist_is_empty( block->mblks_mixin_in_progress, sched->mblk_pool )) ) ) {
      sched->print_buf_sz = 0UL;
      print_all( sched, block );
      FD_LOG_CRIT(( "invariant violation end_txn_idx %lu start_txn_idx %lu curr_txn_idx %lu: %s", mblk->end_txn_idx, mblk->start_txn_idx, mblk->curr_txn_idx, sched->print_buf ));
    }
  }

  /* Very rarely, we've finished hashing, but not all transactions in
     the microblock have been parsed out.  This can happen if we haven't
     received all the FEC sets for this microblock.  We can't yet fully
     mixin the microblock.  So we'll stick it back into the end of the
     queue, and try to see if there's a fully parsed microblock.
     Unless, there's truly nothing else to mixin.  Then we would start
     mixin with the partially parsed microblock.  We do this because the
     txn pool is meant to be an OOO scheduling window not tied to
     max_live_slots sizing requirements, so there shouldn't be a way for
     external input to tie up txn pool entries for longer than
     necessary. */
  if( FD_UNLIKELY( mblk->curr_txn_idx>=block->txn_parsed_cnt || /* Nothing more to mixin for this microblock. */
                   (mblk->end_txn_idx>block->txn_parsed_cnt &&  /* There is something to mixin, but the microblock isn't fully parsed yet ... */
                    mblk->curr_txn_idx==mblk->start_txn_idx &&  /* ... and we haven't started mixin on it yet ... */
                    (block->poh_mblk_in_flight_cnt ||           /* ... and another microblock is in-progress and might preempt this microblock and clobber the bmtree, so we shouldn't start the partial microblock just yet.  Counting microblocks rather than tasks matters: a batched PoH task is retired one microblock at a time, and the ones not yet retired are off every list. */
                     !mblk_slist_is_empty( block->mblks_hashing_in_progress, sched->mblk_pool ) ||
                     !mblk_slist_is_empty( block->mblks_mixin_in_progress, sched->mblk_pool ))) ) ) {
    mblk_slist_idx_push_tail( block->mblks_mixin_in_progress, mblk_idx, sched->mblk_pool );

    /* No other microblock in the mixin queue. */
    if( FD_UNLIKELY( block->poh_hashing_done_cnt-block->poh_hash_cmp_done_cnt==1 ) ) return 0;

    /* At this point, there's at least one more microblock in the mixin
       queue we could try.  It's a predecessor (in parse order) that
       finished hashing later than the partially parsed microblock at
       the head of the mixin queue. */

    /* It should never clobber the bmtree for a microblock that has had some mixin done on it. */
    if( FD_UNLIKELY( mblk->curr_txn_idx!=mblk->start_txn_idx ) ) {
      sched->print_buf_sz = 0UL;
      print_all( sched, block );
      FD_LOG_CRIT(( "invariant violation curr_txn_idx %lu start_txn_idx %lu: %s", mblk->curr_txn_idx, mblk->start_txn_idx, sched->print_buf ));
    }

    mblk_idx = mblk_slist_idx_pop_head( block->mblks_mixin_in_progress, sched->mblk_pool );
    mblk = sched->mblk_pool+mblk_idx;

    /* It should be a fresh microblock for mixin. */
    FD_TEST( mblk->curr_txn_idx==mblk->start_txn_idx );
    /* Invariant: at any given point in time, there can be at most one
       microblock that hasn't been fully parsed yet, due to the nature
       of sequential parsing.  So this microblock has to be fully
       parsed. */
    FD_TEST( mblk->end_txn_idx<=block->txn_parsed_cnt );
  }

  FD_TEST( mblk->curr_txn_idx<mblk->end_txn_idx );

  /* Now mixin. */
  if( FD_LIKELY( mblk->curr_txn_idx==mblk->start_txn_idx ) ) block->bmtree = fd_bmtree_commit_init( block->bmtree_mem, 32UL, 1UL, 0UL ); /* Optimize for single-transaction microblocks, which are the majority. */

  ulong txn_gidx = mblk->mixin_txn_idx;
  uint next_txn_pool_idx = sched->txn_info_pool[ txn_gidx ].next_idx;
  fd_txn_p_t * _txn = sched->txn_pool+txn_gidx;
  fd_txn_t * txn = TXN(_txn);
  for( ulong j=0; j<txn->signature_cnt; j++ ) {
    fd_bmtree_node_t node[ 1 ];
    fd_bmtree_hash_leaf( node, _txn->payload+txn->signature_off+FD_TXN_SIGNATURE_SZ*j, 64UL, 1UL );
    fd_bmtree_commit_append( block->bmtree, node, 1UL );
    mblk->curr_sig_cnt++;
  }

  /* Release the txn_idx. */
  txn_bitset_insert( sched->poh_mixin_done_set, txn_gidx );
  sched->metrics->txn_mixin_done_cnt++;
  if( txn_bitset_test( sched->exec_done_set, txn_gidx ) && txn_bitset_test( sched->sigverify_done_set, txn_gidx ) ) {
    if( FD_UNLIKELY( block->txn_idx_tail==(uint)txn_gidx ) ) block->txn_idx_tail = 0U;
    fd_rdisp_complete_txn( sched->rdisp, txn_gidx, 1 );
    sched->txn_pool_free_cnt++;
    block->txn_done_cnt++;
    sched->metrics->txn_done_cnt++;
  }

  mblk->curr_txn_idx++;
  mblk->mixin_txn_idx = next_txn_pool_idx;
  int rv = 2;
  if( FD_LIKELY( mblk->curr_txn_idx==mblk->end_txn_idx ) ) {
    /* Ready to compute the final hash for this microblock. */
    block->poh_hash_cmp_done_cnt++;
    sched->metrics->mblk_poh_done_cnt++;
    uchar * root = fd_bmtree_commit_fini( block->bmtree );
    uchar mixin_buf[ 64 ];
    fd_memcpy( mixin_buf, mblk->curr_hash, 32UL );
    fd_memcpy( mixin_buf+32UL, root, 32UL );
    fd_sha256_hash( mixin_buf, 64UL, mblk->curr_hash );
    free_mblk( sched, block, (uint)mblk_idx );
    /* Bypass PoH verification for fuzzing/testing throughput. */
    if( FD_UNLIKELY( !sched->bypass_poh_verify && memcmp( mblk->curr_hash, mblk->end_hash, sizeof(fd_hash_t) ) ) ) {
      FD_BASE58_ENCODE_32_BYTES( mblk->curr_hash->hash, our_str );
      FD_BASE58_ENCODE_32_BYTES( mblk->end_hash->hash, ref_str );
      FD_LOG_INFO(( "bad block: poh hash mismatch on mblk %lu, ours %s, claimed %s, hashcnt %lu, txns [%lu,%lu), %u sigs, slot %lu, parent slot %lu", mblk_idx, our_str, ref_str, mblk->hashcnt, mblk->start_txn_idx, mblk->end_txn_idx, mblk->curr_sig_cnt, block->slot, block->parent_slot ));
      return -1;
    }
  } else {
    /* There are more transactions to mixin in this microblock. */
    mblk_slist_idx_push_head( block->mblks_mixin_in_progress, mblk_idx, sched->mblk_pool );
    rv = 1;
  }

  return rv;
}

/* Does activating bank_idx move execution to another fork?  A block
   that descends from the last active block continues its fork, even
   across blocks that were added done and never activated, such as a
   leader block. */
static int
is_fork_switch( fd_sched_t * sched, ulong bank_idx ) {
  if( FD_UNLIKELY( sched->last_active_bank_idx==ULONG_MAX ) ) return 0;
  for( ulong idx=bank_idx; idx!=ULONG_MAX; idx=block_pool_ele( sched, idx )->parent_idx ) {
    if( idx==sched->last_active_bank_idx ) return 0;
  }
  return 1;
}

static void
try_activate_block( fd_sched_t * sched ) {
  /* Early return if there's already an active block. */
  if( FD_LIKELY( sched->active_bank_idx!=ULONG_MAX ) ) return;

  /* See if there are any allocated staging lanes that we can activate
     for scheduling ... */
  ulong staged_bitset = sched->staged_bitset;
  while( staged_bitset ) {
    int lane_idx  = fd_ulong_find_lsb( staged_bitset );
    staged_bitset = fd_ulong_pop_lsb( staged_bitset );

    ulong              head_idx     = sched->staged_head_bank_idx[ lane_idx ];
    fd_sched_block_t * head_block   = block_pool_ele( sched, head_idx );
    fd_sched_block_t * parent_block = block_pool_ele( sched, head_block->parent_idx );
    //FIXME: restore these invariant checks when we have immediate demotion of dying blocks
    //Today, dying blocks can remain staged if they have in-flight transactions.
    // if( FD_UNLIKELY( parent_block->dying ) ) {
    //   /* Invariant: no child of a dying block should be staged. */
    //   FD_LOG_CRIT(( "invariant violation: staged_head_bank_idx %lu, slot %lu, parent slot %lu on lane %d has parent_block->dying set, slot %lu, parent slot %lu",
    //                 head_idx, head_block->slot, head_block->parent_slot, lane_idx, parent_block->slot, parent_block->parent_slot ));
    // }
    // if( FD_UNLIKELY( head_block->dying ) ) {
    //   /* Invariant: no dying block should be staged. */
    //   FD_LOG_CRIT(( "invariant violation: staged_head_bank_idx %lu, slot %lu, prime %lu on lane %u has head_block->dying set",
    //                 head_idx, (ulong)head_block->block_id.slot, (ulong)head_block->block_id.prime, lane_idx ));
    // }
    if( block_is_done( parent_block ) && block_is_activatable( head_block ) ) {
      /* ... Yes, on this staging lane the parent block is done.  So we
         can activate the staged child. */
      if( FD_UNLIKELY( is_fork_switch( sched, head_idx ) ) ) { /* Forking is rare. */
        FD_LOG_DEBUG(( "activating block %lu:%lu: fork switch to lane %d", head_block->slot, head_idx, lane_idx ));
        sched->metrics->lane_switch_cnt++;
      } else {
        FD_LOG_DEBUG(( "activating block %lu:%lu on lane %d", head_block->slot, head_idx, lane_idx ));
      }
      sched->active_bank_idx = head_idx;
      return;
    }
  }

  /* ... No lane head with a done parent has real work.  Wake one that
     can speculate on the additions it owes, if the speculation pool has
     room enough to make the switch worthwhile. */
  staged_bitset = sched->staged_bitset;
  while( staged_bitset ) {
    int lane_idx  = fd_ulong_find_lsb( staged_bitset );
    staged_bitset = fd_ulong_pop_lsb( staged_bitset );

    ulong              head_idx     = sched->staged_head_bank_idx[ lane_idx ];
    fd_sched_block_t * head_block   = block_pool_ele( sched, head_idx );
    fd_sched_block_t * parent_block = block_pool_ele( sched, head_block->parent_idx );
    if( block_is_done( parent_block ) && block_is_stageable( head_block ) && block_may_speculate( sched, head_block, FD_SCHED_LTHASH_SPEC_THRESHOLD_PER_TILE*sched->exec_cnt ) ) {
      FD_LOG_DEBUG(( "activating block %lu:%lu: speculation on lane %d", head_block->slot, head_idx, lane_idx ));
      sched->metrics->lane_switch_cnt += (uint)is_fork_switch( sched, head_idx );
      sched->active_bank_idx = head_idx;
      return;
    }
  }

  /* ... No, promote unstaged blocks. */
  ulong root_idx = sched->root_idx;
  if( FD_UNLIKELY( root_idx==ULONG_MAX ) ) {
    FD_LOG_CRIT(( "invariant violation: root_idx==ULONG_MAX indicating fd_sched is uninitialized" ));
  }
  /* Find and stage the longest stageable unstaged fork.  This is a
     policy decision. */
  ulong depth = compute_longest_unstaged_fork( sched, root_idx );
  if( FD_LIKELY( depth>0UL ) ) {
    if( FD_UNLIKELY( sched->staged_bitset==fd_ulong_mask_lsb( FD_SCHED_MAX_STAGING_LANES ) ) ) {
      /* No more staging lanes available.  All of them are occupied by
         slow squatters.  Only empty blocks can be demoted, and so
         blocks with in-flight transactions, including dying in-flight
         blocks, shouldn't be demoted.  We demote all demotable lanes.
         Demotion isn't all that expensive, since demotable blocks have
         no transactions in them.  If a demoted block proves to be
         active still, it'll naturally promote back into a staging lane.

         In fact, all lanes should be demotable at this point.  None of
         the lanes have anything dispatchable, otherwise we would have
         simply activated one of the dispatchable lanes.  None of the
         lanes have anything in-flight either, as we allow for a grace
         period while something is in-flight, before we deactivate any
         block.  In principle, we could get rid of the grace period and
         deactivate right away.  In that case, it's okay if nothing is
         demotable at the moment, as that simply implies that all lanes
         have in-flight tasks.  We would get another chance to try to
         demote when the last in-flight task on any lane completes.

         A note on why this whole thing does not deadlock:

         One might reasonably wonder what happens if all the lanes are
         non-empty, non-dead, but for some reason couldn't be activated
         for dispatching.  We would deadlock in this case, as no lane
         dispatches to the point of being demotable, and no unstaged
         block can be promoted.  Such is not in fact possible.  The only
         way a dispatchable lane can be ineligible for activation is if
         it has a parent block that isn't done yet.  So a deadlock
         happens when this parent block, or any of its dispatchable
         ancestors, is unstaged.  An important invariant we maintain is
         that a staged block can't have an unstaged stageable parent.
         This invariant, by induction, gives us the guarantee that at
         least one of the lanes can be activated. */
      for( int l=0; l<(int)FD_SCHED_MAX_STAGING_LANES; l++ ) {
        /* We would be able to assert that all lanes are demotable,
           except that abandoned blocks are given no grace period for
           deactivation.  So there could be lanes transiently occupied
           by dying blocks that are neither demotable (due to in-flight
           tasks) nor activatable (due to being dying).  If
           rdisp_demote() supported non-empty blocks, then we could
           probably restore the assertion. */
        if( FD_UNLIKELY( !lane_is_demotable( sched, l ) ) ) continue;
        demote_lane( sched, l );
        sched->metrics->lane_demoted_cnt++;
      }
      /* We weren't able to successfully demote anything.  This is
         likely because all lanes are occupied by dying blocks with
         in-flight tasks.  We would get another chance to try to demote
         when the last in-flight task on any lane completes. */
      if( FD_UNLIKELY( sched->staged_bitset==fd_ulong_mask_lsb( FD_SCHED_MAX_STAGING_LANES ) ) ) return;
    }
    FD_TEST( sched->staged_bitset!=fd_ulong_mask_lsb( FD_SCHED_MAX_STAGING_LANES ) );
    int   lane_idx      = pick_free_lane( sched );
    ulong head_bank_idx = promote_from_longest_unstaged_fork( sched, root_idx, lane_idx );
    if( FD_UNLIKELY( head_bank_idx==ULONG_MAX ) ) {
      /* We found a promotable fork depth>0.  This should not happen. */
      FD_LOG_CRIT(( "invariant violation: head_bank_idx==ULONG_MAX" ));
    }
    /* We don't bother with promotion unless the block is immediately
       dispatchable.  So it's okay to set the active block here.  This
       doesn't cause out-of-order block replay because the parent of the
       promoted block must be done.  We can prove this by contradiction
       as follows.  The promoted block is the shallowest promotable
       block of its fork, so its parent is not promotable.  The parent
       is complete, because FEC sets arrive in order along a fork and a
       child of it has arrived.  Suppose the parent were not done.  It
       is not dying, or the promoted block would be dying too and not
       promotable.  It is not unstaged, or it would be promotable, being
       complete, and so dispatchable until it ends.  So it would be
       staged and dispatchable, with nothing in flight, since a block
       with tasks in flight is the active block or dying, and no block
       is active here.  That makes it activatable, and only a parent of
       its own that is not done kept the first loop above from
       activating it.  That parent is staged as well, because a staged
       block never has an unstaged parent that still has to run, and the
       same argument applies to it, and so on up the fork chain until a
       staged block with a done parent is reached, which the first loop
       would have activated. */
    fd_sched_block_t * head_block = block_pool_ele( sched, head_bank_idx );
    FD_LOG_DEBUG(( "activating block %lu:%lu: unstaged promotion to lane %d", head_block->slot, head_bank_idx, lane_idx ));
    sched->metrics->lane_switch_cnt += (uint)is_fork_switch( sched, head_bank_idx );
    sched->active_bank_idx = head_bank_idx;
    return;
  }
  /* No unstaged blocks to promote.  So we're done.  Yay. */
}

static void
check_or_set_active_block( fd_sched_t * sched ) {
  if( FD_UNLIKELY( sched->active_bank_idx==ULONG_MAX ) ) {
    try_activate_block( sched );
  } else {
    fd_sched_block_t * active_block = block_pool_ele( sched, sched->active_bank_idx );
    if( FD_UNLIKELY( block_should_deactivate( sched, active_block ) ) ) {
      sched->print_buf_sz = 0UL;
      print_all( sched, active_block );
      FD_LOG_NOTICE(( "%s", sched->print_buf ));
      FD_LOG_CRIT(( "invariant violation: should have been deactivated" ));
    }
  }
}

/* This function has two main jobs:
   - Mark everything on the fork tree dying.
   - Take blocks out of rdisp if possible. */
static void
subtree_mark_and_maybe_prune_rdisp( fd_sched_t * sched, fd_sched_block_t * block ) {
  if( FD_UNLIKELY( block->rooted ) ) {
    FD_LOG_CRIT(( "invariant violation: rooted block should not be abandoned, slot %lu, parent slot %lu",
                  block->slot, block->parent_slot ));
  }
  /* All minority fork nodes pass through this function eventually.  So
     this is a good point to check per-node invariants for minority
     forks. */
  if( FD_UNLIKELY( block->staged && !block->in_rdisp ) ) {
    FD_LOG_CRIT(( "invariant violation: staged block is not in the dispatcher, slot %lu, parent slot %lu",
                  block->slot, block->parent_slot ));
  }

  fd_sched_block_t * parent = block_pool_ele( sched, block->parent_idx );
  if( FD_UNLIKELY( !parent || !parent->in_sched ) ) {
    /* Only the root has no parent.  Abandon should never be called on
       the root.  So any block we are trying to abandon should have a
       parent. */
    FD_LOG_CRIT(( "invariant violation: parent not found slot %lu, parent slot %lu",
                  block->slot, block->parent_slot ));
  }

  /* Gated on the parent going down and on this block not already being
     on its way down.

     The parent test is because this function also runs on the block the
     public abandon API was called on, whose parent is very much alive.
     Inheriting there would stamp DEAD_ANCESTOR on a block that went
     down on its own, and overwrite the discarded bit the caller just
     set with the live parent's 0.

     The block test is because the walk also revisits blocks that
     already went down, and an ancestor abandoned later must not
     re-label them.  This cannot be decided based on dead_reason alone
     because a verdict the replay tile made leaves it NONE.

     Descendants work fine either way, because dying is set below before
     we recurse, so every child rightfully sees a dying parent. */
  if( FD_UNLIKELY( parent->dying && !block->dying ) ) record_lineage_death( block, parent );

  /* Setting the flag is non-optional and can happen more than once. */
  block->dying = 1;
  lthash_release_held_batch( sched, block );

  /* Removal from dispatcher should only happen once. */
  if( block->in_rdisp ) {

    /* The dispatcher expects blocks to be abandoned in the same order
       that they were added on each lane, which holds trivially with
       every staged block having its own lane. */
    if( FD_UNLIKELY( block->staged && sched->active_bank_idx==sched->staged_head_bank_idx[ block->staging_lane ] && sched->active_bank_idx!=ULONG_MAX ) ) {
      FD_TEST( block_pool_ele( sched, sched->active_bank_idx )==block );
      FD_LOG_DEBUG(( "reset active_bank_idx %lu: abandon", sched->active_bank_idx ));
      sched->last_active_bank_idx = sched->active_bank_idx;
      sched->active_bank_idx = ULONG_MAX;
      sched->metrics->deactivate_abandoned_cnt++;
    }

    /* We inform the dispatcher of an abandon only when there are no
       more in-flight transactions.  Otherwise, if the dispatcher
       recycles the same txn_id that was just abandoned, and we receive
       completion of an in-flight transaction whose txn_id was just
       recycled. */
    // FIXME The recycling might be fine now that we no longer use
    // txn_id to index into anything.  We might be able to just drop
    // txn_id on abandoned blocks.  Though would this leak transaction
    // content if the txn_id is recycled?
    // Note that subtree pruning from sched isn't dependent on the
    // in-flight check being present here, as is_prunable already checks
    // for in-flight==0.
    int abandon = !block_is_in_flight( block );

    if( abandon ) {
      block->in_rdisp = 0;
      sched->metrics->lthash_discarded_add_owed_cnt    += block->add_owed_cnt;
      sched->metrics->lthash_discarded_add_pending_cnt += block->add_created_cnt-block->add_surfaced_cnt;
      sched->metrics->lthash_discarded_sub_queued_cnt  += block->sub_queued_cnt;
      sched->metrics->lthash_discarded_sub_applied_cnt += block->sub_applied_cnt;
      sched->metrics->lthash_discarded_add_applied_cnt += block->add_applied_cnt-block->add_undone_cnt;
      lthash_block_reset( sched, block );
      fd_rdisp_abandon_block( sched->rdisp, (ulong)(block-sched->block_pool) );
      block->txn_idx_tail = 0U;
      sched->txn_pool_free_cnt += block->txn_parsed_cnt-block->txn_done_cnt; /* in_flight_cnt==0 */

      sched->metrics->block_abandoned_cnt++;
      sched->metrics->txn_abandoned_parsed_cnt    += block->txn_parsed_cnt;
      sched->metrics->txn_abandoned_exec_done_cnt += block->txn_exec_done_cnt;
      sched->metrics->txn_abandoned_done_cnt      += block->txn_done_cnt;

      //FIXME when demote supports non-empty blocks, we should demote
      //the block from the lane unconditionally and immediately,
      //regardless of whether it's safe to abandon or not.  So a block
      //would go immediately from staged to unstaged and eventually to
      //abandoned.
      if( FD_LIKELY( block->staged ) ) {
        FD_LOG_DEBUG(( "block %lu:%lu exited lane %lu: abandon", block->slot, block_to_idx( sched, block ), block->staging_lane ));
        block->staged = 0;
        /* Release the staging lane, which the block had to itself. */
        sched->staged_bitset = fd_ulong_clear_bit( sched->staged_bitset, (int)block->staging_lane );
        sched->staged_head_bank_idx[ block->staging_lane ] = ULONG_MAX;
      }
    }
  }

  /* Abandon the entire fork chaining off of this block. */
  ulong child_idx = block->child_idx;
  while( child_idx!=ULONG_MAX ) {
    fd_sched_block_t * child = block_pool_ele( sched, child_idx );
    subtree_mark_and_maybe_prune_rdisp( sched, child );
    child_idx = child->sibling_idx;
  }
}

/* This function tells sched that the subtree is no longer worth
   replaying.  It can happen as a result of one of the following.
     - Bad block at head of lane.
     - Bad block at tail of lane.
     - Root notify.

   It's safe to call this function more than once on the same block. */
static void
subtree_abandon( fd_sched_t * sched, fd_sched_block_t * block ) {
  subtree_mark_and_maybe_prune_rdisp( sched, block );
  /* We do not gate refcnt releases on the entire subtree being
     prunable.  In the root notify case there can be in-flight tasks in
     the middle of a subtree, and gating on whole-subtree prunability
     would defer the release of an otherwise prunable block, e.g. an
     inactive sibling of an in-flight block, to a later abandon such as
     a subsequent root notify.  That could stall bank reclamation.

     The sched fork tree still stays in sync with the banks tree.  This
     is to prevent attacks targeting lifetime discrepancy.  So while we
     know that the subtree can be pruned from sched at this point, we
     only release refcnts here and stop short of actually pruning, which
     remains solely initiated by banks. */
  subtree_release_refcnt( sched, block );
}

/* Release the bank refcnt for every block in the subtree that sched is
   done with.  This is evaluated per block.  A block's refcnt is
   released as soon as that block individually qualifies, independent of
   whether its siblings or descendants still have in-flight tasks.  This
   is safe because the actual pruning is initiated separately by banks,
   and gated on the whole subtree's refcnts reaching zero.  Releasing
   refcnts eagerly per block get us there sooner.  Blocks that are still
   in-flight will be released when their last task drains.  This
   function is idempotent. */
static void
subtree_release_refcnt( fd_sched_t * sched, fd_sched_block_t * block ) {
  FD_TEST( block->in_sched );
  if( block->refcnt && block_is_prunable( block ) ) {
    FD_TEST( block->dying ); /* The happy path releases the refcnt on full replay.  Only bad blocks end up here. */
    FD_TEST( !block->block_end_done ); /* Implied by an outstanding refcnt.  The happy path releases the refcnt on full replay. */
    block->refcnt = 0;
    FD_TEST( ref_q_avail( sched->ref_q ) );
    ref_q_push_tail( sched->ref_q, block_to_idx( sched, block ) );
    if( FD_LIKELY( block->block_start_done ) ) FD_LOG_DEBUG(( "block %lu:%lu replayed partially, releasing refcnt without full replay", block->slot, block_to_idx( sched, block ) ));
    else FD_LOG_DEBUG(( "block %lu:%lu replayed nothing, releasing refcnt without any replay", block->slot, block_to_idx( sched, block ) ));
  }

  ulong child_idx = block->child_idx;
  while( child_idx!=ULONG_MAX ) {
    fd_sched_block_t * child_block = block_pool_ele( sched, child_idx );
    subtree_release_refcnt( sched, child_block );
    child_idx = child_block->sibling_idx;
  }
}

static void
subtree_prune( fd_sched_t * sched, ulong bank_idx, ulong except_idx ) {
  fd_sched_block_t * head = block_pool_ele( sched, bank_idx );
  head->parent_idx        = ULONG_MAX;
  fd_sched_block_t * tail = head;

  while( head ) {
    FD_TEST( !head->refcnt );
    FD_TEST( head->in_sched );
    head->in_sched = 0;
    if( FD_UNLIKELY( block_to_idx( sched, head )==sched->last_active_bank_idx ) ) sched->last_active_bank_idx = ULONG_MAX; /* Don't count a lane switch if the last active block has been pruned. */

    ulong child_idx = head->child_idx;
    while( child_idx!=ULONG_MAX ) {
      fd_sched_block_t * child = block_pool_ele( sched, child_idx );
      /* Add children to be visited.  We abuse the parent_idx field to
         link up the next block to visit. */
      if( child_idx!=except_idx ) {
        tail->parent_idx = child_idx;
        tail             = child;
        tail->parent_idx = ULONG_MAX;
      }
      child_idx = child->sibling_idx;
    }

    /* Prune the current block.  We will never publish halfway into a
       staging lane, because anything that we are publishing away should
       be out of the dispatcher at this point, much less staged.
         - Anything on the rooted fork should have finished replaying
           gracefully and be out of the dispatcher.
         - Anything on minority forks should have been marked dying and
           be taken out of the dispatcher.

       There should be no more in-flight tasks either.  Prunes are
       initiated by banks, and the refcnt on the bank won't drop to zero
       unless all in-flight tasks have been drained.  So the fact that
       we're pruning implies that the bank thinks there's nothing more
       in-flight. */
    if( FD_UNLIKELY( block_is_in_flight( head ) ) ) {
      FD_LOG_CRIT(( "invariant violation: block has tasks in flight (%u exec %u sigverify %u poh %u cert %u lthash sub, %u/%u lthash add surfaced/done, %u lthash tasks), slot %lu, parent slot %lu",
                    head->txn_exec_in_flight_cnt, head->txn_sigverify_in_flight_cnt, head->poh_hashing_in_flight_cnt, head->cert_in_flight_cnt, head->sub_in_flight_cnt, head->add_surfaced_cnt, head->add_done_cnt, head->lthash_in_flight_cnt, head->slot, head->parent_slot ));
    }
    if( FD_UNLIKELY( head->in_rdisp ) ) {
      /* We should have removed it from the dispatcher when we were
         notified of the new root, or when in-flight transactions were
         drained. */
      FD_LOG_CRIT(( "invariant violation: block is in the dispatcher, slot %lu, parent slot %lu", head->slot, head->parent_slot ));
    }

    /* Return remaining mblk descriptors to the shared pool. */
    free_mblk_slist( sched, head, head->mblks_unhashed );
    free_mblk_slist( sched, head, head->mblks_hashing_in_progress );
    free_mblk_slist( sched, head, head->mblks_mixin_in_progress );

    if( FD_UNLIKELY( !head->block_end_done ) ) {
      sched->print_buf_sz = 0UL;
      print_block_metrics( sched, head );
      if( FD_LIKELY( head->block_start_done ) ) FD_LOG_DEBUG(( "block %lu:%lu replayed partially, pruning without full replay: %s", head->slot, block_to_idx( sched, head ), sched->print_buf ));
      else FD_LOG_DEBUG(( "block %lu:%lu replayed nothing, pruning without any replay: %s", head->slot, block_to_idx( sched, head ), sched->print_buf ));
    }

    sched->block_pool_popcnt--;

    fd_sched_block_t * next = block_pool_ele( sched, head->parent_idx );

    /* We don't have to clear the indices here since no one should be
       accessing them.  Defensive programming. */
    head->parent_idx  = ULONG_MAX;
    head->child_idx   = ULONG_MAX;
    head->sibling_idx = ULONG_MAX;

    head = next;
  }
}

static void
maybe_switch_block( fd_sched_t * sched, ulong bank_idx ) {
  /* This only happens rarely when there are dying in-flight blocks.
     Early exit and don't let dying blocks affect replay. */
  if( FD_UNLIKELY( bank_idx!=sched->active_bank_idx ) ) return;

  fd_sched_block_t * block = block_pool_ele( sched, bank_idx );
  if( FD_UNLIKELY( block_is_done( block ) ) ) {
    /* In a successfully replayed block, there should be exactly one
       subtraction and one addition per writable account, after
       adjusting for failed speculations.  This is the culmination of
       all the out-of-band LtHash activity in the block, and a cheap way
       for us to check count invariants. */
    FD_TEST( block->sub_applied_cnt==block->add_applied_cnt-block->add_undone_cnt );
    sched->metrics->lthash_frozen_cnt += block->sub_applied_cnt;
    lthash_block_reset( sched, block );
    fd_rdisp_remove_block( sched->rdisp, bank_idx );
    FD_LOG_DEBUG(( "block %lu:%lu exited lane %lu: remove", block->slot, bank_idx, block->staging_lane ));
    block->in_rdisp = 0;
    block->staged   = 0;
    sched->metrics->block_removed_cnt++;
    FD_LOG_DEBUG(( "reset active_bank_idx %lu: remove", sched->active_bank_idx ));
    sched->last_active_bank_idx = sched->active_bank_idx;
    sched->active_bank_idx = ULONG_MAX;

    /* Every staged block has a lane to itself, including this block.
       Release the lane and look for the next block to run, which is
       typically a child on another lane. */
    sched->staged_bitset = fd_ulong_clear_bit( sched->staged_bitset, (int)block->staging_lane );
    sched->staged_head_bank_idx[ block->staging_lane ] = ULONG_MAX;
    try_activate_block( sched );
    /* The common case activates a child of the block that just
       finished.  Count the uncommon cases. */
    int child_activated = sched->active_bank_idx!=ULONG_MAX && block_pool_ele( sched, sched->active_bank_idx )->parent_idx==bank_idx;
    sched->metrics->deactivate_no_child_cnt += (uint)!child_activated;
  } else if( block_should_deactivate( sched, block ) ) {
    /* We exhausted the active block, but it's not fully done yet.  We
       are just not getting FEC sets for it fast enough.  This could
       happen when the network path is congested, or when the leader
       simply went down.  Reset the active block. */
    sched->last_active_bank_idx = sched->active_bank_idx;
    sched->active_bank_idx = ULONG_MAX;
    /* Attribute this deactivation to a full speculation pool when the
       block still owes additions.  A full speculation pool is the only
       thing that could have stopped it from speculating.  The other
       reason, fec_eos, never reaches this branch.  A block with fec_eos
       is dispatched to finish, and then it leaves through the branch
       above. */
    sched->metrics->lthash_pool_full_cnt += (uint)(block->add_owed_cnt>0U);
    sched->metrics->deactivate_no_txn_cnt++;
    try_activate_block( sched );
  }
}

/* Returns length of the longest stageable unstaged fork, if there is
   one, and 0 otherwise. */
static ulong
compute_longest_unstaged_fork( fd_sched_t * sched, ulong bank_idx ) {
  if( FD_UNLIKELY( bank_idx==ULONG_MAX ) ) {
    FD_LOG_CRIT(( "invariant violation: bank_idx==ULONG_MAX" ));
  }

  fd_sched_block_t * block = block_pool_ele( sched, bank_idx );

  ulong max_child_depth = 0UL;
  ulong child_idx       = block->child_idx;
  while( child_idx!=ULONG_MAX ) {
    ulong child_depth = compute_longest_unstaged_fork( sched, child_idx );
    if( child_depth > max_child_depth ) {
      max_child_depth = child_depth;
    }
    fd_sched_block_t * child = block_pool_ele( sched, child_idx );
    child_idx = child->sibling_idx;
  }

  block->luf_depth = max_child_depth + fd_ulong_if( block_is_promotable( block ), 1UL, 0UL );
  return block->luf_depth;
}

/* Promotes one block onto lane_idx, the shallowest promotable block of
   the longest stageable unstaged fork under bank_idx, and returns its
   index, or ULONG_MAX if there is no such block.  Assumes
   compute_longest_unstaged_fork() ran on the fork tree since it last
   changed. */
static ulong
promote_from_longest_unstaged_fork( fd_sched_t * sched, ulong bank_idx, int lane_idx ) {
  while( bank_idx!=ULONG_MAX ) {
    fd_sched_block_t * block = block_pool_ele( sched, bank_idx );
    if( FD_LIKELY( block_is_promotable( block ) ) ) {
      block->staged       = 1;
      block->staging_lane = (ulong)lane_idx;
      fd_rdisp_promote_block( sched->rdisp, bank_idx, block->staging_lane );
      sched->staged_bitset = fd_ulong_set_bit( sched->staged_bitset, lane_idx );
      /* No need to update staged_popcnt_wmk because the fact that there
         are unstaged blocks implies we already maxed out lanes at one
         point. */
      sched->staged_head_bank_idx[ lane_idx ] = bank_idx;
      sched->metrics->block_promoted_cnt++;
      sched->metrics->lane_promoted_cnt++;
      FD_LOG_DEBUG(( "block %lu:%lu entered lane %lu: promote", block->slot, bank_idx, block->staging_lane ));
      /* The lane map is claimed first so that the pseudo transactions
         the drain creates land in it.  A block that hit fec_eos while
         unstaged has not drained yet.  Drain a little bit.  It is about
         to be activated, so the rest of the drain can be done by future
         polls. */
      lthash_claim_lane_map( sched, block );
      lthash_maybe_drain( sched, block, FD_SCHED_LTHASH_DRAIN_CHUNK );
      return bank_idx;
    }

    /* Descend into the longest stageable unstaged fork. */
    ulong max_depth      = 0UL;
    ulong best_child_idx = ULONG_MAX;
    for( ulong child_idx=block->child_idx; child_idx!=ULONG_MAX; ) {
      fd_sched_block_t * child = block_pool_ele( sched, child_idx );
      if( child->luf_depth>max_depth ) {
        max_depth      = child->luf_depth;
        best_child_idx = child_idx;
      }
      child_idx = child->sibling_idx;
    }
    bank_idx = best_child_idx;
  }
  return ULONG_MAX;
}

/* Returns 1 if the lane's block can be demoted, 0 otherwise. */
static int
lane_is_demotable( fd_sched_t * sched, int lane_idx ) {
  fd_sched_block_t * block = block_pool_ele( sched, sched->staged_head_bank_idx[ lane_idx ] );
  FD_TEST( block->staged );
  FD_TEST( block->staging_lane==(ulong)lane_idx );
  return block_is_demotable( block );
}

/* Demotes the lane's block, which must be demotable, and frees the
   lane. */
static void
demote_lane( fd_sched_t * sched, int lane_idx ) {
  ulong              bank_idx = sched->staged_head_bank_idx[ lane_idx ];
  fd_sched_block_t * block    = block_pool_ele( sched, bank_idx );
  FD_TEST( block->staged );
  FD_TEST( block->staging_lane==(ulong)lane_idx );

  lthash_demote( sched, block );
  int ret = fd_rdisp_demote_block( sched->rdisp, bank_idx );
  if( FD_UNLIKELY( ret!=0 ) ) {
    FD_LOG_CRIT(( "fd_rdisp_demote_block failed for block %lu:%lu, lane %d", block->slot, bank_idx, lane_idx ));
  }
  FD_LOG_DEBUG(( "block %lu:%lu exited lane %lu: demote", block->slot, bank_idx, block->staging_lane ));
  block->staged = 0;

  sched->staged_bitset = fd_ulong_clear_bit( sched->staged_bitset, lane_idx );
  sched->staged_head_bank_idx[ lane_idx ] = ULONG_MAX;
  sched->metrics->block_demoted_cnt++;
}

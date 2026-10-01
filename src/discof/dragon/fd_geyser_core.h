#ifndef HEADER_fd_src_discof_dragon_fd_geyser_core_h
#define HEADER_fd_src_discof_dragon_fd_geyser_core_h

/* fd_geyser_core.h turns the replay tile's notifications into the
   agave shaped callbacks of fd_geyser_api.h.

   The core owns the fork graph: one record per bank, keyed by the
   bank's app-wide sequence number (bank_seq, which is what the wire
   calls bank_id), holding the slot, the parent, the block identities
   and the counters that decide whether the bank is sealed.  It stores
   no content.

   It also owns the bank references that replay hands out.  Replay
   increments a bank's reference count once for every registered
   consumer tile when it publishes the bank, and again when the bank
   becomes the root; the core gives each of those back by calling
   release_fn with the bank's pool index.  A reference is given back as
   soon as the callbacks of the notification that carried it have
   returned and no consumer holds a claim on the bank
   (fd_geyser_bank_hold), or immediately when replay asks for it back.

   Every release carries the sequence number of the notification the
   core is acting on, plus one, and covers only the grants replay
   published below it.  Replay recycles a bank index as soon as its
   references are gone, so without that bound a release decided on an
   old notification could give back a grant for the next bank at the
   same index, one the core has not read yet.

   The owner drives the core from its link callbacks, passing the
   sequence number of the frag it is handling:

     fd_geyser_core_new / _join
     fd_geyser_core_register( core, consumer )   once per consumer
     per frag, by signal:
       fd_geyser_core_slot_completed / _slot_dead / _oc_advanced /
       _root_advanced / _drop_bank_ref
     on an input gap:  fd_geyser_core_link_gap, with the sequence
       number of the first frag after the gap, before handling it
     periodically:     fd_geyser_core_housekeeping */

#include "fd_geyser_api.h"
#include "../replay/fd_replay_tile.h"
#include "../../disco/events/generated/fd_event_gen.h"

#define FD_GEYSER_CORE_ALIGN (128UL)

/* FD_GEYSER_CONSUMER_MAX bounds the registrations one core serves. */

#define FD_GEYSER_CONSUMER_MAX (4UL)

/* FD_GEYSER_STALE_SLOTS is how far behind the newest slot a bank may
   fall before the core gives up on it, matching yellowstone's
   STALE_SLOT_THRESHOLD. */

#define FD_GEYSER_STALE_SLOTS (300UL)

/* FD_GEYSER_ROOT_CHAIN_MAX bounds how many banks one root advance can
   finalize.  Consensus advances the root a slot at a time, so the
   chain is short; a longer one means the core missed root
   notifications, and the banks beyond the bound are pruned without a
   finalized status rather than reported out of order. */

#define FD_GEYSER_ROOT_CHAIN_MAX (256UL)

/* FD_GEYSER_PENDING_MAX_SLOTS is how far the root may move past a bank
   that is still waiting for its records before the core gives up on
   it.  A bank whose commitment advanced before its records arrived
   keeps its confirmed or finalized status until it seals; past this
   bound the records are taken to be lost, and nothing is delivered for
   the bank at that level. */

#define FD_GEYSER_PENDING_MAX_SLOTS (32UL)

struct fd_geyser_core;
typedef struct fd_geyser_core fd_geyser_core_t;

struct fd_geyser_core_params {
  /* max_live_banks is the number of banks replay can have live, which
     is also the bound on the bank pool indices replay reports.  The
     core tracks up to twice as many records, because a bank whose
     reference it has already given back may be recycled by replay
     while the record is still in the fork graph. */
  ulong max_live_banks;

  /* alpenglow selects the consensus the validator runs.  Under
     alpenglow there is no optimistic confirmation notification, and a
     newly rooted bank is reported confirmed and then finalized, which
     is what agave's votor does for the same reason. */
  int alpenglow;

  /* records_gate makes the seal wait for the transaction and sysvar
     records of the bank.  It belongs off until the producer records
     exist, because a bank would otherwise never seal. */
  int records_gate;

  /* stale_slots overrides FD_GEYSER_STALE_SLOTS.  0 means the
     default. */
  ulong stale_slots;

  /* release_fn gives back the references replay granted for bank_idx
     while publishing a frag below seq_bound.  Called at most once per
     reference the core holds, and never from fd_geyser_core_new. */
  void * release_ctx;
  void (* release_fn)( void * ctx, ulong bank_idx, ulong seq_bound );

  /* read_fn reads one account at an accdb fork, which is what
     fd_geyser_read_account is built on: the core knows which fork a
     bank is, the owner of the core knows how to read one.  Returns 0
     and fills lamports, executable, owner, data and data_sz of out on
     success, or -1 if the fork could not be read.  out->data points
     into memory the reader owns, valid until the next call.

     A core made without one serves no account reads, which is what a
     server configured without deferred delivery needs. */
  void * read_ctx;
  int (* read_fn)( void *                ctx,
                   fd_accdb_fork_id_t    fork_id,
                   uchar const *         pubkey,
                   fd_geyser_account_t * out );
};

typedef struct fd_geyser_core_params fd_geyser_core_params_t;

/* The bits of a bank's sysvar mask.  Yellowstone seals a block only
   once it has seen the writes of these four sysvars
   (block_reconstruction_v2.rs:32-37), and so does the core. */

#define FD_GEYSER_SYSVAR_CLOCK             (1U)
#define FD_GEYSER_SYSVAR_SLOT_HASHES       (2U)
#define FD_GEYSER_SYSVAR_SLOT_HISTORY      (4U)
#define FD_GEYSER_SYSVAR_RECENT_BLOCKHASHES (8U)
#define FD_GEYSER_SYSVAR_ALL               (15U)

struct fd_geyser_core_metrics {
  ulong bank_created_cnt;
  ulong bank_discarded_cnt[ 7 ];                      /* by FD_GEYSER_DISCARD_* */
  ulong bank_incomplete_cnt[ FD_GEYSER_INCOMPLETE_CNT ];
  ulong status_cnt[ 7 ];                              /* by FD_GEYSER_SLOT_* */
  ulong ref_acquired_cnt;
  ulong ref_released_cnt;
  ulong pool_full_cnt;                                /* records evicted to make room */
  ulong map_full_cnt;                                 /* bank lookups that ran out of probes */
  ulong flush_cnt;                                    /* fork graph flushes */
  ulong unknown_bank_cnt;                             /* notifications naming a bank the core never saw */
  ulong ref_unnamed_cnt;                              /* references given up without a release, for want of a pool index */
  ulong txn_record_cnt;                               /* commit records accounted for */
  ulong txn_event_cnt;                                /* runtime_txn events received on the event links */
  ulong write_record_cnt;                             /* runtime-write records accounted for */
  ulong record_dropped_cnt;                           /* records the core could not read or whose bank is gone */
  ulong account_cnt;                                  /* account writes reported to consumers */
  ulong account_byte_cnt;                             /* account data bytes those writes carried */
  ulong record_gap_cnt;                               /* gaps reported on a record link */
  ulong txn_meta_failed_cnt;                          /* records whose transaction did not parse */
  ulong bank_pending_cnt;                             /* banks that owed a confirmed or finalized status */
  ulong pending_timeout_cnt;                          /* banks given up on because their records never arrived */
  ulong pending_dropped_cnt;                          /* banks given up on because their records are gone */
  ulong root_chain_broken_cnt;                        /* root advances whose chain did not reach the previous root */
  ulong bank_sealed_cnt;                              /* banks reported sealed */
  ulong acct_read_cnt;                                /* accounts read at a bank's fork */
  ulong acct_read_closed_cnt;                         /* those reads that found no account */
  ulong acct_read_fail_cnt;                           /* reads refused or failed */
};

typedef struct fd_geyser_core_metrics fd_geyser_core_metrics_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_geyser_core_align( void );

/* fd_geyser_core_footprint returns the size of the memory region the
   core needs, or 0 if the parameters are invalid. */

ulong
fd_geyser_core_footprint( fd_geyser_core_params_t const * params );

void *
fd_geyser_core_new( void *                          mem,
                    fd_geyser_core_params_t const * params );

fd_geyser_core_t *
fd_geyser_core_join( void * mem );

/* fd_geyser_core_register adds a consumer.  Returns 0 on success, or
   -1 if FD_GEYSER_CONSUMER_MAX consumers are already registered. */

int
fd_geyser_core_register( fd_geyser_core_t *           core,
                         fd_geyser_consumer_t const * consumer );

/* The notification handlers.  Each takes the replay message as it
   arrived on the link; the caller has checked the frag size. */

void
fd_geyser_core_slot_completed( fd_geyser_core_t *                 core,
                               fd_replay_slot_completed_t const * msg,
                               ulong                              frag_seq );

void
fd_geyser_core_slot_dead( fd_geyser_core_t *            core,
                          fd_replay_slot_dead_t const * msg,
                          ulong                         frag_seq );

void
fd_geyser_core_oc_advanced( fd_geyser_core_t *              core,
                            fd_replay_oc_advanced_t const * msg,
                            ulong                           frag_seq );

void
fd_geyser_core_root_advanced( fd_geyser_core_t *                core,
                              fd_replay_root_advanced_t const * msg,
                              ulong                             frag_seq );

void
fd_geyser_core_drop_bank_ref( fd_geyser_core_t * core,
                              ulong              bank_idx,
                              ulong              frag_seq );

/* fd_geyser_core_commit_record reports one committed transaction and
   the accounts it wrote.  The first record of a bank the core has not
   seen yet creates it, so records may arrive before the bank freezes.
   Returns 0 if the record was accounted for, or -1 if it was dropped:
   its fields do not describe a record the core can read, or the bank it
   names is gone.

   fd_geyser_core_runtime_write_record does the same for one account the
   runtime wrote outside of a transaction, and notes which of the four
   sysvars the seal waits for it was. */

int
fd_geyser_core_commit_record( fd_geyser_core_t *                       core,
                              fd_event_internal_commit_parts_t const * parts );

int
fd_geyser_core_runtime_write_record( fd_geyser_core_t *                             core,
                                     fd_event_internal_runtime_write_parts_t const * parts );

/* fd_geyser_core_record_gap reports that a record link lost frags.  The
   records that went missing belonged to banks that had not frozen yet,
   so every bank still in flight is marked incomplete; the banks that
   already froze and sealed are untouched.  Unlike a gap on the
   notification link this releases nothing: the record links carry no
   bank references. */

void
fd_geyser_core_record_gap( fd_geyser_core_t * core );

/* fd_geyser_core_txn_event takes one runtime_txn event from an event
   link.  The transaction itself is served from its commit record; the
   event is accounted for so that the two sources can be reconciled
   while the record is being moved over to the event. */

void
fd_geyser_core_txn_event( fd_geyser_core_t *             core,
                          fd_event_runtime_txn_t const * ev );

/* fd_geyser_core_link_gap reports that the core missed notifications.
   The fork graph is flushed, and a reference is given back for every
   bank index replay could have granted one for, because the core
   cannot know which grants it missed.  Releasing a bank index the
   core holds nothing for is a no-op for replay, so this leaks
   nothing and releases nothing twice.

   seq_bound is the sequence number of the first frag the core will
   handle after the gap, so the sweep covers every grant that went
   missing and none of the grants still on their way. */

void
fd_geyser_core_link_gap( fd_geyser_core_t * core,
                         ulong              seq_bound );

/* fd_geyser_core_housekeeping drops banks that fell too far behind the
   newest slot without ever resolving. */

void
fd_geyser_core_housekeeping( fd_geyser_core_t * core );

/* fd_geyser_core_end_of_startup reports the end of startup to every
   consumer, once. */

void
fd_geyser_core_end_of_startup( fd_geyser_core_t * core );

FD_FN_PURE fd_geyser_core_metrics_t const *
fd_geyser_core_metrics( fd_geyser_core_t const * core );

/* fd_geyser_core_bank_cnt returns the number of banks in the fork
   graph, and fd_geyser_core_ref_held_cnt the number of replay
   references the core has not given back yet. */

FD_FN_PURE ulong
fd_geyser_core_bank_cnt( fd_geyser_core_t const * core );

FD_FN_PURE ulong
fd_geyser_core_ref_held_cnt( fd_geyser_core_t const * core );

/* fd_geyser_core_pending_cnt returns the number of banks that owe a
   confirmed or finalized status, waiting for the records of their
   block. */

FD_FN_PURE ulong
fd_geyser_core_pending_cnt( fd_geyser_core_t const * core );

/* fd_geyser_core_bank_slot returns the slot of a tracked bank, or
   ULONG_MAX if the bank is unknown. */

FD_FN_PURE ulong
fd_geyser_core_bank_slot( fd_geyser_core_t const * core,
                          ulong                    bank_id );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_dragon_fd_geyser_core_h */

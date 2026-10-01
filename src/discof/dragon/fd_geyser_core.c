#include "fd_geyser_core.h"
#include "../../flamenco/runtime/fd_system_ids.h"

#define FD_GEYSER_CORE_MAGIC (0xf17eda2547d2a601UL) /* firedancer geyser */

/* GEYSER_BANK_SEQ_NULL is what the map uses for a free entry.  Replay
   starts bank_seq at 1 and reserves 0 as the invalid sentinel
   (fd_bank.h), so 0 cannot name a bank.  ULONG_MAX marks an entry that
   held a bank which has since been removed, so that a probe sequence
   through it continues. */

#define GEYSER_BANK_SEQ_NULL  (0UL)
#define GEYSER_BANK_SEQ_GRAVE (ULONG_MAX)

/* GEYSER_MAP_PROBE_MAX bounds a probe sequence, so that a lookup costs
   the same whatever the map holds.  A bank that does not fit within
   that many entries of its home slot is not indexed, which the caller
   handles by flushing the graph. */

#define GEYSER_MAP_PROBE_MAX (32UL)

struct geyser_bank {
  ulong bank_seq; /* GEYSER_BANK_SEQ_NULL while the record is free */
  ulong bank_idx;
  ulong slot;
  ulong parent_bank_seq;
  ulong parent_slot;
  ulong block_height;
  ulong parent_block_height;
  ulong txn_count_total;  /* transactions since genesis, from replay */
  ulong executed_txn_cnt; /* ULONG_MAX while the parent is unknown */
  ulong txn_records_seen;
  ulong acct_records_owed; /* account records the commit records seen announce */
  ulong acct_records_seen;
  ulong ref_cnt;          /* replay references not given back yet */
  ulong claim_cnt;        /* consumer claims */
  ulong order;            /* creation order */
  ulong confirm_order;    /* order the confirmation was named in, among the banks of one slot */
  ulong finalize_order;   /* order the finalization was named in, among the banks of one slot */

  fd_hash_t block_id;
  fd_hash_t block_hash;

  /* The accdb fork the bank's writes landed on, which is where the
     state the block left an account in is read.  Known from the moment
     the bank freezes; a bank the core learned about from a record has
     none until then. */
  fd_accdb_fork_id_t accdb_fork_id;
  int                has_fork;

  uint sysvar_mask;

  uint has_parent:1;
  uint created:1;
  uint completed:1;
  uint confirmed:1;
  uint rooted:1;
  uint dropped:1;
  uint pruned:1;   /* the pruning verdict, taken before anything is dropped */
  uint gapped:1;
  uint complete:1;
  uint sent_created:1;
  uint sent_processed:1;
  uint sent_confirmed:1;
  uint sent_finalized:1;
  uint pending_confirmed:1; /* confirmed, waiting for the bank to seal */
  uint pending_finalized:1; /* rooted, waiting for the bank to seal */
  uint sent_sealed:1;

  int incomplete_reason;
};

typedef struct geyser_bank geyser_bank_t;

struct fd_geyser_core {
  ulong magic;

  ulong max_live_banks;
  ulong bank_max;   /* records in the pool */
  ulong map_sz;     /* power of two */
  ulong stale_slots;
  int   alpenglow;
  int   records_gate;

  void * release_ctx;
  void (* release_fn)( void * ctx, ulong bank_idx, ulong seq_bound );

  void * read_ctx;
  int (* read_fn)( void * ctx, fd_accdb_fork_id_t fork_id, uchar const * pubkey, fd_geyser_account_t * out );

  /* The bound every release carries: one past the newest notification
     the core has handled, so a release covers exactly the grants the
     core could have read. */
  ulong seq_bound;

  geyser_bank_t * bank;  /* bank_max entries */
  ulong *         map;   /* map_sz entries: bank_seq */
  ulong *         map_rec;

  ulong bank_cnt;
  ulong grave_cnt;  /* map entries whose bank is gone */
  ulong ref_held;
  ulong order_next;
  ulong bank_seq_hi;   /* highest bank_seq seen */
  ulong slot_hi;       /* highest slot seen */
  ulong root_bank_seq; /* ULONG_MAX until a root is known */
  ulong root_slot;

  int   startup_done;

  /* The deferred statuses the core owes: a bank whose commitment
     advanced before the records of its block had all arrived keeps its
     status until it seals.  Each bank waits on its own records only,
     so one that never seals costs itself its levels and nothing else.
     pending_cnt is how many banks owe a status, so that a record costs
     nothing when none do; the two sequence numbers order the banks of
     one slot. */
  ulong pending_cnt;
  ulong confirm_seq;
  ulong finalize_seq;

  /* The meta object of the transaction the core is reporting, built
     on the first ask of the callback it is reported in.  meta_rec is
     the record it was built from, which is what makes a stale object
     tell itself apart. */
  fd_event_internal_commit_parts_t const * meta_rec;
  fd_txn_meta_scratch_t                    meta_scratch[1];
  fd_txn_meta_t                            meta[1];
  int                                      meta_valid;

  ulong                consumer_cnt;
  fd_geyser_consumer_t consumer[ FD_GEYSER_CONSUMER_MAX ];

  fd_geyser_core_metrics_t metrics;
};

/* Construction ******************************************************/

FD_FN_CONST ulong
fd_geyser_core_align( void ) {
  return FD_GEYSER_CORE_ALIGN;
}

static ulong
geyser_bank_max( ulong max_live_banks ) {
  /* Twice the live bank count: replay may recycle a bank index as soon
     as the core gave its reference back, while the old record is still
     in the fork graph waiting to be rooted or pruned. */
  return 2UL*max_live_banks;
}

static ulong
geyser_map_sz( ulong bank_max ) {
  return fd_ulong_pow2_up( 4UL*bank_max );
}

ulong
fd_geyser_core_footprint( fd_geyser_core_params_t const * params ) {
  if( FD_UNLIKELY( !params ) ) return 0UL;
  if( FD_UNLIKELY( params->max_live_banks<2UL || params->max_live_banks>(1UL<<24) ) ) return 0UL;
  if( FD_UNLIKELY( !params->release_fn ) ) return 0UL;

  ulong bank_max = geyser_bank_max( params->max_live_banks );
  ulong map_sz   = geyser_map_sz( bank_max );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_GEYSER_CORE_ALIGN,   sizeof(fd_geyser_core_t)       );
  l = FD_LAYOUT_APPEND( l, alignof(geyser_bank_t), bank_max*sizeof(geyser_bank_t) );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),         map_sz*sizeof(ulong)           );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),         map_sz*sizeof(ulong)           );
  return FD_LAYOUT_FINI( l, FD_GEYSER_CORE_ALIGN );
}

void *
fd_geyser_core_new( void *                          mem,
                    fd_geyser_core_params_t const * params ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_GEYSER_CORE_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_geyser_core_footprint( params ) ) ) {
    FD_LOG_WARNING(( "invalid fd_geyser_core params" ));
    return NULL;
  }

  ulong bank_max = geyser_bank_max( params->max_live_banks );
  ulong map_sz   = geyser_map_sz( bank_max );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_geyser_core_t * core  = FD_SCRATCH_ALLOC_APPEND( l, FD_GEYSER_CORE_ALIGN,   sizeof(fd_geyser_core_t)       );
  void *             bank  = FD_SCRATCH_ALLOC_APPEND( l, alignof(geyser_bank_t), bank_max*sizeof(geyser_bank_t) );
  void *             map   = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),         map_sz*sizeof(ulong)           );
  void *             mrec  = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),         map_sz*sizeof(ulong)           );
  FD_SCRATCH_ALLOC_FINI( l, FD_GEYSER_CORE_ALIGN );

  fd_memset( core, 0, sizeof(fd_geyser_core_t) );
  fd_memset( bank, 0, bank_max*sizeof(geyser_bank_t) );
  fd_memset( map,  0, map_sz*sizeof(ulong)           );
  fd_memset( mrec, 0, map_sz*sizeof(ulong)           );

  core->max_live_banks = params->max_live_banks;
  core->bank_max       = bank_max;
  core->map_sz         = map_sz;
  core->stale_slots    = params->stale_slots ? params->stale_slots : FD_GEYSER_STALE_SLOTS;
  core->alpenglow      = params->alpenglow;
  core->records_gate   = params->records_gate;
  core->release_ctx    = params->release_ctx;
  core->release_fn     = params->release_fn;
  core->read_ctx       = params->read_ctx;
  core->read_fn        = params->read_fn;
  core->bank           = bank;
  core->map            = map;
  core->map_rec        = mrec;
  core->root_bank_seq  = ULONG_MAX;
  core->root_slot      = ULONG_MAX;

  FD_COMPILER_MFENCE();
  core->magic = FD_GEYSER_CORE_MAGIC;
  FD_COMPILER_MFENCE();
  return mem;
}

fd_geyser_core_t *
fd_geyser_core_join( void * mem ) {
  fd_geyser_core_t * core = mem;
  if( FD_UNLIKELY( !core ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( core->magic!=FD_GEYSER_CORE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  return core;
}

int
fd_geyser_core_register( fd_geyser_core_t *           core,
                         fd_geyser_consumer_t const * consumer ) {
  if( FD_UNLIKELY( core->consumer_cnt>=FD_GEYSER_CONSUMER_MAX ) ) return -1;
  core->consumer[ core->consumer_cnt++ ] = *consumer;
  return 0;
}

FD_FN_PURE fd_geyser_core_metrics_t const *
fd_geyser_core_metrics( fd_geyser_core_t const * core ) {
  return &core->metrics;
}

FD_FN_PURE ulong
fd_geyser_core_bank_cnt( fd_geyser_core_t const * core ) {
  return core->bank_cnt;
}

FD_FN_PURE ulong
fd_geyser_core_ref_held_cnt( fd_geyser_core_t const * core ) {
  return core->ref_held;
}

FD_FN_PURE ulong
fd_geyser_core_pending_cnt( fd_geyser_core_t const * core ) {
  return core->pending_cnt;
}

/* Fork graph index ***************************************************/

static ulong
geyser_map_hash( ulong bank_seq ) {
  return fd_ulong_hash( bank_seq );
}

static geyser_bank_t *
geyser_query( fd_geyser_core_t * core,
              ulong              bank_seq ) {
  if( FD_UNLIKELY( bank_seq==GEYSER_BANK_SEQ_NULL || bank_seq==GEYSER_BANK_SEQ_GRAVE ) ) return NULL;
  ulong mask = core->map_sz-1UL;
  ulong i    = geyser_map_hash( bank_seq ) & mask;
  for( ulong probe=0UL; probe<GEYSER_MAP_PROBE_MAX; probe++ ) {
    ulong key = core->map[ i ];
    if( key==GEYSER_BANK_SEQ_NULL ) return NULL;
    if( key==bank_seq ) return core->bank + core->map_rec[ i ];
    i = (i+1UL) & mask;
  }
  return NULL;
}

/* geyser_map_insert indexes a record.  Returns 0 on success, or -1 if
   the probe sequence from the bank's home slot is full, which a caller
   recovers from by flushing. */

static int
geyser_map_insert( fd_geyser_core_t * core,
                   ulong              bank_seq,
                   ulong              rec_idx ) {
  ulong mask = core->map_sz-1UL;
  ulong i    = geyser_map_hash( bank_seq ) & mask;
  for( ulong probe=0UL; probe<GEYSER_MAP_PROBE_MAX; probe++ ) {
    ulong key = core->map[ i ];
    if( key==GEYSER_BANK_SEQ_NULL || key==GEYSER_BANK_SEQ_GRAVE || key==bank_seq ) {
      core->map    [ i ] = bank_seq;
      core->map_rec[ i ] = rec_idx;
      return 0;
    }
    i = (i+1UL) & mask;
  }
  core->metrics.map_full_cnt++;
  return -1;
}

static void
geyser_map_remove( fd_geyser_core_t * core,
                   ulong              bank_seq ) {
  ulong mask = core->map_sz-1UL;
  ulong i    = geyser_map_hash( bank_seq ) & mask;
  for( ulong probe=0UL; probe<GEYSER_MAP_PROBE_MAX; probe++ ) {
    ulong key = core->map[ i ];
    if( key==GEYSER_BANK_SEQ_NULL ) return;
    if( key==bank_seq ) {
      core->map[ i ] = GEYSER_BANK_SEQ_GRAVE;
      core->grave_cnt++;
      return;
    }
    i = (i+1UL) & mask;
  }
}

/* geyser_map_rebuild reindexes every live record.  Returns 0 on
   success, or -1 if some record found no free entry within a probe
   sequence of its home slot. */

static int
geyser_map_rebuild( fd_geyser_core_t * core ) {
  fd_memset( core->map, 0, core->map_sz*sizeof(ulong) );
  core->grave_cnt = 0UL;
  int err = 0;
  for( ulong i=0UL; i<core->bank_max; i++ ) {
    if( core->bank[ i ].bank_seq==GEYSER_BANK_SEQ_NULL ) continue;
    if( FD_UNLIKELY( geyser_map_insert( core, core->bank[ i ].bank_seq, i ) ) ) err = -1;
  }
  return err;
}

/* geyser_map_compact keeps probe sequences short.  A removed entry has
   to stay in the map so that the probes running through it still find
   what is behind it, so the map is rebuilt once a quarter of it is
   made of those.  Records keep their addresses, so this is safe to
   call between notifications. */

static void
geyser_flush( fd_geyser_core_t * core,
              int                reason );

static void
geyser_map_compact( fd_geyser_core_t * core ) {
  if( FD_LIKELY( core->grave_cnt<=core->map_sz/4UL ) ) return;
  if( FD_UNLIKELY( geyser_map_rebuild( core ) ) ) {
    FD_DRAGON_WARN_POW2( core->metrics.flush_cnt+1UL,
                         "dragon could not index every bank, dropping the fork graph" );
    geyser_flush( core, FD_GEYSER_DISCARD_FLUSH );
  }
}

/* Callbacks **********************************************************/

static void
geyser_emit_status( fd_geyser_core_t * core,
                    ulong              slot,
                    ulong              parent_slot,
                    int                has_parent,
                    int                status,
                    ulong              bank_id,
                    int                has_bank_id,
                    char const *       dead_error ) {
  core->metrics.status_cnt[ status ]++;
  for( ulong i=0UL; i<core->consumer_cnt; i++ ) {
    fd_geyser_consumer_t const * c = core->consumer + i;
    if( FD_LIKELY( c->on_slot_status ) )
      c->on_slot_status( c->ctx, slot, parent_slot, has_parent, status, bank_id, has_bank_id, dead_error );
  }
}

static void
geyser_emit_block_meta( fd_geyser_core_t *    core,
                        geyser_bank_t const * rec ) {
  fd_geyser_block_meta_t meta = {
    .slot                = rec->slot,
    .parent_slot         = rec->parent_slot,
    .has_parent          = !!rec->has_parent,
    .block_hash          = rec->block_hash,
    .block_id            = rec->block_id,
    .block_height        = rec->block_height,
    .parent_block_height = rec->parent_block_height,
    .executed_txn_cnt    = rec->executed_txn_cnt,
    .entry_cnt           = 0UL
  };
  for( ulong i=0UL; i<core->consumer_cnt; i++ ) {
    fd_geyser_consumer_t const * c = core->consumer + i;
    if( FD_LIKELY( c->on_block_meta ) ) c->on_block_meta( c->ctx, &meta, rec->bank_seq );
  }
}

static void
geyser_emit_account( fd_geyser_core_t *          core,
                     fd_geyser_account_t const * acct ) {
  core->metrics.account_cnt++;
  core->metrics.account_byte_cnt += acct->data_sz;
  for( ulong i=0UL; i<core->consumer_cnt; i++ ) {
    fd_geyser_consumer_t const * c = core->consumer + i;
    if( FD_LIKELY( c->on_account && c->wants_accounts ) ) c->on_account( c->ctx, acct, acct->slot, acct->bank_id );
  }
}

static void
geyser_emit_txn( fd_geyser_core_t *      core,
                 fd_geyser_txn_t const * txn ) {
  for( ulong i=0UL; i<core->consumer_cnt; i++ ) {
    fd_geyser_consumer_t const * c = core->consumer + i;
    if( FD_LIKELY( c->on_transaction && c->wants_transactions ) ) c->on_transaction( c->ctx, txn, txn->slot, txn->bank_id );
  }
}

static void
geyser_emit_sealed( fd_geyser_core_t * core,
                    ulong              bank_id ) {
  core->metrics.bank_sealed_cnt++;
  for( ulong i=0UL; i<core->consumer_cnt; i++ ) {
    fd_geyser_consumer_t const * c = core->consumer + i;
    if( FD_LIKELY( c->on_bank_sealed ) ) c->on_bank_sealed( c->ctx, bank_id );
  }
}

static void
geyser_emit_discarded( fd_geyser_core_t * core,
                       ulong              bank_id,
                       int                reason ) {
  core->metrics.bank_discarded_cnt[ reason ]++;
  for( ulong i=0UL; i<core->consumer_cnt; i++ ) {
    fd_geyser_consumer_t const * c = core->consumer + i;
    if( FD_LIKELY( c->on_bank_discarded ) ) c->on_bank_discarded( c->ctx, bank_id, reason );
  }
}

/* Bank references ****************************************************/

/* geyser_ref_give_back hands every reference the core holds on the
   record back to replay.  One release message covers every reference
   replay granted for the bank index, so calling this for a record
   that holds nothing is harmless. */

static void
geyser_ref_give_back( fd_geyser_core_t * core,
                      geyser_bank_t *    rec ) {
  if( FD_LIKELY( !rec->ref_cnt ) ) return;

  core->ref_held                -= rec->ref_cnt;
  core->metrics.ref_released_cnt += rec->ref_cnt;
  rec->ref_cnt                   = 0UL;

  /* A release names a bank by its index in replay's pool, so a bank
     whose index the core was never told cannot be released by name.
     The references it holds are recovered by the sweep an input gap
     does, which names every index. */
  if( FD_UNLIKELY( rec->bank_idx>=core->max_live_banks ) ) {
    core->metrics.ref_unnamed_cnt++;
    return;
  }

  /* One release covers every grant replay made for the bank below the
     bound, which is all of the ones counted above. */
  core->release_fn( core->release_ctx, rec->bank_idx, core->seq_bound );
}

/* geyser_ref_try_give_back releases the record's references once no
   consumer claims the bank.  Nothing in the core itself needs a bank
   after the callbacks of a notification have returned. */

static void
geyser_ref_try_give_back( fd_geyser_core_t * core,
                          geyser_bank_t *    rec ) {
  if( FD_UNLIKELY( rec->claim_cnt ) ) return;
  geyser_ref_give_back( core, rec );
}

static void
geyser_ref_acquired( fd_geyser_core_t * core,
                     geyser_bank_t *    rec ) {
  rec->ref_cnt++;
  core->ref_held++;
  core->metrics.ref_acquired_cnt++;
}

/* Seal ***************************************************************/

static void
geyser_seal( fd_geyser_core_t * core,
             geyser_bank_t *    rec ) {
  int  complete = 0;
  int  reason   = FD_GEYSER_INCOMPLETE_NONE;

  if     ( FD_UNLIKELY( rec->dropped )              ) reason = FD_GEYSER_INCOMPLETE_DROPPED;
  else if( FD_UNLIKELY( rec->gapped )               ) reason = FD_GEYSER_INCOMPLETE_GAP;
  else if( FD_UNLIKELY( !rec->created || !rec->completed ) ) reason = FD_GEYSER_INCOMPLETE_PENDING;
  else if( !core->records_gate                      ) complete = 1;
  else if( FD_UNLIKELY( rec->txn_records_seen!=rec->executed_txn_cnt ) ) reason = FD_GEYSER_INCOMPLETE_RECORDS;
  else if( FD_UNLIKELY( rec->acct_records_seen!=rec->acct_records_owed ) ) reason = FD_GEYSER_INCOMPLETE_RECORDS;
  else if( FD_UNLIKELY( rec->sysvar_mask!=0xFU )    ) reason = FD_GEYSER_INCOMPLETE_SYSVARS;
  else                                                complete = 1;

  if( FD_UNLIKELY( !complete && rec->incomplete_reason!=reason ) ) core->metrics.bank_incomplete_cnt[ reason ]++;

  rec->complete           = !!complete;
  rec->incomplete_reason  = reason;
}

/* geyser_notify_sealed reports a bank that has just sealed, once.  It
   runs after the bank's block summary and processed status have gone
   out, so that a consumer building the block of a bank has everything
   the bank is described by. */

static void
geyser_notify_sealed( fd_geyser_core_t * core,
                      geyser_bank_t *    rec ) {
  if( FD_LIKELY( !rec->complete || rec->sent_sealed ) ) return;
  rec->sent_sealed = 1;
  geyser_emit_sealed( core, rec->bank_seq );
}

/* Deferred statuses **************************************************/

/* A bank's records and the notifications that advance its commitment
   travel on different links, so a record link that lags by one
   iteration can leave a bank unsealed at the moment it is confirmed or
   rooted.  The status is then owed rather than dropped: it is emitted
   the moment the bank seals, which is what lets the consumer serve the
   block at that level.

   A bank is served the moment it seals, whatever the banks around it
   are waiting for, which is what an unsealed bank costs anywhere else
   in the core: only its own levels.  Among the banks that seal
   together the older slot goes first. */

static void
geyser_pending_mark( fd_geyser_core_t * core,
                     geyser_bank_t *    rec,
                     int                confirmed,
                     int                finalized ) {
  int was = rec->pending_confirmed || rec->pending_finalized;

  if( confirmed && !rec->pending_confirmed ) {
    rec->pending_confirmed = 1;
    rec->confirm_order     = core->confirm_seq++;
  }
  if( finalized && !rec->pending_finalized ) {
    rec->pending_finalized = 1;
    rec->finalize_order    = core->finalize_seq++;
  }

  if( FD_LIKELY( !was ) ) {
    core->pending_cnt++;
    core->metrics.bank_pending_cnt++;
  }
}

/* geyser_pending_settled is called once a bank owes nothing any
   more. */

static void
geyser_pending_settled( fd_geyser_core_t * core,
                        geyser_bank_t *    rec ) {
  if( FD_LIKELY( !rec->pending_confirmed && !rec->pending_finalized ) ) core->pending_cnt--;
}

/* geyser_emit_owed emits the statuses a bank owes without waiting for
   it to seal, which is what a bank that never will gets: consensus
   reached the level whether or not the records did, so every consumer
   sees the same slots reach it, and one that wanted the content finds
   the bank incomplete. */

static void
geyser_emit_owed( fd_geyser_core_t * core,
                  geyser_bank_t *    rec ) {
  if( FD_LIKELY( !rec->pending_confirmed && !rec->pending_finalized ) ) return;

  if( rec->pending_confirmed ) {
    rec->pending_confirmed = 0;
    if( FD_LIKELY( !rec->sent_confirmed ) ) {
      rec->sent_confirmed = 1;
      geyser_emit_status( core, rec->slot, rec->parent_slot, (int)rec->has_parent,
                          FD_GEYSER_SLOT_CONFIRMED, rec->bank_seq, 1, NULL );
    }
  }
  if( rec->pending_finalized ) {
    rec->pending_finalized = 0;
    if( core->alpenglow && !rec->sent_confirmed ) {
      rec->confirmed      = 1;
      rec->sent_confirmed = 1;
      geyser_emit_status( core, rec->slot, rec->parent_slot, (int)rec->has_parent,
                          FD_GEYSER_SLOT_CONFIRMED, rec->bank_seq, 1, NULL );
    }
    if( FD_LIKELY( !rec->sent_finalized ) ) {
      rec->sent_finalized = 1;
      geyser_emit_status( core, rec->slot, rec->parent_slot, (int)rec->has_parent,
                          FD_GEYSER_SLOT_FINALIZED, rec->bank_seq, 1, NULL );
    }
  }
  geyser_pending_settled( core, rec );
}

/* Pool ***************************************************************/

static void
geyser_discard( fd_geyser_core_t * core,
                geyser_bank_t *    rec,
                int                reason ) {
  ulong bank_seq = rec->bank_seq;
  if( FD_UNLIKELY( bank_seq==GEYSER_BANK_SEQ_NULL ) ) return;

  /* A status the bank still owes goes out first: the level was
     reached, only the content is gone with the bank. */
  geyser_emit_owed( core, rec );

  /* Claims are void once the bank is gone, so the references go back
     whether or not a consumer still holds one. */
  rec->claim_cnt = 0UL;
  geyser_ref_give_back( core, rec );

  geyser_map_remove( core, bank_seq );
  fd_memset( rec, 0, sizeof(geyser_bank_t) );
  core->bank_cnt--;

  geyser_emit_discarded( core, bank_seq, reason );
}

/* geyser_pending_ready returns the sealed bank with the lowest slot
   that still owes a status of the given level, or NULL if none has
   sealed.  A bank that has not sealed waits for its own records only:
   an unsealed bank costs itself its levels and nothing else, which is
   what an incomplete bank costs anywhere else in the core. */

static geyser_bank_t *
geyser_pending_ready( fd_geyser_core_t * core,
                      int                finalized ) {
  geyser_bank_t * best = NULL;
  for( ulong i=0UL; i<core->bank_max; i++ ) {
    geyser_bank_t * rec = core->bank + i;
    if( rec->bank_seq==GEYSER_BANK_SEQ_NULL ) continue;
    if( !( finalized ? rec->pending_finalized : rec->pending_confirmed ) ) continue;

    geyser_seal( core, rec );
    if( FD_UNLIKELY( !rec->complete ) ) continue;

    /* Among the banks that are ready together, the older slot goes
       first, and two banks of one slot go in the order the
       notifications named them. */
    if( !best || rec->slot<best->slot ||
        ( rec->slot==best->slot &&
          ( finalized ? rec->finalize_order<best->finalize_order
                      : rec->confirm_order <best->confirm_order  ) ) ) best = rec;
  }
  return best;
}

/* geyser_pending_hopeless gives up on the banks that owe a status and
   can no longer seal, rather than making a consumer wait out the bound
   for them: the statuses go out now, and the bank stays in the graph
   until the root passes it, so that it is rooted in its turn.  Its
   references are already back with replay. */

static void
geyser_pending_hopeless( fd_geyser_core_t * core ) {
  for( ulong i=0UL; i<core->bank_max; i++ ) {
    geyser_bank_t * rec = core->bank + i;
    if( rec->bank_seq==GEYSER_BANK_SEQ_NULL ) continue;
    if( !rec->pending_confirmed && !rec->pending_finalized ) continue;
    if( FD_LIKELY( !rec->dropped && !rec->gapped ) ) continue;

    core->metrics.pending_dropped_cnt++;
    geyser_emit_owed( core, rec );
  }
}

/* geyser_pending_flush emits the statuses the core owes, for every
   bank that has sealed. */

static void
geyser_pending_flush( fd_geyser_core_t * core ) {
  if( FD_LIKELY( !core->pending_cnt ) ) return;

  geyser_pending_hopeless( core );

  for( int finalized=0; finalized<2; finalized++ ) {
    for(;;) {
      geyser_bank_t * rec = geyser_pending_ready( core, finalized );
      if( FD_LIKELY( !rec ) ) break;

      geyser_notify_sealed( core, rec );

      if( !finalized ) {
        rec->pending_confirmed = 0;
        geyser_pending_settled( core, rec );
        if( FD_LIKELY( !rec->sent_confirmed ) ) {
          rec->sent_confirmed = 1;
          geyser_emit_status( core, rec->slot, rec->parent_slot, (int)rec->has_parent,
                              FD_GEYSER_SLOT_CONFIRMED, rec->bank_seq, 1, NULL );
        }
        continue;
      }

      rec->pending_finalized = 0;
      geyser_pending_settled( core, rec );

      /* Under alpenglow a newly rooted bank is reported confirmed
         first, as it is when it seals in time. */
      if( core->alpenglow && !rec->sent_confirmed ) {
        rec->confirmed      = 1;
        rec->sent_confirmed = 1;
        geyser_emit_status( core, rec->slot, rec->parent_slot, (int)rec->has_parent,
                            FD_GEYSER_SLOT_CONFIRMED, rec->bank_seq, 1, NULL );
      }
      if( FD_LIKELY( !rec->sent_finalized ) ) {
        rec->sent_finalized = 1;
        geyser_emit_status( core, rec->slot, rec->parent_slot, (int)rec->has_parent,
                            FD_GEYSER_SLOT_FINALIZED, rec->bank_seq, 1, NULL );
      }
    }
  }
}

/* geyser_pending_sweep gives up on the banks that have owed a status
   for longer than the root took to move FD_GEYSER_PENDING_MAX_SLOTS
   slots past them.  Their records were lost, so the statuses go out
   without the content. */

static void
geyser_pending_sweep( fd_geyser_core_t * core ) {
  if( FD_LIKELY( !core->pending_cnt ) ) return;
  if( FD_UNLIKELY( core->root_slot==ULONG_MAX ) ) return;
  if( FD_UNLIKELY( core->root_slot<FD_GEYSER_PENDING_MAX_SLOTS ) ) return;

  ulong keep_from = core->root_slot - FD_GEYSER_PENDING_MAX_SLOTS;
  for( ulong i=0UL; i<core->bank_max; i++ ) {
    geyser_bank_t * rec = core->bank + i;
    if( rec->bank_seq==GEYSER_BANK_SEQ_NULL ) continue;
    if( !rec->pending_confirmed && !rec->pending_finalized ) continue;
    if( rec->slot>=keep_from ) continue;

    core->metrics.pending_timeout_cnt++;
    FD_DRAGON_WARN_POW2( core->metrics.pending_timeout_cnt,
                         "dragon giving up on slot %lu (bank_id %lu): its records never arrived",
                         rec->slot, rec->bank_seq );
    geyser_emit_owed( core, rec );
  }
}

/* geyser_evict frees the record of the lowest slot that is not the
   root, so that a new bank always has a place. */

static void
geyser_evict( fd_geyser_core_t * core ) {
  geyser_bank_t * victim = NULL;
  for( ulong i=0UL; i<core->bank_max; i++ ) {
    geyser_bank_t * rec = core->bank + i;
    if( rec->bank_seq==GEYSER_BANK_SEQ_NULL ) continue;
    if( rec->bank_seq==core->root_bank_seq  ) continue;
    if( !victim || rec->slot<victim->slot || ( rec->slot==victim->slot && rec->order<victim->order ) ) victim = rec;
  }
  if( FD_UNLIKELY( !victim ) ) return;
  core->metrics.pool_full_cnt++;
  FD_DRAGON_WARN_POW2( core->metrics.pool_full_cnt,
                       "dragon fork graph full, dropping bank (slot=%lu bank_id=%lu)",
                       victim->slot, victim->bank_seq );
  geyser_discard( core, victim, FD_GEYSER_DISCARD_STALE );
}

static geyser_bank_t *
geyser_acquire( fd_geyser_core_t * core,
                ulong              bank_seq ) {
  if( FD_UNLIKELY( core->bank_cnt>=core->bank_max ) ) geyser_evict( core );
  geyser_map_compact( core );

  for( int attempt=0; attempt<2; attempt++ ) {
    for( ulong i=0UL; i<core->bank_max; i++ ) {
      geyser_bank_t * rec = core->bank + i;
      if( rec->bank_seq!=GEYSER_BANK_SEQ_NULL ) continue;

      if( FD_UNLIKELY( geyser_map_insert( core, bank_seq, i ) ) ) {
        /* The probe sequence from this bank's home slot is full.
           Dropping the graph empties the index, and the retry below
           indexes the bank at its home slot. */
        FD_DRAGON_WARN_POW2( core->metrics.map_full_cnt+1UL,
                             "dragon cannot index bank_id %lu, dropping the fork graph", bank_seq );
        geyser_flush( core, FD_GEYSER_DISCARD_FLUSH );
        break;
      }

      fd_memset( rec, 0, sizeof(geyser_bank_t) );
      rec->bank_seq = bank_seq;
      rec->order    = core->order_next++;
      core->bank_cnt++;
      core->metrics.bank_created_cnt++;
      return rec;
    }
  }
  return NULL;
}

static void
geyser_flush( fd_geyser_core_t * core,
              int                reason ) {
  for( ulong i=0UL; i<core->bank_max; i++ ) {
    geyser_bank_t * rec = core->bank + i;
    if( rec->bank_seq==GEYSER_BANK_SEQ_NULL ) continue;
    geyser_discard( core, rec, reason );
  }
  /* The pool is empty, so the index is empty too. */
  fd_memset( core->map, 0, core->map_sz*sizeof(ulong) );
  core->grave_cnt     = 0UL;
  core->root_bank_seq = ULONG_MAX;
  core->root_slot     = ULONG_MAX;
  core->metrics.flush_cnt++;
}

/* geyser_discard_losers drops the other banks of a slot once one of
   them is confirmed or rooted.  At most two banks share a slot
   (fd_replay_tile.h), so this is the equivocation case. */

static void
geyser_discard_losers( fd_geyser_core_t * core,
                       ulong              slot,
                       ulong              winner_bank_seq ) {
  for( ulong i=0UL; i<core->bank_max; i++ ) {
    geyser_bank_t * rec = core->bank + i;
    if( rec->bank_seq==GEYSER_BANK_SEQ_NULL ) continue;
    if( rec->slot!=slot || rec->bank_seq==winner_bank_seq ) continue;
    geyser_discard( core, rec, FD_GEYSER_DISCARD_LOSER );
  }
}

/* geyser_descends_from_root returns 1 if the record is the root or
   descends from it.  A record whose ancestry runs out above the root's
   slot is kept: the core may simply never have seen the bank that
   links it, and a bank newer than the root is not on a pruned fork
   just because of that. */

static int
geyser_descends_from_root( fd_geyser_core_t * core,
                           geyser_bank_t *    rec ) {
  geyser_bank_t * cur = rec;
  for( ulong step=0UL; step<core->bank_max; step++ ) {
    if( cur->bank_seq==core->root_bank_seq ) return 1;
    if( cur->slot<=core->root_slot         ) return 0;
    if( cur->parent_bank_seq==ULONG_MAX    ) return 1;
    geyser_bank_t * parent = geyser_query( core, cur->parent_bank_seq );
    if( !parent ) return 1;
    cur = parent;
  }
  return 0;
}

/* geyser_prune drops every bank that does not descend from the root.
   The verdicts are taken before anything is dropped, because the
   ancestry of one bank runs through others. */

static void
geyser_prune( fd_geyser_core_t * core ) {
  for( ulong i=0UL; i<core->bank_max; i++ ) {
    geyser_bank_t * rec = core->bank + i;
    if( rec->bank_seq==GEYSER_BANK_SEQ_NULL ) continue;
    rec->pruned = !geyser_descends_from_root( core, rec );
  }

  for( ulong i=0UL; i<core->bank_max; i++ ) {
    geyser_bank_t * rec = core->bank + i;
    if( rec->bank_seq==GEYSER_BANK_SEQ_NULL ) continue;
    if( !rec->pruned                        ) continue;
    /* A bank the root passed over that still owes its finalized status
       is kept until it seals or is given up on, which is what makes a
       late record still reach the consumer. */
    if( FD_UNLIKELY( rec->pending_finalized ) ) continue;
    geyser_discard( core, rec, FD_GEYSER_DISCARD_PRUNED );
  }
}

/* Notifications ******************************************************/

void
fd_geyser_core_slot_completed( fd_geyser_core_t *                 core,
                               fd_replay_slot_completed_t const * msg,
                               ulong                              frag_seq ) {
  ulong bank_seq = msg->bank_seq;
  ulong bank_idx = msg->bank_idx;

  core->seq_bound = frag_seq+1UL;

  if( FD_UNLIKELY( bank_seq==GEYSER_BANK_SEQ_NULL || bank_seq==GEYSER_BANK_SEQ_GRAVE ||
                   bank_idx>=core->max_live_banks ) ) {
    core->metrics.unknown_bank_cnt++;
    FD_DRAGON_WARN_POW2( core->metrics.unknown_bank_cnt,
                         "dragon ignoring slot %lu with bank_id %lu bank_idx %lu",
                         msg->slot, bank_seq, bank_idx );
    return;
  }

  /* A bank sequence far below everything seen means replay restarted
     its bank pool, so nothing in the graph refers to a live bank any
     more.  Forks complete out of order, so only a gap wider than the
     whole bank pool can be a restart. */
  if( FD_UNLIKELY( bank_seq+core->max_live_banks < core->bank_seq_hi ) ) {
    FD_DRAGON_WARN_POW2( core->metrics.flush_cnt+1UL,
                         "dragon flushing its fork graph: bank_id %lu is far behind %lu",
                         bank_seq, core->bank_seq_hi );
    geyser_flush( core, FD_GEYSER_DISCARD_FLUSH );
    core->bank_seq_hi = 0UL;
    core->slot_hi     = 0UL;
  }

  geyser_bank_t * rec = geyser_query( core, bank_seq );
  if( FD_UNLIKELY( rec && rec->completed ) ) {
    /* The same bank was published twice, so replay granted another
       reference for it. */
    geyser_ref_acquired( core, rec );
    geyser_ref_try_give_back( core, rec );
    return;
  }

  /* The bank may already be in the graph because its records arrived
     before it froze; then this notification fills in everything the
     records could not name. */
  if( FD_LIKELY( !rec ) ) rec = geyser_acquire( core, bank_seq );
  if( FD_UNLIKELY( !rec ) ) {
    /* geyser_evict always frees a record unless the graph holds
       nothing but the root, which cannot happen with a pool twice the
       size of replay's. */
    core->metrics.ref_acquired_cnt++;
    core->metrics.ref_released_cnt++;
    core->release_fn( core->release_ctx, bank_idx, core->seq_bound );
    FD_DRAGON_WARN_POW2( core->metrics.pool_full_cnt+1UL,
                         "dragon has no room for slot %lu (bank_id %lu)", msg->slot, bank_seq );
    return;
  }

  geyser_bank_t * parent = msg->parent_bank_seq!=ULONG_MAX ? geyser_query( core, msg->parent_bank_seq ) : NULL;

  rec->bank_idx            = bank_idx;
  rec->accdb_fork_id       = msg->accdb_fork_id;
  rec->has_fork            = 1;
  rec->slot                = msg->slot;
  rec->parent_bank_seq     = msg->parent_bank_seq;
  rec->parent_slot         = msg->parent_slot;
  /* Every bank but genesis has a parent slot, whether or not the core
     saw the parent bank; parent_bank_seq is what links the graph. */
  rec->has_parent          = msg->slot!=0UL;
  rec->block_id            = msg->block_id;
  rec->block_hash          = msg->block_hash;
  rec->block_height        = msg->block_height;
  rec->parent_block_height = parent ? parent->block_height : ULONG_MAX;
  rec->txn_count_total     = msg->transaction_count;

  /* How many transactions the block executed, which is how many commit
     records the bank must produce.  Replay counts them per slot, and
     that is what the core uses: the cumulative count minus the parent's
     is the same number, but only for a parent the core has seen, which
     the first bank of a run has not. */
  if( FD_LIKELY( msg->vote_success!=ULONG_MAX && msg->vote_failed!=ULONG_MAX &&
                 msg->nonvote_success!=ULONG_MAX && msg->nonvote_failed!=ULONG_MAX ) ) {
    rec->executed_txn_cnt = msg->vote_success + msg->vote_failed + msg->nonvote_success + msg->nonvote_failed;
  } else {
    rec->executed_txn_cnt = parent ? msg->transaction_count - parent->txn_count_total : ULONG_MAX;
  }
  rec->created             = 1;
  rec->completed           = 1;

  core->bank_seq_hi = fd_ulong_max( core->bank_seq_hi, bank_seq  );
  core->slot_hi     = fd_ulong_max( core->slot_hi,     msg->slot );

  geyser_ref_acquired( core, rec );
  geyser_seal( core, rec );

  /* The bank comes into being and freezes in the same notification
     until the producer records exist, so the synthesized CreatedBank
     goes out first, then the block summary, then the processed status,
     which is the order a yellowstone client sees. */
  if( FD_LIKELY( !rec->sent_created ) ) {
    rec->sent_created = 1;
    geyser_emit_status( core, rec->slot, rec->parent_slot, (int)rec->has_parent,
                        FD_GEYSER_SLOT_CREATED_BANK, bank_seq, 1, NULL );
  }
  geyser_emit_block_meta( core, rec );
  rec->sent_processed = 1;
  geyser_emit_status( core, rec->slot, rec->parent_slot, (int)rec->has_parent,
                      FD_GEYSER_SLOT_PROCESSED, bank_seq, 1, NULL );

  /* Everything that describes the bank has gone out, so a bank that
     sealed here is reported sealed, and the statuses the core owes for
     any bank go out behind it. */
  geyser_notify_sealed( core, rec );
  geyser_pending_flush( core );

  geyser_ref_try_give_back( core, rec );
}

void
fd_geyser_core_slot_dead( fd_geyser_core_t *            core,
                          fd_replay_slot_dead_t const * msg,
                          ulong                         frag_seq ) {
  ulong slot = msg->slot;

  core->seq_bound = frag_seq+1UL;

  for( ulong i=0UL; i<core->bank_max; i++ ) {
    geyser_bank_t * rec = core->bank + i;
    if( rec->bank_seq==GEYSER_BANK_SEQ_NULL ) continue;
    if( rec->slot!=slot ) continue;
    geyser_discard( core, rec, FD_GEYSER_DISCARD_DEAD );
  }

  core->slot_hi = fd_ulong_max( core->slot_hi, slot );

  /* A dead slot belongs to no bank, so the status carries no bank id
     and no parent. */
  geyser_emit_status( core, slot, 0UL, 0, FD_GEYSER_SLOT_DEAD, 0UL, 0, NULL );
}

void
fd_geyser_core_oc_advanced( fd_geyser_core_t *              core,
                            fd_replay_oc_advanced_t const * msg,
                            ulong                           frag_seq ) {
  core->seq_bound = frag_seq+1UL;

  geyser_bank_t * rec = geyser_query( core, msg->bank_seq );
  if( FD_UNLIKELY( !rec ) ) {
    core->metrics.unknown_bank_cnt++;
    return;
  }
  if( FD_UNLIKELY( rec->confirmed ) ) return;

  rec->confirmed = 1;
  geyser_discard_losers( core, rec->slot, msg->bank_seq );

  geyser_seal( core, rec );
  geyser_notify_sealed( core, rec );
  if( FD_LIKELY( rec->complete ) ) {
    if( FD_LIKELY( !rec->sent_confirmed ) ) {
      rec->sent_confirmed = 1;
      geyser_emit_status( core, rec->slot, rec->parent_slot, (int)rec->has_parent,
                          FD_GEYSER_SLOT_CONFIRMED, rec->bank_seq, 1, NULL );
    }
  } else if( FD_UNLIKELY( !rec->sent_confirmed ) ) {
    /* The records of the block have not all arrived, so the status is
       owed until they do. */
    geyser_pending_mark( core, rec, 1, 0 );
  }

  geyser_ref_try_give_back( core, rec );
  geyser_pending_flush( core );
}

void
fd_geyser_core_root_advanced( fd_geyser_core_t *                core,
                              fd_replay_root_advanced_t const * msg,
                              ulong                             frag_seq ) {
  ulong bank_seq = msg->bank_seq;
  ulong bank_idx = msg->bank_idx;

  core->seq_bound = frag_seq+1UL;

  if( FD_UNLIKELY( bank_idx>=core->max_live_banks ) ) {
    /* Replay granted a reference for an index that is not in its
       pool, which the core cannot give back by name. */
    core->metrics.unknown_bank_cnt++;
    FD_DRAGON_WARN_POW2( core->metrics.unknown_bank_cnt,
                         "dragon ignoring root slot %lu with bank_id %lu bank_idx %lu",
                         msg->slot, bank_seq, bank_idx );
    return;
  }

  geyser_bank_t * rec = geyser_query( core, bank_seq );
  if( FD_UNLIKELY( !rec ) ) {
    /* The core never saw the bank, so the reference replay granted for
       the new root goes straight back.  Banks at or below the root's
       slot cannot be on the rooted fork's future, so they go.  Before
       the first root this is the history that predates the core;
       after it, it is a root the core cannot report, which every
       finalized stream then misses. */
    core->metrics.unknown_bank_cnt++;
    if( FD_UNLIKELY( core->root_bank_seq!=ULONG_MAX ) ) {
      core->metrics.root_chain_broken_cnt++;
      FD_DRAGON_WARN_POW2( core->metrics.root_chain_broken_cnt,
                           "dragon root slot %lu (bank_id %lu) is not in the fork graph: "
                           "no finalized status for it or the banks it prunes",
                           msg->slot, bank_seq );
    }
    if( FD_LIKELY( bank_idx<core->max_live_banks ) ) {
      core->metrics.ref_acquired_cnt++;
      core->metrics.ref_released_cnt++;
      core->release_fn( core->release_ctx, bank_idx, core->seq_bound );
    }
    core->root_bank_seq = ULONG_MAX;
    core->root_slot     = msg->slot;
    for( ulong i=0UL; i<core->bank_max; i++ ) {
      geyser_bank_t * other = core->bank + i;
      if( other->bank_seq==GEYSER_BANK_SEQ_NULL ) continue;
      if( other->slot>msg->slot ) continue;
      geyser_discard( core, other, FD_GEYSER_DISCARD_PRUNED );
    }
    return;
  }

  /* A bank that the records created before replay named it learns its
     pool index here, which is what a release has to carry. */
  if( FD_UNLIKELY( rec->bank_idx>=core->max_live_banks ) ) rec->bank_idx = bank_idx;

  geyser_ref_acquired( core, rec );

  /* Collect the banks the root passed over, newest first, then report
     them oldest first: a client sees rooted slots ascend.  A record's
     address is stable until that record is discarded, and the only
     discards here are of losers, whose slots are not in the chain.

     Once the core has a root, every later root descends from it, so
     the walk ends at a rooted bank; a walk that ends anywhere else,
     or runs past the bound, has lost part of the chain, and the banks
     it did not reach are pruned without a finalized status. */
  ulong           chain_cnt = 0UL;
  geyser_bank_t * chain[ FD_GEYSER_ROOT_CHAIN_MAX ];
  geyser_bank_t * cur       = rec;
  int             broken    = 0;
  for(;;) {
    if( cur->rooted ) break;
    if( FD_UNLIKELY( chain_cnt>=FD_GEYSER_ROOT_CHAIN_MAX ) ) { broken = 1; break; }
    chain[ chain_cnt++ ] = cur;
    geyser_bank_t * parent = cur->parent_bank_seq!=ULONG_MAX ? geyser_query( core, cur->parent_bank_seq ) : NULL;
    if( !parent ) { broken = core->root_bank_seq!=ULONG_MAX; break; }
    cur = parent;
  }
  if( FD_UNLIKELY( broken ) ) {
    core->metrics.root_chain_broken_cnt++;
    FD_DRAGON_WARN_POW2( core->metrics.root_chain_broken_cnt,
                         "dragon root chain from slot %lu (bank_id %lu) does not reach the previous root "
                         "(slot %lu): %lu banks rooted, the rest pruned without a finalized status",
                         rec->slot, bank_seq, core->root_slot, chain_cnt );
  }

  for( ulong i=chain_cnt; i>0UL; i-- ) {
    geyser_bank_t * anc = chain[ i-1UL ];

    anc->rooted = 1;
    geyser_discard_losers( core, anc->slot, anc->bank_seq );

    geyser_seal( core, anc );
    geyser_notify_sealed( core, anc );
    if( FD_UNLIKELY( !anc->complete ) ) {
      /* The block's records have not all arrived.  The status is owed
         until they do, and the bank holds no reference while it waits:
         replay gets everything back at root time whether or not the
         core has served the bank.  A bank whose records are gone for
         good is reported here, in its turn, so rooted slots still
         ascend. */
      geyser_pending_mark( core, anc, 0, 1 );
      if( FD_UNLIKELY( anc->dropped || anc->gapped ) ) {
        core->metrics.pending_dropped_cnt++;
        geyser_emit_owed( core, anc );
      }
      geyser_ref_give_back( core, anc );
      continue;
    }

    /* Under alpenglow no optimistic confirmation notification exists,
       so a newly rooted bank is reported confirmed first.  This is
       what agave's votor does when it sets the root. */
    if( core->alpenglow && !anc->sent_confirmed ) {
      anc->confirmed      = 1;
      anc->sent_confirmed = 1;
      geyser_emit_status( core, anc->slot, anc->parent_slot, (int)anc->has_parent,
                          FD_GEYSER_SLOT_CONFIRMED, anc->bank_seq, 1, NULL );
    }

    if( FD_LIKELY( !anc->sent_finalized ) ) {
      anc->sent_finalized = 1;
      geyser_emit_status( core, anc->slot, anc->parent_slot, (int)anc->has_parent,
                          FD_GEYSER_SLOT_FINALIZED, anc->bank_seq, 1, NULL );
    }
  }

  core->root_bank_seq = bank_seq;
  core->root_slot     = rec->slot;
  core->slot_hi       = fd_ulong_max( core->slot_hi, rec->slot );

  geyser_prune( core );
  geyser_ref_try_give_back( core, rec );

  geyser_pending_sweep( core );
  geyser_pending_flush( core );
}

void
fd_geyser_core_drop_bank_ref( fd_geyser_core_t * core,
                              ulong              bank_idx,
                              ulong              frag_seq ) {
  core->seq_bound = frag_seq+1UL;

  for( ulong i=0UL; i<core->bank_max; i++ ) {
    geyser_bank_t * rec = core->bank + i;
    if( rec->bank_seq==GEYSER_BANK_SEQ_NULL ) continue;
    if( rec->bank_idx!=bank_idx ) continue;

    /* Replay is waiting on this reference to make progress, so it goes
       back now whatever a consumer thinks it holds.  A bank whose
       references already went back sends nothing: the request may
       belong to an older bank at this index, whose successor replay
       has already granted a reference for.  The bank stays in the
       graph, marked incomplete, so that nothing is delivered for it at
       confirmed or finalized. */
    rec->dropped   = 1;
    rec->claim_cnt = 0UL;
    geyser_ref_give_back( core, rec );
    geyser_seal( core, rec );
    geyser_emit_discarded( core, rec->bank_seq, FD_GEYSER_DISCARD_DROPPED );
  }

  geyser_pending_flush( core );
}

/* Records ***********************************************************/

/* geyser_write_version orders the account writes of one slot the way
   agave's write versions do: first the phase the write belongs to
   (before, during or after the block's transactions), then its
   position within the phase, then its position within its record.

   The producer holds index and sub to the widths this packing gives
   them (fd_event_internal.h), so the saturation here only ever bites
   on a record that arrived malformed, where ordering the write last
   within its phase beats wrapping it in front of everything. */

static ulong
geyser_write_version( ulong phase,
                      ulong index,
                      ulong sub ) {
  index = fd_ulong_min( index, FD_EVENT_INTERNAL_WRITE_INDEX_MAX );
  sub   = fd_ulong_min( sub,   FD_EVENT_INTERNAL_WRITE_SUB_MAX   );
  return (phase<<60) | (index<<8) | sub;
}

/* geyser_record_bank finds the bank a record belongs to, creating it if
   the record is the first thing the core hears about that bank.  A bank
   created here has no parent and no block identity until it freezes,
   which is what the synthesized CreatedBank status reports; yellowstone
   tolerates data before the bank it belongs to is described
   (block_reconstruction_v2.rs:80-90). */

static geyser_bank_t *
geyser_record_bank( fd_geyser_core_t * core,
                    ulong              bank_seq,
                    ulong              slot ) {
  if( FD_UNLIKELY( bank_seq==GEYSER_BANK_SEQ_NULL || bank_seq==GEYSER_BANK_SEQ_GRAVE ) ) return NULL;

  geyser_bank_t * rec = geyser_query( core, bank_seq );
  if( FD_LIKELY( rec ) ) return rec;

  /* A record naming a bank at or below the root belongs to one the core
     already gave up on, having rooted or pruned it.  Tracking it again
     would put a bank in the graph that can never seal. */
  if( FD_UNLIKELY( core->root_slot!=ULONG_MAX && slot<=core->root_slot ) ) return NULL;

  rec = geyser_acquire( core, bank_seq );
  if( FD_UNLIKELY( !rec ) ) return NULL;

  rec->bank_idx            = ULONG_MAX; /* replay names the pool index when the bank freezes */
  rec->slot                = slot;
  rec->parent_bank_seq     = ULONG_MAX;
  rec->parent_block_height = ULONG_MAX;
  rec->executed_txn_cnt    = ULONG_MAX;
  rec->created             = 1;

  core->bank_seq_hi = fd_ulong_max( core->bank_seq_hi, bank_seq );
  core->slot_hi     = fd_ulong_max( core->slot_hi,     slot     );

  rec->sent_created = 1;
  geyser_emit_status( core, slot, 0UL, 0, FD_GEYSER_SLOT_CREATED_BANK, bank_seq, 1, NULL );
  return rec;
}

/* geyser_commit_valid checks that every count, index and offset of a
   commit record addresses the record itself.  The frame the record
   arrived in was validated by the ingest side; this is about the
   fields. */

static int
geyser_commit_valid( fd_event_internal_commit_parts_t const * parts ) {
  fd_event_internal_commit_t const * msg = parts->prefix;

  if( FD_UNLIKELY( !msg->keys_cnt ) ) return 0;
  if( FD_UNLIKELY( msg->pre_lamports_cnt!=msg->keys_cnt ||
                   msg->post_lamports_cnt!=msg->keys_cnt ||
                   msg->is_writable_cnt!=msg->keys_cnt ) ) return 0;
  if( FD_UNLIKELY( (ulong)msg->acct_addr_cnt>msg->keys_cnt ) ) return 0;
  if( FD_UNLIKELY( (ulong)msg->adtl_writable_cnt>msg->keys_cnt-(ulong)msg->acct_addr_cnt ) ) return 0;

  for( ulong i=0UL; i<msg->trace_cnt; i++ ) {
    fd_event_internal_commit_trace_t const * t = parts->trace + i;
    if( FD_UNLIKELY( (ulong)t->program_id_idx>=msg->keys_cnt ) ) return 0;
    if( FD_UNLIKELY( (ulong)t->acct_cnt>msg->trace_accts_cnt ||
                     (ulong)t->acct_off>msg->trace_accts_cnt-(ulong)t->acct_cnt ) ) return 0;
    if( FD_UNLIKELY( (ulong)t->data_sz>msg->trace_data_cnt ||
                     (ulong)t->data_off>msg->trace_data_cnt-(ulong)t->data_sz ) ) return 0;
  }
  for( ulong i=0UL; i<msg->trace_accts_cnt; i++ ) {
    if( FD_UNLIKELY( (ulong)parts->trace_accts[ i ]>=msg->keys_cnt ) ) return 0;
  }
  for( ulong i=0UL; i<msg->touched_cnt; i++ ) {
    fd_event_internal_commit_touched_t const * t = parts->touched + i;
    if( FD_UNLIKELY( (ulong)t->key_idx>=msg->keys_cnt ) ) return 0;
  }
  return 1;
}

int
fd_geyser_core_commit_record( fd_geyser_core_t *                       core,
                              fd_event_internal_commit_parts_t const * parts ) {
  fd_event_internal_commit_t const * msg = parts->prefix;

  if( FD_UNLIKELY( !geyser_commit_valid( parts ) ) ) {
    core->metrics.record_dropped_cnt++;
    return -1;
  }

  geyser_bank_t * rec = geyser_record_bank( core, msg->bank_seq, msg->slot );

  /* A record of a bank whose reference replay took back, or of one the
     core has no room for, changes nothing: the bank is already
     incomplete and nothing will be delivered for it. */
  if( FD_UNLIKELY( !rec || rec->dropped ) ) {
    core->metrics.record_dropped_cnt++;
    return -1;
  }

  rec->txn_records_seen++;
  core->metrics.txn_record_cnt++;

  /* Each account the record names arrives as an account record of its
     own, behind this one on the same link. */
  if( FD_LIKELY( msg->accounts_included ) ) rec->acct_records_owed += msg->touched_cnt;

  fd_geyser_txn_t txn = {
    .slot          = rec->slot,
    .bank_id       = rec->bank_seq,
    .index_in_slot = msg->index_in_slot,
    .signature     = msg->signature,
    .is_vote       = !!msg->is_simple_vote,
    .rec           = parts
  };
  core->meta_rec   = parts;
  core->meta_valid = 0;
  geyser_emit_txn( core, &txn );
  core->meta_rec   = NULL;


  geyser_seal( core, rec );
  geyser_notify_sealed( core, rec );
  geyser_pending_flush( core );
  return 0;
}

/* geyser_sysvar_bit returns which of the sysvars the seal waits for a
   pubkey is, or 0 for any other account. */

static uint
geyser_sysvar_bit( uchar const * pubkey ) {
  if( !memcmp( pubkey, fd_sysvar_clock_id.uc,                32UL ) ) return FD_GEYSER_SYSVAR_CLOCK;
  if( !memcmp( pubkey, fd_sysvar_slot_hashes_id.uc,          32UL ) ) return FD_GEYSER_SYSVAR_SLOT_HASHES;
  if( !memcmp( pubkey, fd_sysvar_slot_history_id.uc,         32UL ) ) return FD_GEYSER_SYSVAR_SLOT_HISTORY;
  if( !memcmp( pubkey, fd_sysvar_recent_block_hashes_id.uc,  32UL ) ) return FD_GEYSER_SYSVAR_RECENT_BLOCKHASHES;
  return 0U;
}

int
fd_geyser_core_runtime_write_record( fd_geyser_core_t *                              core,
                                     fd_event_internal_runtime_write_parts_t const * parts ) {
  fd_event_internal_runtime_write_t const * msg = parts->prefix;

  if( FD_UNLIKELY( !msg->keys_cnt || msg->phase>2U ) ) {
    core->metrics.record_dropped_cnt++;
    return -1;
  }
  int txn_write = msg->phase==1U;
  if( FD_UNLIKELY( txn_write && msg->touched_cnt!=1UL ) ) {
    core->metrics.record_dropped_cnt++;
    return -1;
  }
  for( ulong i=0UL; i<msg->touched_cnt; i++ ) {
    fd_event_internal_runtime_write_touched_t const * t = parts->touched + i;
    if( FD_UNLIKELY( (ulong)t->key_idx>=msg->keys_cnt ||
                     t->data_sz>msg->account_data_cnt ||
                     t->data_off>msg->account_data_cnt-t->data_sz ) ) {
      core->metrics.record_dropped_cnt++;
      return -1;
    }
  }

  geyser_bank_t * rec = geyser_record_bank( core, msg->bank_seq, msg->slot );
  if( FD_UNLIKELY( !rec || rec->dropped ) ) {
    core->metrics.record_dropped_cnt++;
    return -1;
  }

  if( txn_write ) {
    rec->acct_records_seen++;
  } else {
    core->metrics.write_record_cnt++;
    for( ulong i=0UL; i<msg->keys_cnt; i++ ) rec->sysvar_mask |= geyser_sysvar_bit( parts->keys[ i ] );
  }

  for( ulong i=0UL; i<msg->touched_cnt; i++ ) {
    fd_event_internal_runtime_write_touched_t const * t = parts->touched + i;
    fd_geyser_account_t acct = {
      .slot          = rec->slot,
      .bank_id       = rec->bank_seq,
      .pubkey        = parts->keys[ t->key_idx ],
      .owner         = t->owner,
      .lamports      = t->lamports,
      .executable    = !!t->executable,
      .data          = ( msg->accounts_included && t->data_sz ) ? parts->account_data+t->data_off : NULL,
      .data_sz       = msg->accounts_included ? t->data_sz : 0UL,
      .data_missing  = !msg->accounts_included,
      .write_version = txn_write ? geyser_write_version( 1UL, msg->commit_index_in_slot, msg->touched_idx )
                                 : geyser_write_version( (ulong)msg->phase, msg->write_seq, i ),
      .txn_signature = txn_write ? msg->signature : NULL
    };
    geyser_emit_account( core, &acct );
  }

  geyser_seal( core, rec );
  geyser_notify_sealed( core, rec );
  geyser_pending_flush( core );
  return 0;
}

void
fd_geyser_core_txn_event( fd_geyser_core_t *             core,
                          fd_event_runtime_txn_t const * ev ) {
  (void)ev;
  core->metrics.txn_event_cnt++;
}

void
fd_geyser_core_record_gap( fd_geyser_core_t * core ) {
  core->metrics.record_gap_cnt++;

  /* Marking the banks in flight is enough: a bank that already froze
     knows how many records it must see, so one lost on its way leaves
     its count short and the seal refuses it anyway.  A bank that has
     not frozen has no count to compare against yet, so it is the one
     that needs telling. */
  for( ulong i=0UL; i<core->bank_max; i++ ) {
    geyser_bank_t * rec = core->bank + i;
    if( rec->bank_seq==GEYSER_BANK_SEQ_NULL ) continue;
    if( rec->completed                      ) continue;
    rec->gapped = 1;
    geyser_seal( core, rec );
  }

  /* A bank that lost records will never seal, so the levels it was
     holding back move on. */
  geyser_pending_flush( core );
}

void
fd_geyser_core_link_gap( fd_geyser_core_t * core,
                         ulong              seq_bound ) {
  core->seq_bound = seq_bound;

  geyser_flush( core, FD_GEYSER_DISCARD_FLUSH );

  /* The core cannot know which grants it missed, so it releases every
     bank index replay could have granted one for.  Replay drops all of
     a bank's dragon references on one release, so a release for a bank
     the core holds nothing for changes nothing. */
  for( ulong bank_idx=0UL; bank_idx<core->max_live_banks; bank_idx++ ) {
    core->release_fn( core->release_ctx, bank_idx, seq_bound );
  }

  core->bank_seq_hi = 0UL;
}

void
fd_geyser_core_housekeeping( fd_geyser_core_t * core ) {
  geyser_map_compact( core );

  geyser_pending_sweep( core );
  geyser_pending_flush( core );

  if( FD_UNLIKELY( core->slot_hi<core->stale_slots ) ) return;
  ulong keep_from = core->slot_hi - core->stale_slots;

  for( ulong i=0UL; i<core->bank_max; i++ ) {
    geyser_bank_t * rec = core->bank + i;
    if( rec->bank_seq==GEYSER_BANK_SEQ_NULL ) continue;
    if( rec->bank_seq==core->root_bank_seq  ) continue;
    if( rec->slot>=keep_from                ) continue;
    geyser_discard( core, rec, FD_GEYSER_DISCARD_STALE );
  }
}

void
fd_geyser_core_end_of_startup( fd_geyser_core_t * core ) {
  if( FD_UNLIKELY( core->startup_done ) ) return;
  core->startup_done = 1;
  for( ulong i=0UL; i<core->consumer_cnt; i++ ) {
    fd_geyser_consumer_t const * c = core->consumer + i;
    if( c->on_end_of_startup ) c->on_end_of_startup( c->ctx );
  }
}

/* Extensions *********************************************************/

int
fd_geyser_bank_hold( fd_geyser_core_t * core,
                     ulong              bank_id ) {
  geyser_bank_t * rec = geyser_query( core, bank_id );
  if( FD_UNLIKELY( !rec || rec->dropped ) ) return -1;

  /* A claim is worth something only while the core still holds a
     reference replay granted, or before it has been granted one at
     all: the claim then keeps that reference.  A bank that froze and
     whose references are already back with replay may have been
     recycled, so there is nothing left to claim. */
  if( FD_UNLIKELY( rec->completed && !rec->ref_cnt ) ) return -1;

  rec->claim_cnt++;
  return 0;
}

void
fd_geyser_bank_release( fd_geyser_core_t * core,
                        ulong              bank_id ) {
  geyser_bank_t * rec = geyser_query( core, bank_id );
  if( FD_UNLIKELY( !rec || !rec->claim_cnt ) ) return;
  rec->claim_cnt--;
  geyser_ref_try_give_back( core, rec );
}

fd_txn_meta_t const *
fd_geyser_txn_meta( fd_geyser_core_t *      core,
                    fd_geyser_txn_t const * txn ) {
  if( FD_UNLIKELY( !core->meta_rec || core->meta_rec!=txn->rec ) ) return NULL;
  if( FD_LIKELY( core->meta_valid ) ) return core->meta_valid>0 ? core->meta : NULL;

  core->meta_valid = fd_txn_meta_from_commit( core->meta, core->meta_scratch, txn->rec ) ? -1 : 1;
  if( FD_UNLIKELY( core->meta_valid<0 ) ) {
    core->metrics.txn_meta_failed_cnt++;
    return NULL;
  }
  return core->meta;
}

int
fd_geyser_bank_is_complete( fd_geyser_core_t const * core,
                            ulong                    bank_id ) {
  geyser_bank_t * rec = geyser_query( (fd_geyser_core_t *)core, bank_id );
  return rec && rec->complete;
}

int
fd_geyser_read_account( fd_geyser_core_t *    core,
                        ulong                 bank_id,
                        uchar const *         pubkey,
                        fd_geyser_account_t * out ) {
  geyser_bank_t * rec = geyser_query( core, bank_id );
  if( FD_UNLIKELY( !core->read_fn || !rec || rec->dropped || !rec->has_fork || !rec->claim_cnt ) ) {
    core->metrics.acct_read_fail_cnt++;
    return -1;
  }

  fd_memset( out, 0, sizeof(fd_geyser_account_t) );
  if( FD_UNLIKELY( core->read_fn( core->read_ctx, rec->accdb_fork_id, pubkey, out ) ) ) {
    core->metrics.acct_read_fail_cnt++;
    return -1;
  }

  out->slot    = rec->slot;
  out->bank_id = rec->bank_seq;
  out->pubkey  = pubkey;

  core->metrics.acct_read_cnt++;
  if( FD_UNLIKELY( !out->lamports ) ) core->metrics.acct_read_closed_cnt++;
  return 0;
}

FD_FN_PURE ulong
fd_geyser_core_bank_slot( fd_geyser_core_t const * core,
                          ulong                    bank_id ) {
  geyser_bank_t * rec = geyser_query( (fd_geyser_core_t *)core, bank_id );
  return rec ? rec->slot : ULONG_MAX;
}

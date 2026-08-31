#include "utils/fd_ssctrl.h"
#include "utils/fd_ssload.h"
#include "utils/fd_ssmsg.h"
#include "utils/fd_ssparse.h"
#include "utils/fd_ssmanifest_parser.h"
#include "utils/fd_slot_delta_parser.h"
#include "utils/fd_snapin_io.h"
#include "../../util/fd_hash32.h"

#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/gui/fd_gui_config_parse.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/fd_hashes.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_slot_history.h"

#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/features/fd_feature_snoop.h"
#include "../../flamenco/stakes/fd_stake_types.h"
#include "../../disco/stem/fd_stem.h"
#include "../../flamenco/accdb/fd_accdb.h"
#include "../../disco/events/generated/fd_event_gen.h"

#include "generated/fd_snapin_tile_seccomp.h"

#include <errno.h>
#include <unistd.h>

#define NAME "snapin"

/* Batch disk records into one pwrite. */

#define FD_SNAPIN_WRITE_BUF_SZ (2UL<<20)

/* Warn every 10 seconds while data waits for tile 0. */

#define FD_SNAPIN_GATE_WARN_NS (10L*1000L*1000L*1000L)

/* 300 root slots in the slot deltas array, and each one references all
   151 prior blockhashes that it's able to. */
#define FD_SNAPIN_MAX_SLOT_DELTA_GROUPS (300UL*151UL)

struct fd_blockhash_entry {
  fd_hash_t blockhash;

  struct {
    ulong prev;
    ulong next;
  } map;
};

typedef struct fd_blockhash_entry fd_blockhash_entry_t;

#define MAP_NAME                           blockhash_map
#define MAP_KEY                            blockhash
#define MAP_KEY_T                          fd_hash_t
#define MAP_ELE_T                          fd_blockhash_entry_t
#define MAP_KEY_EQ(k0,k1)                  (!memcmp((k0),(k1), sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed)             (fd_hash32( (key)->uc, (seed) ))
#define MAP_PREV                           map.prev
#define MAP_NEXT                           map.next
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

/* For a transaction to be valid to be inserted into the txncache, it
   must reference a blockhash that is in the set of recent blockhashes.
   This means that only transactions executed in the latest 151 slots
   can be in the txncache: the remaining entries can be ignored. */
#define FD_SNAPIN_TXNCACHE_MAX_ENTRIES (FD_TXNCACHE_MAX_SLOT_DELTAS*FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT)

FD_STATIC_ASSERT( FD_TXNCACHE_MAX_SLOT_DELTAS<=FD_SLOT_DELTA_MAX_ENTRIES, txncache_staging_slot_cnt );

struct blockhash_group {
  uchar blockhash[ 32UL ];
  ulong slot;
  ulong txnhash_offset;
  ulong txncache_entry_idx;
  ulong txncache_entry_cnt;
};

typedef struct blockhash_group blockhash_group_t;

struct txncache_staging_slot {
  ulong slot;
  ulong entry_cnt;
};

typedef struct txncache_staging_slot txncache_staging_slot_t;

struct fd_snapin_out_link {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
  ulong       mtu;
};
typedef struct fd_snapin_out_link fd_snapin_out_link_t;

/* One writer per tile. */
struct snapin_writer {
  int     fd;
  uchar * buf;
  ulong   buf_used;
  ulong   buf_off;

  ulong bytes_written;
};

typedef struct snapin_writer snapin_writer_t;

struct fd_snapin_tile {
  int  state;
  uint full           : 1;  /* loading a full snapshot? */
  uint init_completed : 1;  /* tile 0: did INIT complete for this attempt? */
  uint gate_pending   : 1;  /* waiting for attempt slot */

  ulong tile_idx;           /* tile kind ID */
  ulong tile_cnt;
  ulong lane_cnt;
  ulong generation;         /* attempt number */
  ulong expected_frame;
  ulong pending_control;    /* control message expected from snapdc tiles */
  uchar control_seen[ FD_TOPO_MAX_TILE_IN_LINKS ];

  ulong seed;
  long boot_timestamp;

  fd_accdb_t *    accdb;
  fd_txncache_t * txncache; /* tile 0 only */

  fd_banks_t * banks;
  fd_bank_t *  bank;        /* tile 0 only */

  /* Shared stake data updated by every tile. */
  fd_stake_delegations_t * stake_delegations;

  /* Tile 0 merges feature data after each attempt. */
  fd_feature_snoop_t feature_snoop[1];

  fd_ssparse_t             ssparse[1];
  fd_ssmanifest_parser_t * manifest_parser;   /* tile 0 only */
  fd_slot_delta_parser_t * slot_delta_parser; /* tile 0 only */

  struct {
    int manifest_done;
    int status_cache_done;
    int manifest_processed;
  } flags;

  ulong advertised_slot;
  ulong bank_slot;
  ulong epoch;

  fd_epoch_schedule_t epoch_schedule;

  ulong full_genesis_creation_time_seconds;
  uchar advertised_hash[ FD_HASH_FOOTPRINT ];

  ulong capitalization;          /* tile 0: capitalization of all loaded accounts, from the shared totals */
  ulong dup_capitalization;      /* tile 0: capitalization of duplicate accounts, from the shared totals */
  ulong manifest_capitalization; /* capitalization according to the current snapshot manifest */

  struct {
    ulong              capitalization;
    fd_feature_snoop_t feature_snoop;
  } recovery; /* tile 0: stores state from the last full snapshot for incremental revert */

  ulong               blockhash_groups_len;
  blockhash_group_t * blockhash_groups;

  int alpenglow;

  fd_sstxncache_hash_t *  txncache_entries;
  txncache_staging_slot_t txncache_slots[ FD_TXNCACHE_MAX_SLOT_DELTAS ];
  ulong                   txncache_slots_len;
  ulong                   txncache_current_slot_idx;
  ulong                   txncache_current_slot_entry_cnt;

  fd_accdb_fork_id_t accdb_root_fork_id;
  fd_accdb_fork_id_t accdb_incr_fork_id; /* tile 0: child fork for incremental writes (purge on failure) */
  fd_txncache_fork_id_t txncache_root_fork_id;

  struct {
    ulong full_bytes_read;
    ulong incremental_bytes_read;

    /* Account counters (full + incremental) */
    ulong accounts_loaded;
    ulong accounts_replaced;
    ulong accounts_ignored;

    /* Account counters (snapshot taken for full snapshot only) */
    ulong full_accounts_loaded;
    ulong full_accounts_replaced;
    ulong full_accounts_ignored;

    /* Persistent counters */
    ulong total_accounts_processed;
    ulong total_account_batches_processed;
  } metrics;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
    ulong       pos;
  } in[ FD_TOPO_MAX_TILE_IN_LINKS ];

  fd_snapin_out_link_t ct_out;
  fd_snapin_out_link_t manifest_out; /* tile 0 only */
  fd_snapin_out_link_t gui_out;      /* tile 0 only */

  /* Shared snapshot state. */
  fd_snapio_snoop_hdr_t * snoop_hdr;
  int *                   stripe_locks;
  fd_snapio_worker_t *    my_snoop;                                /* this tile's failed partitions */
  fd_snapio_worker_t *    snoops[ FD_TOPO_MAX_TILE_IN_LINKS ];     /* tile 0: all failed partitions */

  /* Parse state for one attempt. */
  ulong appendvec_seq;      /* next appendvec number */
  ulong claimed_appendvec;  /* current claim */
  ulong owned_appendvecs;   /* used claims */
  ulong owned_bytes;
  ulong incr_fork;          /* insert fork; USHORT_MAX for full */
  long  gate_warn_ts;       /* next wait warning */

  /* Added to shared totals at FINI. */
  struct {
    ulong accounts_loaded;
    ulong accounts_replaced;
    ulong accounts_ignored;
    ulong input_lamports;
    ulong replaced_lamports;
    ulong ignored_lamports;
  } worker;

  /* Per-tile disk writer. */
  fd_accdb_snapshot_whead_t whead;
  snapin_writer_t writer;
  fd_accdb_snapshot_worker_metrics_t worker_metrics[1];
  struct {
    int   accepted;    /* false for ignored duplicates */
    ulong received;
    ulong file_off;    /* record offset */
  } open_acc;

  /* Batch data used by worker_snoop_winner. */
  struct {
    ulong                 slot;
    uchar const * const * pubkeys;
    uchar const * const * owners;
    uchar const * const * datas;
    ulong const *         lamports;
    ulong const *         data_lens;
    ulong const *         data_szs;    /* bytes readable at datas[i] */
    int   const *         executables;
  } snoop_view;

  /* Buffer snoop data before inserting with the stripe lock. */
  struct {
    int   active;
    int   executable;
    ulong slot;
    ulong lamports;
    ulong data_len;
    ulong need;
    ulong write_pos;
    uchar pubkey[ 32UL ];
    uchar owner [ 32UL ];
    uchar buf   [ FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ];
  } pending;

  /* Tile 0 end-of-attempt state. */
  int   attempt_folded;     /* attempt data already read */
  struct {
    ulong eq_slot_dups;
    ulong eq_slot_lamports_diff;
  } worker_fold;

  /* Tile 0 totals across successful attempts. */
  struct {
    ulong accounts_loaded;
    ulong accounts_replaced;
    ulong accounts_ignored;
  } totals_fold;

  /* Tile 0 rolls back a failure at the next INIT. */
  struct {
    int                pending;
    int                full;  /* failed attempt type */
    fd_accdb_fork_id_t fork;  /* failed incremental fork */
  } rollback;

  /* Failed partitions waiting for purge or reset. */
  uint  doomed_partitions[ FD_SNAPIO_FAIL_PARTITION_MAX ];
  ulong doomed_partition_cnt;
  struct {       /* appendvec sizes logged at FINI */
    ulong cnt;
    ulong bytes;
    ulong max_sz;
    ulong over_64m_cnt;
    ulong over_256m_bytes;
    ulong log2_hist[ 48 ];
  } av_stats;

  ulong gui_config_acct_sz;   /* total expected account data length (0 when not accumulating) */
  ulong gui_config_acct_off;  /* bytes accumulated so far into the current gui_out link chunk */

  /* Tile 0 copy of the shared SlotHistory account. */
  struct {
    int   captured;
    int   executable;
    ulong slot;
    ulong lamports;
    ulong data_len;
    uchar owner[ 32UL ];
    uchar buf[ FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ];
  } slot_history;
};

typedef struct fd_snapin_tile fd_snapin_tile_t;

/* Tile 0 handles shared and final work. */

static inline int
is_lead( fd_snapin_tile_t const * ctx ) {
  return !ctx->tile_idx;
}

static void
format_count( char * out, ulong out_sz, ulong n ) {
  if(      n>=1000000UL ) FD_TEST( fd_cstr_printf_check( out, out_sz, NULL, "%.1fM", (double)n/1e6 ) );
  else if( n>=1000UL    ) FD_TEST( fd_cstr_printf_check( out, out_sz, NULL, "%.1fK", (double)n/1e3 ) );
  else                    FD_TEST( fd_cstr_printf_check( out, out_sz, NULL, "%lu",   n             ) );
}

static inline int
should_shutdown( fd_snapin_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN && is_lead( ctx ) ) ) {
    ulong accounts_dup = ctx->totals_fold.accounts_ignored + ctx->totals_fold.accounts_replaced;
    long  elapsed_ns   = fd_log_wallclock() - ctx->boot_timestamp;
    char  loaded_buf[ 32 ];
    char  dup_buf   [ 32 ];
    format_count( loaded_buf, sizeof(loaded_buf), ctx->totals_fold.accounts_loaded );
    format_count( dup_buf,    sizeof(dup_buf),    accounts_dup                 );
    FD_LOG_NOTICE(( "loaded %s accounts %s(%s dups)%s from snapshot in %.3f seconds",
                    loaded_buf, fd_log_style_dim(), dup_buf, fd_log_style_normal(), (double)elapsed_ns/1e9 ));
  }
  return ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN;
}

static ulong
scratch_align( void ) {
  /* Largest scratch alignment. */
  return 4096UL;
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapin_tile_t),       sizeof(fd_snapin_tile_t)                                    );
  l = FD_LAYOUT_APPEND( l, fd_accdb_align(),                fd_accdb_footprint( tile->snapin.max_live_slots )           );
  if( FD_LIKELY( !tile->kind_id ) ) {
    l = FD_LAYOUT_APPEND( l, fd_txncache_align(),           fd_txncache_footprint( tile->snapin.max_live_slots )        );
    l = FD_LAYOUT_APPEND( l, fd_ssmanifest_parser_align(),  fd_ssmanifest_parser_footprint()                            );
    l = FD_LAYOUT_APPEND( l, fd_slot_delta_parser_align(),  fd_slot_delta_parser_footprint()                            );
    l = FD_LAYOUT_APPEND( l, alignof(blockhash_group_t),    sizeof(blockhash_group_t)*FD_SNAPIN_MAX_SLOT_DELTA_GROUPS   );
    l = FD_LAYOUT_APPEND( l, alignof(fd_sstxncache_hash_t), sizeof(fd_sstxncache_hash_t)*FD_SNAPIN_TXNCACHE_MAX_ENTRIES );
  }
  l = FD_LAYOUT_APPEND( l, 4096UL,                          FD_SNAPIN_WRITE_BUF_SZ                                      );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
metrics_write( fd_snapin_tile_t * ctx ) {
  fd_accdb_flush_metrics( ctx->accdb );

  FD_MGAUGE_SET( SNAPIN, STATE,                  (ulong)ctx->state );
  FD_MGAUGE_SET( SNAPIN, FULL_BYTES_READ,        ctx->metrics.full_bytes_read );
  FD_MGAUGE_SET( SNAPIN, INCREMENTAL_BYTES_READ, ctx->metrics.incremental_bytes_read );
  FD_MCNT_SET  ( SNAPIN, DISK_BYTES_WRITTEN,     ctx->writer.bytes_written );
  FD_MGAUGE_SET( SNAPIN, ACCOUNT_LOADED,         ctx->metrics.accounts_loaded );
  FD_MGAUGE_SET( SNAPIN, ACCOUNT_REPLACED,       ctx->metrics.accounts_replaced );
  FD_MGAUGE_SET( SNAPIN, ACCOUNT_IGNORED,        ctx->metrics.accounts_ignored );
  FD_MCNT_SET  ( SNAPIN, ACCOUNT_PROCESSED,       ctx->metrics.total_accounts_processed );
  FD_MCNT_SET  ( SNAPIN, ACCOUNT_BATCH_PROCESSED, ctx->metrics.total_account_batches_processed );
}

/* verify_slot_deltas_with_slot_history verifies the 'SlotHistory'
   sysvar account after loading a snapshot.  Uses the in-memory copy
   chosen by the same account-stripe winner as accdb.

   Returns 0 if verification passed, -1 if not. */

static int
verify_slot_deltas_with_slot_history( fd_snapin_tile_t * ctx ) {
  if( FD_UNLIKELY( !ctx->slot_history.captured ) ) {
    FD_LOG_WARNING(( "SlotHistory sysvar account was not present in the snapshot stream" ));
    return -1;
  }
  if( FD_UNLIKELY( !ctx->slot_history.lamports || !ctx->slot_history.data_len ) ) {
    FD_LOG_WARNING(( "SlotHistory sysvar account missing or empty" ));
    return -1;
  }
  if( FD_UNLIKELY( !fd_memeq( ctx->slot_history.owner, fd_sysvar_owner_id.uc, sizeof(fd_pubkey_t) ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( ctx->slot_history.owner, owner_b58 );
    FD_LOG_WARNING(( "SlotHistory sysvar owner is invalid: %s != sysvar_owner_id", owner_b58 ));
    return -1;
  }

  fd_slot_history_view_t view[1];
  if( FD_UNLIKELY( !fd_sysvar_slot_history_view( view, ctx->slot_history.buf, ctx->slot_history.data_len ) ) ) {
    FD_LOG_WARNING(( "SlotHistory sysvar account data is corrupt" ));
    return -1;
  }

  /* Sanity checks for slot history:
     https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L586 */

  ulong newest_slot = view->next_slot - 1UL;
  if( FD_UNLIKELY( newest_slot!=ctx->bank_slot ) ) {
    /* VerifySlotHistoryError::InvalidNewestSlot
       https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L621 */
    FD_LOG_WARNING(( "SlotHistory sysvar has an invalid newest slot: %lu != bank slot: %lu", newest_slot, ctx->bank_slot ));
    return -1;
  }

  if( FD_UNLIKELY( view->bits_len!=FD_SLOT_HISTORY_MAX_ENTRIES ) ) {
    /* VerifySlotHistoryError::InvalidNumEntries
       https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L625 */
    FD_LOG_WARNING(( "SlotHistory sysvar has invalid number of entries: %lu != expected: %lu", view->bits_len, FD_SLOT_HISTORY_MAX_ENTRIES ));
    return -1;
  }

  /* All slots in slot deltas should be present in the slot history */
  fd_slot_delta_slot_set_t slot_set = fd_slot_delta_parser_slot_set( ctx->slot_delta_parser );
  for( ulong i=0UL; i<slot_set.ele_cnt; i++ ) {
    ulong slot = slot_set.pool[ i ].slot;
    if( FD_UNLIKELY( fd_sysvar_slot_history_find_slot( view, slot )!=FD_SLOT_HISTORY_SLOT_FOUND ) ) {
      /* VerifySlotDeltasError::SlotNotFoundInHistory
         https://github.com/anza-xyz/agave/blob/v3.1.8/snapshots/src/error.rs#L144
         https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L593 */
      FD_LOG_WARNING(( "slot %lu missing from SlotHistory sysvar account", slot ));
      return -1;
    }
  }

  /* The most recent slots (up to the number of slots in the txncache)
     in the SlotHistory should be present in the txncache. */
  if( FD_LIKELY( slot_set.ele_cnt ) ) {
    ulong oldest = newest_slot - slot_set.ele_cnt;
    for( ulong i=newest_slot; i>oldest; i-- ) {
      if( FD_LIKELY( fd_sysvar_slot_history_find_slot( view, i )==FD_SLOT_HISTORY_SLOT_FOUND ) ) {
        if( FD_UNLIKELY( slot_set_ele_query( slot_set.map, &i, NULL, slot_set.pool )==NULL ) ) {
          /* VerifySlotDeltasError::SlotNotFoundInDeltas
             https://github.com/anza-xyz/agave/blob/v3.1.8/snapshots/src/error.rs#L147
             https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L609 */
          FD_LOG_WARNING(( "slot %lu missing from slot deltas but present in SlotHistory", i ));
          return -1;
        }
      }
    }
  }

  return 0;
}

/* verification of epoch stakes from manifest
   https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L632 */
static int
verify_epoch_stakes( fd_snapshot_manifest_t const * manifest ) {
  fd_epoch_schedule_t epoch_schedule = (fd_epoch_schedule_t){
    .slots_per_epoch             = manifest->epoch_schedule_params.slots_per_epoch,
    .leader_schedule_slot_offset = manifest->epoch_schedule_params.leader_schedule_slot_offset,
    .warmup                      = manifest->epoch_schedule_params.warmup,
    .first_normal_epoch          = manifest->epoch_schedule_params.first_normal_epoch,
    .first_normal_slot           = manifest->epoch_schedule_params.first_normal_slot,
  };

  ulong min_required_epoch = fd_slot_to_epoch( &epoch_schedule, manifest->slot, NULL );
  ulong max_required_epoch = fd_slot_to_leader_schedule_epoch( &epoch_schedule, manifest->slot );

  /* ensure all required epochs are present in epoch stakes */
  for( ulong i=min_required_epoch; i<=max_required_epoch; i++ ) {
    int found = 0;
    for( ulong j=0UL; j<FD_RUNTIME_MANIFEST_EPOCH_STAKES_LEN; j++ ) {
      if( manifest->epoch_stakes[j].epoch==i ) {
        found = 1;
        break;
      }
    }

    if( FD_UNLIKELY( !found ) ) {
      /* VerifyEpochStakesError::StakesNotFound
         https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L667 */
      FD_LOG_WARNING(( "stakes not found for epoch %lu in manifest", i ));
      return -1;
    }
  }

  return 0;
}

static int
verify_slot_deltas_with_bank_slot( fd_snapin_tile_t * ctx,
                                   ulong              bank_slot ) {
  fd_slot_delta_slot_set_t slot_set = fd_slot_delta_parser_slot_set( ctx->slot_delta_parser );
  for( ulong i=0UL; i<slot_set.ele_cnt; i++ ) {
    ulong slot = slot_set.pool[ i ].slot;
    /* VerifySlotDeltasError::SlotGreaterThanMaxRoot
       https://github.com/anza-xyz/agave/blob/v3.1.8/snapshots/src/error.rs#L138
       https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L550 */
    if( FD_UNLIKELY( slot>bank_slot ) ) {
      FD_LOG_WARNING(( "entry slot %lu is greater than bank slot %lu", slot, bank_slot ));
      return -1;
    }
  }
  return 0;
}

static int
verify_bank_hash( fd_snapin_tile_t const *       ctx,
                  fd_snapshot_manifest_t const * manifest ) {
  if( FD_UNLIKELY( manifest->blockhashes_len==0UL ) ) {
    FD_LOG_WARNING(( "%s manifest for epoch %lu and slot %lu has no blockhashes",
                     ctx->full?"full":"incr", ctx->epoch, manifest->slot ));
    return -1;
  }

  if( FD_UNLIKELY( !manifest->has_accounts_lthash ) ) {
    FD_LOG_WARNING(( "%s manifest for epoch %lu and slot %lu is missing accounts lthash",
                     ctx->full?"full":"incr", ctx->epoch, manifest->slot ));
    return -1;
  }

  /* find the last blockhash */
  ulong max_hash_idx = 0UL;
  ulong last_bh_idx  = 0UL;
  for( ulong i=0UL; i<manifest->blockhashes_len; i++ ) {
    if( FD_LIKELY( manifest->blockhashes[ i ].hash_index > max_hash_idx ) ) {
      max_hash_idx = manifest->blockhashes[ i ].hash_index;
      last_bh_idx  = i;
    }
  }

  /* fd_lthash_value_t is aligned to 64B but the accounts_lthash in the
     manifest may not be because its simply a uchar array.  Copy is
     needed to avoid undefined behavior. */
  fd_lthash_value_t accounts_lthash[ 1UL ];
  fd_memcpy( accounts_lthash, manifest->accounts_lthash, sizeof(fd_lthash_value_t) );

  fd_hash_t const * parent_bank_hash = (fd_hash_t const *)fd_type_pun_const( manifest->parent_bank_hash );
  fd_hash_t const * last_blockhash   = (fd_hash_t const *)fd_type_pun_const( manifest->blockhashes[ last_bh_idx ].hash );
  fd_hash_t         computed_bank_hash[ 1UL ];
  fd_hashes_hash_bank( accounts_lthash, parent_bank_hash, last_blockhash, manifest->signature_count, computed_bank_hash );
  fd_hashes_apply_hard_forks(
      computed_bank_hash,
      manifest->slot,
      manifest->parent_slot,
      manifest->hard_forks,
      manifest->hard_fork_cnt );

  if( FD_UNLIKELY( memcmp( computed_bank_hash, manifest->bank_hash, FD_HASH_FOOTPRINT ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( computed_bank_hash->hash, computed_bank_hash_enc );
    FD_BASE58_ENCODE_32_BYTES( manifest->bank_hash, manifest_bank_hash_enc );
    FD_LOG_WARNING(( "%s manifest for epoch %lu and slot %lu bank hash verification failed: computed %s does not match manifest %s",
                     ctx->full?"full":"incr", ctx->epoch, manifest->slot,
                     computed_bank_hash_enc, manifest_bank_hash_enc ));
    return -1;
  }

  return 0;
}

static inline void
clear_control_barrier( fd_snapin_tile_t * ctx ) {
  ctx->pending_control = ULONG_MAX;
  fd_memset( ctx->control_seen, 0, sizeof(ctx->control_seen) );
}

static void
transition_malformed( fd_snapin_tile_t *  ctx,
                      fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_ERROR ) ) return;
  ctx->state = FD_SNAPSHOT_STATE_ERROR;
  fd_stem_publish( stem, ctx->ct_out.idx, FD_SNAPSHOT_MSG_CTRL_ERROR, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static int
populate_txncache( fd_snapin_tile_t *                     ctx,
                   fd_snapshot_manifest_blockhash_t const blockhashes[ static FD_BLOCKHASHES_MAX ],
                   ulong                                  blockhashes_len ) {
  /* Our txncache internally contains the fork structure for the chain,
     which we need to recreate here.  Because snapshots are only served
     for rooted slots, there is actually no forking, and the bank forks
     are just a single bank, the root, like

       _root

     But the txncache also must contain the 150 more recent banks prior
     to the root (151 rooted banks total), looking like,


       _root_150 -> _root_149 -> ... -> _root_2 -> _root_1 -> _root

     Our txncache is "slot agnostic" meaning there is no concept of a
     slot number in it.  It just has a fork tree structure.  So long as
     the fork tree is isomorphic to the actual bank forks, and each bank
     has the correct blockhash, it works.

     So the challenge is simply to create this chain of 151 forks in the
     txncache, with correct blockhashes, and then insert all the
     transactions into it.

     Constructing the chain of blockhashes is easy.  It is just the
     BLOCKHASH_QUEUE array in the manifest.  This array is unfortunately
     not sorted and appears in random order, but it has a hash_index
     field which is a gapless index, starting at some arbitrary offset,
     so we can back out the 151 blockhashes we need from this, by first
     finding the max hash_index as _max and then collecting hash entries
     via,

       _root_150 -> _root_149 -> ... -> _root_2 -> _root_1 -> _root
       _max-150  -> _max-149  -> ... -> _max-2  -> _max-1  -> _max

     Now the remaining problem is inserting transactions into this
     chain.  Remember each transaction needs to be inserted with:

      (a) The fork ID (position of the bank in the chain) it was executed in.
      (b) The blockhash of the bank it referenced.

    (b) is trivial to retrieve, as it's in the actual slot_deltas entry
    in the manifest served by Agave.  But (a) is mildly annoying.  Agave
    serves slot_deltas based on slot, so we need an additional mapping
    from slot to position in our banks chain.  It turns out we have to
    go to yet another structure in the manifest to retrieve this, the
    ancestors array.  This is just an array of slot values,  so we need
    to sort it, and line it up against our banks chain like so,

       _root_150  -> _root_149  -> ... -> _root_2  -> _root_1  -> _root
       _max-150   -> _max-149   -> ... -> _max-2   -> _max-1   -> _max
       _slots_150 -> _slots_149 -> ... -> _slots_2 -> _slots_1 -> _slots

    From there we are done.

    Well almost ... if you were paying attention you might have noticed
    this is a lot of work and we are lazy.  Why don't we just ignore the
    slot mapping and assume everything executed at the root slot
    exactly?  The only invariant we should maintain from a memory
    perspective is that at most, across all active banks,
    FD_MAX_TXN_PER_SLOT transactions are stored per slot, but we
    have preserved that.  It is not true "per slot" technically, but
    it's true across all slots, and the memory is aggregated.  It will
    also always be true, even as slots are garbage collected, because
    entries are collected by reference blockhash, not executed slot.

    ... actually we can't do this.  There's more broken things here.
    The Agave status decided to only store 20 bytes for 32 byte
    transaction hashes to save on memory.  That's OK, but they didn't
    just take the first 20 bytes.  They instead, for each blockhash,
    take a random offset between 0 and 12, and store bytes
    [ offset, offset+20 ) of the transaction hash.  We need to know this
    offset to be able to query the txncache later, so we need to
    retrieve it from the slot_deltas entry in the manifest, and key it
    into our txncache.  Unfortunately this offset is stored per slot in
    the slot_deltas entry.  So we need to first go and retrieve the
    ancestors array, sort it, and line it up against our banks chain as
    described above, and then go through slot deltas, to retrieve the
    offset for each slot, and stick it into the appropriate bank in
    our chain. */

  if( FD_UNLIKELY( blockhashes_len>FD_BLOCKHASHES_MAX ) ) {
    FD_LOG_WARNING(( "corrupt snapshot: blockhash queue length %lu exceeds maximum %lu", blockhashes_len, FD_BLOCKHASHES_MAX ));
    return 1;
  }
  if( FD_UNLIKELY( !blockhashes_len ) ) {
    FD_LOG_WARNING(( "corrupt snapshot: blockhash queue is empty" ));
    return 1;
  }

  ulong seq_min = ULONG_MAX;
  for( ulong i=0UL; i<blockhashes_len; i++ ) seq_min = fd_ulong_min( seq_min, blockhashes[ i ].hash_index );

  ulong seq_max;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( seq_min, blockhashes_len, &seq_max ) ) ) {
    FD_LOG_WARNING(( "corrupt snapshot: blockhash queue sequence number wraparound (seq_min=%lu age_cnt=%lu)", seq_min, blockhashes_len ));
    return 1;
  }

  /* First let's construct the chain array as described above.  But
     index 0 will be the root, index 1 the root's parent, etc. */

  struct {
    int exists;
    uchar blockhash[ 32UL ];
    fd_txncache_fork_id_t fork_id;
    ulong txnhash_offset;
  } banks[ FD_BLOCKHASHES_MAX ] = {0};

  for( ulong i=0UL; i<blockhashes_len; i++ ) {
    fd_snapshot_manifest_blockhash_t const * elem = &blockhashes[ i ];
    ulong idx;
    if( FD_UNLIKELY( __builtin_usubl_overflow( elem->hash_index, seq_min, &idx ) ) ) {
      FD_LOG_WARNING(( "corrupt snapshot: gap in blockhash queue (seq=[%lu,%lu) idx=%lu)", seq_min, seq_max, blockhashes[ i ].hash_index ));
      return 1;
    }

    if( FD_UNLIKELY( idx>=blockhashes_len ) ) {
      FD_LOG_WARNING(( "corrupt snapshot: blockhash queue index out of range (seq_min=%lu age_cnt=%lu idx=%lu)", seq_min, blockhashes_len, idx ));
      return 1;
    }

    if( FD_UNLIKELY( banks[ blockhashes_len-1UL-idx ].exists ) ) {
      FD_LOG_WARNING(( "corrupt snapshot: duplicate blockhash hash_index %lu", elem->hash_index ));
      return 1;
    }

    banks[ blockhashes_len-1UL-idx ].fork_id.val = USHORT_MAX;
    banks[ blockhashes_len-1UL-idx ].txnhash_offset = ULONG_MAX;
    memcpy( banks[ blockhashes_len-1UL-idx ].blockhash, elem->hash, 32UL );
    banks[ blockhashes_len-1UL-idx ].exists = 1;
  }

  ulong chain_len = fd_ulong_min( blockhashes_len, 151UL );

  /* Now we need a hashset of just the 151 most recent blockhashes,
     anything else is a nonce transaction which we do not insert, or an
     already expired transaction which can also be discarded. */

  uchar __attribute__((aligned(alignof(blockhash_map_t)))) _map[ blockhash_map_footprint( 1024UL ) ];
  blockhash_map_t * blockhash_map = blockhash_map_join( blockhash_map_new( _map, 1024UL, ctx->seed ) );
  if( FD_UNLIKELY( !blockhash_map ) ) FD_LOG_ERR(( "failed to create blockhash map" ));

  fd_blockhash_entry_t blockhash_pool[ 151UL ];
  for( ulong i=0UL; i<chain_len; i++ ) {
    fd_memcpy( blockhash_pool[ i ].blockhash.uc, banks[ i ].blockhash, 32UL );

    if( FD_UNLIKELY( blockhash_map_ele_query_const( blockhash_map, &blockhash_pool[ i ].blockhash, NULL, blockhash_pool ) ) ) {
      FD_BASE58_ENCODE_32_BYTES( banks[ i ].blockhash, blockhash_b58 );
      FD_LOG_WARNING(( "corrupt snapshot: duplicate blockhash %s in 151 most recent blockhashes", blockhash_b58 ));
      return 1;
    }

    blockhash_map_ele_insert( blockhash_map, &blockhash_pool[ i ], blockhash_pool );
  }

  /* Now load the blockhash offsets for these blockhashes ... */
  if( FD_UNLIKELY( !ctx->blockhash_groups_len ) ) {
    fd_slot_delta_slot_set_t ss = fd_slot_delta_parser_slot_set( ctx->slot_delta_parser );
    /* No offsets AND no rooted slots is corruption in either mode.  No
       offsets WITH rooted slots only happens under Alpenglow. */
    if( FD_UNLIKELY( !ctx->alpenglow || !ss.ele_cnt ) ) {
      FD_LOG_WARNING(( "corrupt snapshot: no blockhash offsets found (rooted_slots=%lu)", ss.ele_cnt ));
      return 1;
    }
    FD_LOG_WARNING(( "status cache has no blockhash offsets (rooted_slots=%lu); proceeding with empty txncache offsets",
                     ss.ele_cnt ));
  }
  for( ulong i=0UL; i<ctx->blockhash_groups_len; i++ ) {
    blockhash_group_t const * group = &ctx->blockhash_groups[ i ];
    fd_hash_t key;
    fd_memcpy( key.uc, group->blockhash, 32UL );
    fd_blockhash_entry_t * entry = blockhash_map_ele_query( blockhash_map, &key, NULL, blockhash_pool );
    if( FD_UNLIKELY( !entry ) ) continue; /* Not in the most recent 151 blockhashes */

    ulong chain_idx = (ulong)(entry - blockhash_pool);

    if( FD_UNLIKELY( banks[ chain_idx ].txnhash_offset!=ULONG_MAX && banks[ chain_idx ].txnhash_offset!=group->txnhash_offset ) ) {
      FD_BASE58_ENCODE_32_BYTES( entry->blockhash.uc, blockhash_b58 );
      FD_LOG_WARNING(( "corrupt snapshot: conflicting txnhash offsets for blockhash %s", blockhash_b58 ));
      return 1;
    }

    banks[ chain_idx ].txnhash_offset = group->txnhash_offset;
  }

  /* Construct the linear fork chain in the txncache. */

  fd_txncache_fork_id_t parent = { .val = USHORT_MAX };
  for( ulong i=0UL; i<chain_len; i++ ) banks[ chain_len-1UL-i ].fork_id = parent = fd_txncache_attach_child( ctx->txncache, parent );
  for( ulong i=0UL; i<chain_len; i++ ) fd_txncache_attach_blockhash( ctx->txncache, banks[ i ].fork_id, banks[ i ].blockhash );

  /* Now insert all transactions as if they executed at the current
     root, per above. */

  for( ulong i=0UL; i<ctx->blockhash_groups_len; i++ ) {
    blockhash_group_t const * group = &ctx->blockhash_groups[ i ];
    /* Skip if there are no transaction in this group or if the slot is
       too old. */
    if( FD_UNLIKELY( group->txncache_entry_idx==ULONG_MAX || !group->txncache_entry_cnt ) ) continue;

    ulong slot_idx = group->txncache_entry_idx/FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT;
    FD_TEST( slot_idx<ctx->txncache_slots_len );
    /* Skip groups whose entries correspond to a different slot.  This
       happens when an older slot is evicted and its storage is reused. */
    if( FD_UNLIKELY( ctx->txncache_slots[ slot_idx ].slot!=group->slot ) ) continue;
    ulong slot_entry_idx = group->txncache_entry_idx-slot_idx*FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT;
    FD_TEST( slot_entry_idx<=ctx->txncache_slots[ slot_idx ].entry_cnt );
    FD_TEST( group->txncache_entry_cnt<=ctx->txncache_slots[ slot_idx ].entry_cnt-slot_entry_idx );
    fd_sstxncache_hash_t const * entries = &ctx->txncache_entries[ group->txncache_entry_idx ];

    fd_hash_t key;
    fd_memcpy( key.uc, group->blockhash, 32UL );
    if( FD_UNLIKELY( !blockhash_map_ele_query_const( blockhash_map, &key, NULL, blockhash_pool ) ) ) continue;

    for( ulong j=0UL; j<group->txncache_entry_cnt; j++ ) {
      fd_sstxncache_hash_t const * entry = &entries[ j ];
      fd_txncache_insert( ctx->txncache, banks[ 0UL ].fork_id, group->blockhash, entry->txnhash );
    }
  }

  /* Then finalize all the banks (freezing them) and setting the txnhash
     offset so future queries use the correct offset.  If the offset is
     ULONG_MAX this is valid, it means the blockhash had no transactions
     in it, so there's nothing in the status cache under that blockhash.

     Just set the offset to 0 in this case, it doesn't matter, but
     should be valid between 0 and 12 inclusive. */
  for( ulong i=0UL; i<chain_len; i++ ) {
    ulong txnhash_offset = banks[ chain_len-1UL-i ].txnhash_offset==ULONG_MAX ? 0UL : banks[ chain_len-1UL-i ].txnhash_offset;
    fd_txncache_finalize_fork( ctx->txncache, banks[ chain_len-1UL-i ].fork_id, txnhash_offset, banks[ chain_len-1UL-i ].blockhash );
  }

  for( ulong i=1UL; i<chain_len; i++ ) fd_txncache_advance_root( ctx->txncache, banks[ chain_len-1UL-i ].fork_id );

  ctx->txncache_root_fork_id = parent;

  return 0;
}

static void
process_manifest( fd_snapin_tile_t *  ctx,
                  fd_stem_context_t * stem ) {
  fd_snapshot_manifest_t * manifest = fd_chunk_to_laddr( ctx->manifest_out.mem, ctx->manifest_out.chunk );

  if( FD_UNLIKELY( ctx->advertised_slot!=manifest->slot ) ) {
    /* SnapshotError::MismatchedSlot
       https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L472 */
    FD_LOG_WARNING(( "snapshot manifest bank slot %lu does not match advertised slot %lu from snapshot peer",
                     manifest->slot, ctx->advertised_slot ));
    transition_malformed( ctx, stem );
    return;
  }

  if( FD_UNLIKELY( !manifest->has_accounts_lthash ) ) {
    /* The manifest must contain accounts lthash, irrespective of
       whether lthash verification is disabled or not.
       https://github.com/anza-xyz/agave/blob/v3.1.9/runtime/src/serde_snapshot.rs#L482 */
    FD_LOG_WARNING(( "snapshot manifest missing accounts lthash" ));
    transition_malformed( ctx, stem );
    return;
  }

  uchar const * sum = manifest->accounts_lthash;
  uchar hash32[32]; fd_blake3_hash( sum, FD_LTHASH_LEN_BYTES, hash32 );
  FD_BASE58_ENCODE_32_BYTES( sum,    sum_enc    );
  FD_BASE58_ENCODE_32_BYTES( hash32, hash32_enc );
  FD_LOG_INFO(( "snapshot manifest slot=%lu indicates lthash[..32]=%s blake3(lthash)=%s",
                manifest->slot, sum_enc, hash32_enc ));

  if( FD_UNLIKELY( memcmp( ctx->advertised_hash, hash32, FD_HASH_FOOTPRINT ) ) ) {
    /* SnapshotError::MismatchedHash
        https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L479 */
    FD_BASE58_ENCODE_32_BYTES( ctx->advertised_hash, advertised_hash_enc );
    FD_LOG_WARNING(( "snapshot manifest accounts lthash %s does not match advertised hash from snapshot peer %s",
                     hash32_enc, advertised_hash_enc ));
    transition_malformed( ctx, stem );
    return;
  }

  ctx->bank_slot = manifest->slot;
  ctx->manifest_capitalization = manifest->capitalization;
  if( FD_UNLIKELY( ctx->manifest_capitalization>LONG_MAX ) ) {
    /* Calculations downstream require capitalization to be treated
       as long (to handle addition and subtraction). */
    FD_LOG_WARNING(( "snapshot manifest capitalization %lu exceeds LONG_MAX", ctx->manifest_capitalization ));
    transition_malformed( ctx, stem );
    return;
  }

  if( FD_UNLIKELY( fd_ssload_manifest_validate( manifest, FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS, FD_RUNTIME_MAX_STAKE_ACCOUNTS ) ) ) {
    FD_LOG_WARNING(( "snapshot manifest validation failed" ));
    transition_malformed( ctx, stem );
    return;
  }

  fd_epoch_schedule_t epoch_schedule = (fd_epoch_schedule_t){
    .slots_per_epoch             = manifest->epoch_schedule_params.slots_per_epoch,
    .leader_schedule_slot_offset = manifest->epoch_schedule_params.leader_schedule_slot_offset,
    .warmup                      = manifest->epoch_schedule_params.warmup,
    .first_normal_epoch          = manifest->epoch_schedule_params.first_normal_epoch,
    .first_normal_slot           = manifest->epoch_schedule_params.first_normal_slot,
  };
  ctx->epoch          = fd_slot_to_epoch( &epoch_schedule, manifest->slot, NULL );
  ctx->epoch_schedule = epoch_schedule;

  if( FD_UNLIKELY( verify_bank_hash( ctx, manifest ) ) ) {
    /* https://github.com/anza-xyz/agave/blob/v3.1.9/runtime/src/bank.rs#L4682 */
    transition_malformed( ctx, stem );
    return;
  }

  if( FD_UNLIKELY( verify_slot_deltas_with_bank_slot( ctx, manifest->slot ) ) ) {
    FD_LOG_WARNING(( "slot deltas verification failed" ));
    transition_malformed( ctx, stem );
    return;
  }

  if( FD_UNLIKELY( verify_epoch_stakes( manifest ) ) ) {
    FD_LOG_WARNING(( "epoch stakes verification failed" ));
    transition_malformed( ctx, stem );
    return;
  }

  if( FD_UNLIKELY( populate_txncache( ctx, manifest->blockhashes, manifest->blockhashes_len ) ) ) {
    FD_LOG_WARNING(( "populating txncache failed" ));
    transition_malformed( ctx, stem );
    return;
  }

  if( ctx->full ) {
    ctx->full_genesis_creation_time_seconds = manifest->creation_time_seconds;
  } else {
    if( FD_UNLIKELY( manifest->creation_time_seconds!=ctx->full_genesis_creation_time_seconds ) ) {
      FD_LOG_WARNING(( "snapshot manifest genesis creation time seconds %lu does not match full snapshot genesis creation time seconds %lu",
                       manifest->creation_time_seconds, ctx->full_genesis_creation_time_seconds ));
      transition_malformed( ctx, stem );
      return;
    }
  }

  manifest->accdb_fork_id    = fd_ushort_if( ctx->full, ctx->accdb_root_fork_id.val, ctx->accdb_incr_fork_id.val );
  manifest->txncache_fork_id = ctx->txncache_root_fork_id.val;

  ulong sig = ctx->full ? fd_ssmsg_sig( FD_SSMSG_MANIFEST_FULL ) :
                          fd_ssmsg_sig( FD_SSMSG_MANIFEST_INCREMENTAL );
  fd_stem_publish( stem, ctx->manifest_out.idx, sig, ctx->manifest_out.chunk, sizeof(fd_snapshot_manifest_t), 0UL, 0UL, 0UL );
  ctx->manifest_out.chunk = fd_dcache_compact_next( ctx->manifest_out.chunk, sizeof(fd_snapshot_manifest_t), ctx->manifest_out.chunk0, ctx->manifest_out.wmark );
}

static int
validate_capitalization( fd_snapin_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->capitalization!=ctx->manifest_capitalization ) ) {
    /* SnapshotError::MismatchedCapitalization
        https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/snapshot_bank_utils.rs#L217 */
    FD_LOG_WARNING(( "%s snapshot manifest capitalization %lu does not match computed capitalization %lu",
                     ctx->full?"full":"incr", ctx->manifest_capitalization, ctx->capitalization ));
    return -1;
  }
  return 0;
}

/* Write engine */

static void
writer_init( snapin_writer_t * writer,
             int               fd,
             uchar *           buf ) {
  fd_memset( writer, 0, sizeof(*writer) );
  writer->fd  = fd;
  writer->buf = buf;
}

static void
writer_begin( snapin_writer_t * writer ) {
  FD_TEST( !writer->buf_used );
}

static int
writer_flush( snapin_writer_t * writer ) {
  if( FD_UNLIKELY( !writer->buf_used ) ) return 0;

  ulong sz   = writer->buf_used;
  ulong off  = writer->buf_off;
  ulong done = 0UL;
  while( done<sz ) {
    long res = pwrite( writer->fd, writer->buf+done, sz-done, (long)(off+done) );
    if( FD_UNLIKELY( res<=0L ) ) {
      int err = res<0L ? errno : EIO;
      if( res<0L && err==EINTR ) continue;
      if( done ) {
        memmove( writer->buf, writer->buf+done, sz-done );
        writer->buf_off  += done;
        writer->buf_used -= done;
      }
      FD_LOG_WARNING(( "snapshot write failed at offset %lu (%d-%s)", off+done, err, fd_io_strerror( err ) ));
      return -1;
    }
    done                  += (ulong)res;
    writer->bytes_written += (ulong)res;
  }
  writer->buf_off  += sz;
  writer->buf_used  = 0UL;
  return 0;
}

static int
writer_write( snapin_writer_t * writer,
              ulong             file_off,
              uchar const *     data,
              ulong             sz ) {
  if( FD_UNLIKELY( !sz ) ) return 0;
  if( FD_UNLIKELY( file_off!=writer->buf_off+writer->buf_used ) ) {
    if( FD_UNLIKELY( writer_flush( writer ) ) ) return -1;
    writer->buf_off = file_off;
  }
  while( sz ) {
    ulong avail = FD_SNAPIN_WRITE_BUF_SZ-writer->buf_used;
    ulong n     = fd_ulong_min( sz, avail );
    fd_memcpy( writer->buf+writer->buf_used, data, n );
    writer->buf_used += n;
    data += n;
    sz   -= n;
    if( FD_UNLIKELY( writer->buf_used==FD_SNAPIN_WRITE_BUF_SZ && writer_flush( writer ) ) ) return -1;
  }
  return 0;
}

static int
writer_end( snapin_writer_t * writer ) {
  return writer_flush( writer );
}

static void
writer_abort( snapin_writer_t * writer ) {
  writer->buf_used = 0UL;
}

static int
worker_stage_meta( fd_snapin_tile_t * ctx,
                   ulong              file_off,
                   uchar const *      pubkey,
                   uchar const *      owner,
                   ulong              data_len ) {
  fd_accdb_disk_meta_t meta;
  fd_memcpy( meta.pubkey, pubkey, 32UL );
  meta.size       = (uint)data_len;
  meta.generation = 0U;
  fd_memcpy( meta.owner, owner, 32UL );
  return writer_write( &ctx->writer, file_off, meta.b, sizeof(fd_accdb_disk_meta_t) );
}

/* Shared account data */

/* Find SlotHistory, feature, and stake accounts. */

static inline int
worker_snoop_candidate( uchar const * pubkey,
                        uchar const * owner ) {
  return !memcmp( owner,  fd_solana_feature_program_id.uc, 32UL )
      || !memcmp( owner,  fd_solana_stake_program_id.uc,   32UL )
      || !memcmp( pubkey, fd_sysvar_slot_history_id.uc,    32UL );
}

/* Return the body prefix needed by snoops. */

static inline ulong
worker_snoop_need( uchar const * pubkey,
                   uchar const * owner,
                   ulong         lamports,
                   ulong         data_len ) {
  if( FD_UNLIKELY( !memcmp( pubkey, fd_sysvar_slot_history_id.uc, 32UL ) ) ) {
    return data_len<=FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ? data_len : 0UL;
  }
  if( FD_UNLIKELY( !lamports ) ) return 0UL;
  if( FD_UNLIKELY( !memcmp( owner, fd_solana_feature_program_id.uc, 32UL ) ) ) {
    return fd_ulong_min( data_len, sizeof(fd_feature_t) );
  }
  if( FD_UNLIKELY( !memcmp( owner, fd_solana_stake_program_id.uc, 32UL ) ) ) {
    return data_len>=sizeof(fd_stake_state_t) ? sizeof(fd_stake_state_t) : 0UL;
  }
  return 0UL;
}

FD_STATIC_ASSERT( sizeof(fd_feature_t)    <=FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, snoop_prefix_buf );
FD_STATIC_ASSERT( sizeof(fd_stake_state_t)<=FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, snoop_prefix_buf );

/* Called with the account stripe locked.
   The last accepted account updates the shared snoop. */

static void
worker_snoop_winner( void * cb_ctx,
                     ulong  batch_idx ) {
  fd_snapin_tile_t * ctx = (fd_snapin_tile_t *)cb_ctx;

  uchar const * pubkey   = ctx->snoop_view.pubkeys  [ batch_idx ];
  uchar const * owner    = ctx->snoop_view.owners   [ batch_idx ];
  uchar const * data     = ctx->snoop_view.datas    [ batch_idx ];
  ulong         lamports = ctx->snoop_view.lamports [ batch_idx ];
  ulong         data_len = ctx->snoop_view.data_lens[ batch_idx ];
  ulong         data_sz  = ctx->snoop_view.data_szs [ batch_idx ];

  if( FD_UNLIKELY( !memcmp( pubkey, fd_sysvar_slot_history_id.uc, 32UL ) ) ) {
    if( FD_UNLIKELY( data_len>FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ) ) return;
    fd_snapio_snoop_hdr_t * hdr = ctx->snoop_hdr;
    hdr->slot_history.slot       = ctx->snoop_view.slot;
    hdr->slot_history.lamports   = lamports;
    hdr->slot_history.data_len   = data_len;
    hdr->slot_history.executable = ctx->snoop_view.executables[ batch_idx ];
    fd_memcpy( hdr->slot_history.owner, owner, 32UL );
    fd_memcpy( hdr->slot_history.buf, data, fd_ulong_min( data_len, data_sz ) );
    hdr->slot_history.captured   = 1;
    return;
  }

  if( FD_UNLIKELY( !memcmp( owner, fd_solana_feature_program_id.uc, 32UL ) ) ) {
    fd_feature_snoop_account( &ctx->snoop_hdr->feature_snoop, (fd_pubkey_t const *)pubkey,
                              lamports, owner, data, data_sz );
    return;
  }

  if( FD_UNLIKELY( !lamports ) ) return;

  /* Match the single-tile stake update. */
  fd_stake_state_t const * stake_state = fd_stake_state_view( data, data_sz );
  if( FD_UNLIKELY( !stake_state || stake_state->stake_type!=FD_STAKE_STATE_STAKE ) ) return;

  fd_delegation_t const * delegation = &stake_state->stake.stake.delegation;
  if( FD_UNLIKELY( ( delegation->activation_epoch!=ULONG_MAX &&
                     delegation->activation_epoch>=(ulong)USHORT_MAX ) ||
                   ( delegation->deactivation_epoch!=ULONG_MAX &&
                     delegation->deactivation_epoch>=(ulong)USHORT_MAX ) ) ) return;

  fd_stake_delegations_root_update(
      ctx->stake_delegations,
      (fd_pubkey_t const *)pubkey,
      &delegation->voter_pubkey,
      delegation->stake,
      delegation->activation_epoch,
      delegation->deactivation_epoch,
      stake_state->stake.stake.credits_observed,
      lamports,
      (uint)data_len,
      /* fd_stake_delegations_refresh recomputes this after load. */
      FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
}

static void
worker_reset_attempt( fd_snapin_tile_t * ctx ) {
  ctx->expected_frame = 0UL;
  for( ulong lane=0UL; lane<ctx->lane_cnt; lane++ ) ctx->in[ lane ].pos = 0UL;
  ctx->appendvec_seq    = 0UL;
  ctx->owned_appendvecs = 0UL;
  ctx->owned_bytes      = 0UL;
  ctx->incr_fork        = ULONG_MAX;
  ctx->gate_pending     = 0;
  ctx->whead.val                    = 0UL;
  ctx->whead.has_partition          = 0;
  ctx->whead.attempt_partition_cnt  = 0UL;
  fd_memset( &ctx->open_acc, 0, sizeof(ctx->open_acc) );
  fd_memset( &ctx->worker, 0, sizeof(ctx->worker) );
  fd_memset( ctx->worker_metrics, 0, sizeof(ctx->worker_metrics) );
  ctx->pending.active            = 0;
  fd_ssparse_init( ctx->ssparse );
  fd_ssparse_batch_enable( ctx->ssparse, 1 );
  fd_ssparse_appendvec_passthrough_enable( ctx->ssparse, 1 );
  /* The gate takes the next appendvec claim. */
}

/* Count one successful insert call. */

static inline void
worker_record_insert_metrics( fd_snapin_tile_t * ctx,
                              ulong              cnt,
                              ulong              accounts_ignored,
                              ulong              accounts_replaced,
                              ulong              accounts_loaded,
                              ulong              input_lamports,
                              ulong              replaced_lamports,
                              ulong              ignored_lamports ) {
  ctx->metrics.accounts_ignored  += accounts_ignored;
  ctx->metrics.accounts_replaced += accounts_replaced;
  ctx->metrics.accounts_loaded   += accounts_loaded;
  ctx->metrics.total_accounts_processed += cnt;
  ctx->metrics.total_account_batches_processed++;
  ctx->worker.accounts_ignored  += accounts_ignored;
  ctx->worker.accounts_replaced += accounts_replaced;
  ctx->worker.accounts_loaded   += accounts_loaded;
  ctx->worker.input_lamports    = fd_ulong_sat_add( ctx->worker.input_lamports,    input_lamports    );
  ctx->worker.replaced_lamports = fd_ulong_sat_add( ctx->worker.replaced_lamports, replaced_lamports );
  ctx->worker.ignored_lamports  = fd_ulong_sat_add( ctx->worker.ignored_lamports,  ignored_lamports  );
}

static int
worker_process_account_batch( fd_snapin_tile_t *            ctx,
                              fd_ssparse_advance_result_t * result ) {
  uchar const * const * entries    = result->account_batch.batch;
  ulong                 cnt        = result->account_batch.batch_cnt;
  ulong                 batch_slot = result->account_batch.slot;

  uchar const * pubkeys     [ FD_SSPARSE_ACC_BATCH_MAX ] = {0};
  uchar const * owners      [ FD_SSPARSE_ACC_BATCH_MAX ] = {0};
  uchar const * datas       [ FD_SSPARSE_ACC_BATCH_MAX ] = {0};
  ulong         lamports    [ FD_SSPARSE_ACC_BATCH_MAX ] = {0};
  ulong         data_lens   [ FD_SSPARSE_ACC_BATCH_MAX ] = {0};
  int           executables [ FD_SSPARSE_ACC_BATCH_MAX ] = {0};
  int           candidates  [ FD_SSPARSE_ACC_BATCH_MAX ] = {0};
  ulong         file_offsets[ FD_SSPARSE_ACC_BATCH_MAX ] = {0};

  ulong batch_lamports = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    uchar const * e = entries[ i ];
    pubkeys[ i ]     = e + 16UL;
    owners[ i ]      = e + 64UL;
    datas[ i ]       = e + 136UL; /* batch body */
    lamports[ i ]    = fd_ulong_load_8_fast( e+48UL );
    data_lens[ i ]   = fd_ulong_load_8_fast( e+8UL );
    executables[ i ] = e[ 96UL ];
    candidates[ i ]  = worker_snoop_candidate( pubkeys[ i ], owners[ i ] );
    batch_lamports   = fd_ulong_sat_add( batch_lamports, lamports[ i ] );
  }

  ctx->snoop_view.slot        = batch_slot;
  ctx->snoop_view.pubkeys     = pubkeys;
  ctx->snoop_view.owners      = owners;
  ctx->snoop_view.datas       = datas;
  ctx->snoop_view.lamports    = lamports;
  ctx->snoop_view.data_lens   = data_lens;
  ctx->snoop_view.data_szs    = data_lens;
  ctx->snoop_view.executables = executables;

  ulong accounts_ignored, accounts_replaced, accounts_loaded, replaced_lamports, ignored_lamports;
  fd_accdb_fork_id_t fork_id = { .val = ctx->full ? USHORT_MAX : (ushort)ctx->incr_fork };
  if( FD_UNLIKELY( 0!=fd_accdb_snapshot_write_batch_worker( ctx->accdb, fork_id, cnt, pubkeys, batch_slot, lamports,
                                                            data_lens, executables, candidates, &ctx->whead,
                                                            ctx->stripe_locks, FD_SNAPIO_STRIPE_MSK, ctx->worker_metrics,
                                                            file_offsets, &accounts_ignored, &accounts_replaced,
                                                            &accounts_loaded, &replaced_lamports, &ignored_lamports,
                                                            worker_snoop_winner, ctx ) ) ) {
    return -1;
  }

  /* Write accepted records at their assigned offsets. */
  for( ulong i=0UL; i<cnt; i++ ) {
    if( FD_UNLIKELY( file_offsets[ i ]==ULONG_MAX ) ) continue;
    if( FD_UNLIKELY( worker_stage_meta( ctx, file_offsets[ i ], pubkeys[ i ], owners[ i ], data_lens[ i ] ) ) ) return -1;
    if( FD_LIKELY( data_lens[ i ] ) ) {
      if( FD_UNLIKELY( writer_write( &ctx->writer, file_offsets[ i ]+sizeof(fd_accdb_disk_meta_t),
                                    datas[ i ], data_lens[ i ] ) ) ) return -1;
    }
  }

  worker_record_insert_metrics( ctx, cnt, accounts_ignored, accounts_replaced, accounts_loaded,
                                batch_lamports, replaced_lamports, ignored_lamports );

  return 0;
}

/* Insert one streamed account and open its data range.
   Snoop accounts include their buffered prefix. */

static int
worker_insert_one( fd_snapin_tile_t * ctx,
                   uchar const *      pubkey,
                   uchar const *      owner,
                   ulong              slot,
                   ulong              lamports,
                   ulong              data_len,
                   int                executable,
                   int                candidate,
                   uchar const *      data,
                   ulong              data_sz ) {
  uchar const * pubkeys     [ 1 ] = { pubkey };
  uchar const * owners      [ 1 ] = { owner };
  uchar const * datas       [ 1 ] = { data };
  ulong         lamports_a  [ 1 ] = { lamports };
  ulong         data_lens   [ 1 ] = { data_len };
  ulong         data_szs    [ 1 ] = { data_sz };
  int           executables [ 1 ] = { executable };
  int           candidates  [ 1 ] = { candidate };
  ulong         file_offsets[ 1 ];

  ctx->snoop_view.slot        = slot;
  ctx->snoop_view.pubkeys     = pubkeys;
  ctx->snoop_view.owners      = owners;
  ctx->snoop_view.datas       = datas;
  ctx->snoop_view.lamports    = lamports_a;
  ctx->snoop_view.data_lens   = data_lens;
  ctx->snoop_view.data_szs    = data_szs;
  ctx->snoop_view.executables = executables;

  ulong accounts_ignored, accounts_replaced, accounts_loaded, replaced_lamports, ignored_lamports;
  fd_accdb_fork_id_t fork_id = { .val = ctx->full ? USHORT_MAX : (ushort)ctx->incr_fork };
  if( FD_UNLIKELY( 0!=fd_accdb_snapshot_write_batch_worker( ctx->accdb, fork_id, 1UL, pubkeys, slot, lamports_a,
                                                            data_lens, executables, candidates, &ctx->whead,
                                                            ctx->stripe_locks, FD_SNAPIO_STRIPE_MSK, ctx->worker_metrics,
                                                            file_offsets, &accounts_ignored, &accounts_replaced,
                                                            &accounts_loaded, &replaced_lamports, &ignored_lamports,
                                                            worker_snoop_winner, ctx ) ) ) {
    return -1;
  }
  int ignored = file_offsets[ 0 ]==ULONG_MAX;

  ctx->open_acc.accepted = !ignored;
  ctx->open_acc.received = 0UL;
  ctx->open_acc.file_off = file_offsets[ 0 ];
  if( FD_LIKELY( !ignored ) &&
      FD_UNLIKELY( worker_stage_meta( ctx, file_offsets[ 0 ], pubkey, owner, data_len ) ) ) return -1;

  worker_record_insert_metrics( ctx, 1UL, accounts_ignored, accounts_replaced, accounts_loaded,
                                lamports, replaced_lamports, ignored_lamports );

  return 0;
}

/* Insert a buffered snoop account, then stream its body. */

static int
worker_pending_flush( fd_snapin_tile_t * ctx ) {
  ctx->pending.active = 0;
  if( FD_UNLIKELY( 0!=worker_insert_one( ctx, ctx->pending.pubkey, ctx->pending.owner, ctx->pending.slot,
                                         ctx->pending.lamports, ctx->pending.data_len, ctx->pending.executable,
                                         1, ctx->pending.buf, ctx->pending.write_pos ) ) ) return -1;
  if( FD_LIKELY( ctx->open_acc.accepted && ctx->pending.write_pos ) ) {
    if( FD_UNLIKELY( writer_write( &ctx->writer, ctx->open_acc.file_off+sizeof(fd_accdb_disk_meta_t),
                                  ctx->pending.buf, ctx->pending.write_pos ) ) ) return -1;
  }
  ctx->open_acc.received = ctx->pending.write_pos;
  return 0;
}

static int
worker_process_account_header( fd_snapin_tile_t *            ctx,
                               fd_ssparse_advance_result_t * result ) {
  uchar const * pubkey   = result->account_header.pubkey;
  uchar const * owner    = result->account_header.owner;
  ulong         lamports = result->account_header.lamports;
  ulong         data_len = result->account_header.data_len;

  if( FD_LIKELY( !worker_snoop_candidate( pubkey, owner ) ) ) {
    return worker_insert_one( ctx, pubkey, owner, result->account_header.slot, lamports, data_len,
                              result->account_header.executable, 0, NULL, 0UL );
  }

  /* Buffer the snoop prefix before insert. */
  ctx->pending.active     = 1;
  ctx->pending.executable = result->account_header.executable;
  ctx->pending.slot       = result->account_header.slot;
  ctx->pending.lamports   = lamports;
  ctx->pending.data_len   = data_len;
  ctx->pending.need       = worker_snoop_need( pubkey, owner, lamports, data_len );
  ctx->pending.write_pos  = 0UL;
  fd_memcpy( ctx->pending.pubkey, pubkey, 32UL );
  fd_memcpy( ctx->pending.owner,  owner,  32UL );
  if( FD_UNLIKELY( !ctx->pending.need ) ) return worker_pending_flush( ctx );
  return 0;
}

/* Returns 0 on success and -1 on attempt failure. */

static int
worker_process_account_data( fd_snapin_tile_t *            ctx,
                             fd_ssparse_advance_result_t * result ) {
  uchar const * data    = result->account_data.data;
  ulong         data_sz = result->account_data.data_sz;

  if( FD_UNLIKELY( ctx->pending.active ) ) {
    ulong copy_sz = fd_ulong_min( data_sz, ctx->pending.need-ctx->pending.write_pos );
    fd_memcpy( ctx->pending.buf+ctx->pending.write_pos, data, copy_sz );
    ctx->pending.write_pos += copy_sz;
    if( FD_UNLIKELY( ctx->pending.write_pos<ctx->pending.need ) ) return 0;
    if( FD_UNLIKELY( 0!=worker_pending_flush( ctx ) ) ) return -1;
    data    += copy_sz;
    data_sz -= copy_sz;
    if( FD_LIKELY( !data_sz ) ) return 0;
  }

  if( FD_LIKELY( ctx->open_acc.accepted ) ) {
    if( FD_UNLIKELY( writer_write( &ctx->writer,
                                  ctx->open_acc.file_off+sizeof(fd_accdb_disk_meta_t)+ctx->open_acc.received,
                                  data, data_sz ) ) ) return -1;
  }
  ctx->open_acc.received += data_sz;
  return 0;
}

static int
handle_data_frag( fd_snapin_tile_t *  ctx,
                  ulong               in_idx,
                  ulong               chunk,
                  ulong               sz,
                  fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_FINISHING ) ) {
    FD_LOG_WARNING(( "received unexpected data frag while in state %s (%lu)",
                     fd_ssctrl_state_str( (ulong)ctx->state ), (ulong)ctx->state  ));
    transition_malformed( ctx, stem );
    return 0;
  }
  if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_ERROR ) ) {
    /* Ignore all data frags after observing an error in the stream until
       we receive fail & init control messages to restart processing. */
    return 0;
  }
  if( FD_UNLIKELY( ctx->state!=FD_SNAPSHOT_STATE_PROCESSING ) ) {
    FD_LOG_ERR(( "received data frag during invalid state %s (%lu)",
                 fd_ssctrl_state_str( (ulong)ctx->state ), (ulong)ctx->state ));
  }

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) ) {
    FD_LOG_ERR(( "invalid data frag bounds (chunk=%lu chunk0=%lu wmark=%lu sz=%lu mtu=%lu)", chunk, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark, sz, ctx->in[ in_idx ].mtu ));
  }

  for(;;) {
    if( FD_UNLIKELY( sz-ctx->in[ in_idx ].pos==0UL ) ) break;

    uchar const * data = (uchar const *)fd_chunk_to_laddr_const( ctx->in[ in_idx ].wksp, chunk ) + ctx->in[ in_idx ].pos;

    int early_exit = 0;
    fd_ssparse_advance_result_t result[1];
    int res = fd_ssparse_advance( ctx->ssparse, data, sz-ctx->in[ in_idx ].pos, result );
    switch( res ) {
      case FD_SSPARSE_ADVANCE_ERROR:
        FD_LOG_WARNING(( "error while parsing snapshot stream" ));
        transition_malformed( ctx, stem );
        return 0;
      case FD_SSPARSE_ADVANCE_AGAIN:
        break;
      case FD_SSPARSE_ADVANCE_APPENDVEC: {
        /* Parse only this tile's claimed appendvecs. */
        ulong av_idx = ctx->appendvec_seq++;
        if( FD_UNLIKELY( is_lead( ctx ) ) ) {
          ulong body_sz = result->appendvec.data_sz;
          ctx->av_stats.cnt++;
          ctx->av_stats.bytes += body_sz;
          ctx->av_stats.max_sz = fd_ulong_max( ctx->av_stats.max_sz, body_sz );
          if( FD_UNLIKELY( body_sz>(64UL<<20) ) )  ctx->av_stats.over_64m_cnt++;
          if( FD_UNLIKELY( body_sz>(256UL<<20) ) ) ctx->av_stats.over_256m_bytes += body_sz;
          ctx->av_stats.log2_hist[ fd_ulong_min( (ulong)fd_ulong_find_msb( fd_ulong_max( body_sz, 1UL ) ), 47UL ) ]++;
        }
        if( FD_UNLIKELY( av_idx==ctx->claimed_appendvec ) ) {
          /* Claim the next appendvec before parsing this one. */
          ctx->claimed_appendvec = FD_ATOMIC_FETCH_AND_ADD( &ctx->snoop_hdr->next_appendvec, 1UL );
          ctx->owned_appendvecs++;
          fd_ssparse_appendvec_parse( ctx->ssparse );
          ctx->owned_bytes += result->appendvec.data_sz;
        }
        break;
      }
      case FD_SSPARSE_ADVANCE_REGION:
        /* Ignore non-appendvec headers here. */
        break;
      case FD_SSPARSE_ADVANCE_MANIFEST:
      case FD_SSPARSE_ADVANCE_MANIFEST_DONE: {
        if( FD_LIKELY( !is_lead( ctx ) ) ) break; /* Tile 0 only. */
        if( FD_UNLIKELY( ctx->flags.manifest_done ) ) {
          FD_LOG_WARNING(( "excess data after manifest" ));
          transition_malformed( ctx, stem );
          return 0;
        }
        int parser_res = fd_ssmanifest_parser_consume( ctx->manifest_parser,
                                                       result->manifest.data,
                                                       result->manifest.data_sz );
        if( FD_UNLIKELY( parser_res==FD_SSMANIFEST_PARSER_ADVANCE_ERROR ) ) {
          FD_LOG_WARNING(( "error while parsing snapshot manifest" ));
          transition_malformed( ctx, stem );
          return 0;
        }
        if( res==FD_SSPARSE_ADVANCE_MANIFEST_DONE ) {
          if( FD_UNLIKELY( fd_ssmanifest_parser_fini( ctx->manifest_parser )!=FD_SSMANIFEST_PARSER_ADVANCE_DONE ) ) {
            FD_LOG_WARNING(( "manifest stream ended before parser was done" ));
            transition_malformed( ctx, stem );
            return 0;
          }
          ctx->flags.manifest_done = 1;
        }
        break;
      }
      case FD_SSPARSE_ADVANCE_STATUS_CACHE: {
        if( FD_LIKELY( !is_lead( ctx ) ) ) break; /* Tile 0 only. */
        fd_slot_delta_parser_advance_result_t sd_result[1];
        ulong bytes_remaining = result->status_cache.data_sz;

        while( bytes_remaining ) {
          int res = fd_slot_delta_parser_consume( ctx->slot_delta_parser,
                                                  result->status_cache.data,
                                                  bytes_remaining,
                                                  sd_result );
          if( FD_UNLIKELY( res<0 ) ) {
            FD_LOG_WARNING(( "error while parsing slot deltas in status cache" ));
            transition_malformed( ctx, stem );
            return 0;
          } else if( FD_LIKELY( res==FD_SLOT_DELTA_PARSER_ADVANCE_SLOT ) ) {
            /* If we're parsing a new slot, add th new slot if we
               haven't parsed 151 slots yet.  Otherwise ignore or evict
               slots that are too old.  */
            ulong candidate_idx;
            if( FD_LIKELY( ctx->txncache_slots_len<FD_TXNCACHE_MAX_SLOT_DELTAS ) ) {
              candidate_idx = ctx->txncache_slots_len++;
            } else {
              candidate_idx = 0UL;
              for( ulong i=1UL; i<FD_TXNCACHE_MAX_SLOT_DELTAS; i++ ) {
                if( ctx->txncache_slots[ i ].slot<ctx->txncache_slots[ candidate_idx ].slot ) candidate_idx = i;
              }
              if( FD_UNLIKELY( sd_result->slot<ctx->txncache_slots[ candidate_idx ].slot ) ) candidate_idx = ULONG_MAX;
            }

            if( FD_LIKELY( candidate_idx!=ULONG_MAX ) ) {
              ctx->txncache_slots[ candidate_idx ].slot      = sd_result->slot;
              ctx->txncache_slots[ candidate_idx ].entry_cnt = 0UL;
            }
            ctx->txncache_current_slot_idx       = candidate_idx;
            ctx->txncache_current_slot_entry_cnt = 0UL;
          } else if( FD_LIKELY( res==FD_SLOT_DELTA_PARSER_ADVANCE_GROUP ) ) {
            if( FD_UNLIKELY( ctx->blockhash_groups_len>=FD_SNAPIN_MAX_SLOT_DELTA_GROUPS ) ) {
              FD_LOG_WARNING(( "blockhash groups overflow, max is %lu", FD_SNAPIN_MAX_SLOT_DELTA_GROUPS ));
              transition_malformed( ctx, stem );
              return 0;
            }

            blockhash_group_t * group = &ctx->blockhash_groups[ ctx->blockhash_groups_len++ ];
            memcpy( group->blockhash, sd_result->group.blockhash, 32UL );
            group->slot               = sd_result->group.slot;
            group->txnhash_offset     = sd_result->group.txnhash_offset;
            group->txncache_entry_cnt = 0UL;

            /* Ignore the group if its corresponding slot is too old.
               Otherwise record which entry to start looking at. */
            ulong slot_idx = ctx->txncache_current_slot_idx;
            if( FD_UNLIKELY( slot_idx==ULONG_MAX ) ) {
              group->txncache_entry_idx = ULONG_MAX;
            } else {
              FD_TEST( slot_idx<ctx->txncache_slots_len );
              FD_TEST( ctx->txncache_slots[ slot_idx ].slot==group->slot );
              group->txncache_entry_idx = slot_idx*FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT+ctx->txncache_slots[ slot_idx ].entry_cnt;
            }
          } else if( FD_LIKELY( res==FD_SLOT_DELTA_PARSER_ADVANCE_ENTRY ) ) {
            FD_TEST( ctx->blockhash_groups_len );
            blockhash_group_t * group = &ctx->blockhash_groups[ ctx->blockhash_groups_len-1UL ];
            FD_TEST( group->slot==sd_result->entry->slot );

            if( FD_UNLIKELY( ctx->txncache_current_slot_entry_cnt>=FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT ) ) {
              FD_LOG_WARNING(( "txncache entries overflow for slot %lu, max is %lu",
                               group->slot, FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT ));
              transition_malformed( ctx, stem );
              return 0;
            }
            ctx->txncache_current_slot_entry_cnt++;

            /* Record the entry iff it corresponds to a valid slot. */
            ulong slot_idx = ctx->txncache_current_slot_idx;
            if( FD_LIKELY( slot_idx!=ULONG_MAX ) ) {
              FD_TEST( slot_idx<ctx->txncache_slots_len );
              txncache_staging_slot_t * staging_slot = &ctx->txncache_slots[ slot_idx ];
              FD_TEST( staging_slot->slot==group->slot );
              FD_TEST( staging_slot->entry_cnt<FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT );
              ulong entry_idx = slot_idx*FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT+staging_slot->entry_cnt;
              FD_TEST( entry_idx==group->txncache_entry_idx+group->txncache_entry_cnt );
              memcpy( ctx->txncache_entries[ entry_idx ].txnhash, sd_result->entry->txnhash, sizeof(fd_sstxncache_hash_t) );
              staging_slot->entry_cnt++;
              group->txncache_entry_cnt++;
            }
          }

          bytes_remaining           -= sd_result->bytes_consumed;
          result->status_cache.data += sd_result->bytes_consumed;
        }

        if( FD_UNLIKELY( result->status_cache.done ) ) {
          int fini_res = fd_slot_delta_parser_consume( ctx->slot_delta_parser, result->status_cache.data, 0UL, sd_result );
          if( FD_UNLIKELY( fini_res<0 ) ) {
            FD_LOG_WARNING(( "error while finalizing slot deltas in status cache" ));
            transition_malformed( ctx, stem );
            return 0;
          }
          ctx->flags.status_cache_done = fini_res==FD_SLOT_DELTA_PARSER_ADVANCE_DONE;
        }
        break;
      }
      case FD_SSPARSE_ADVANCE_ACCOUNT_HEADER:
        early_exit = worker_process_account_header( ctx, result );
        if( FD_UNLIKELY( early_exit<0 ) ) {
          transition_malformed( ctx, stem );
          return 0;
        }

        /* TODO: Capture GUI config accounts from every tile. */
        if( FD_UNLIKELY( ctx->gui_out.idx!=ULONG_MAX
                      && !memcmp( result->account_header.owner, fd_solana_config_program_id.key, sizeof(fd_hash_t) )
                      && result->account_header.data_len
                      && result->account_header.data_len<=FD_GUI_CONFIG_PARSE_MAX_VALID_ACCT_SZ ) ) {
          ctx->gui_config_acct_sz  = result->account_header.data_len;
          ctx->gui_config_acct_off = 0UL;
        } else {
          ctx->gui_config_acct_sz  = 0UL;
        }
        break;
      case FD_SSPARSE_ADVANCE_ACCOUNT_DATA:
        early_exit = worker_process_account_data( ctx, result );
        if( FD_UNLIKELY( early_exit<0 ) ) {
          transition_malformed( ctx, stem );
          return 0;
        }

        /* Account data may span multiple input chunks (when an account
           straddles a decompressed chunk boundary), so we copy each
           piece into the gui_out dcache and only publish once the full
           account has been received.

           We expect ConfigKeys Vec to be length 2 (checked via the
           first byte of the accumulated data).  We expect the size of
           ConfigProgram-owned accounts to be at most
           FD_GUI_CONFIG_PARSE_MAX_VALID_ACCT_SZ, since this is the
           size that the Solana CLI allocates for them. Although the
           ConfigProgram itself does not enforce these invariants, the
           vast majority of accounts (with a tiny number of exceptions
           on devnet) are maintained with the Solana CLI. */
        if( FD_UNLIKELY( ctx->gui_config_acct_sz ) ) {
          uchar * acct = fd_chunk_to_laddr( ctx->gui_out.mem, ctx->gui_out.chunk );
          fd_memcpy( acct + ctx->gui_config_acct_off, result->account_data.data, result->account_data.data_sz );
          ctx->gui_config_acct_off += result->account_data.data_sz;

          if( FD_LIKELY( ctx->gui_config_acct_off>=ctx->gui_config_acct_sz ) ) {
            ctx->gui_config_acct_sz = 0UL;
            if( FD_LIKELY( acct[ 0 ]==2UL ) ) {
              fd_stem_publish( stem, ctx->gui_out.idx, 0UL, ctx->gui_out.chunk, ctx->gui_config_acct_off, 0UL, 0UL, 0UL );
              ctx->gui_out.chunk = fd_dcache_compact_next( ctx->gui_out.chunk, ctx->gui_config_acct_off, ctx->gui_out.chunk0, ctx->gui_out.wmark );
              early_exit = 1;
            }
          }
        }
        break;
      case FD_SSPARSE_ADVANCE_ACCOUNT_BATCH:
        early_exit = worker_process_account_batch( ctx, result );
        if( FD_UNLIKELY( early_exit<0 ) ) {
          transition_malformed( ctx, stem );
          return 0;
        }
        break;
      case FD_SSPARSE_ADVANCE_DONE:
        ctx->state = FD_SNAPSHOT_STATE_FINISHING;
        break;
      default:
        FD_LOG_ERR(( "unexpected fd_ssparse_advance result %d", res ));
        break;
    }

    if( FD_UNLIKELY( !ctx->flags.manifest_processed && ctx->flags.manifest_done && ctx->flags.status_cache_done ) ) {
      process_manifest( ctx, stem );
      if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_ERROR ) ) break;
      ctx->flags.manifest_processed = 1;
    }

    ctx->in[ in_idx ].pos += result->bytes_consumed;
    if( FD_LIKELY( ctx->full ) ) ctx->metrics.full_bytes_read        += result->bytes_consumed;
    else                         ctx->metrics.incremental_bytes_read += result->bytes_consumed;

    if( FD_UNLIKELY( early_exit ) ) break;
  }

  int reprocess_frag = ctx->in[ in_idx ].pos<sz;
  if( FD_LIKELY( !reprocess_frag ) ) ctx->in[ in_idx ].pos = 0UL;
  return reprocess_frag;
}

/* Tile 0 final work */

/* Read shared totals and snoop data after all FINI acks. */

static void
tile0_fold_attempt( fd_snapin_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->attempt_folded ) ) return;
  ctx->attempt_folded = 1;

  fd_snapio_totals_t const * totals = &ctx->snoop_hdr->totals;

  /* Each tile ends with one unused claim. */
  FD_TEST( totals->appendvecs_processed==ctx->appendvec_seq );
  FD_TEST( ctx->snoop_hdr->next_appendvec==ctx->appendvec_seq+ctx->snoop_hdr->worker_cnt );

  /* Add this attempt to tile 0's session totals. */
  ctx->totals_fold.accounts_loaded   += totals->accounts_loaded;
  ctx->totals_fold.accounts_replaced += totals->accounts_replaced;
  ctx->totals_fold.accounts_ignored  += totals->accounts_ignored;

  ctx->capitalization = fd_ulong_if( ctx->full, 0UL, ctx->recovery.capitalization );
  ctx->capitalization = fd_ulong_sat_add( ctx->capitalization, totals->input_lamports   );
  ctx->capitalization = fd_ulong_sat_sub( ctx->capitalization, totals->ignored_lamports );
  ctx->dup_capitalization = totals->replaced_lamports;
  ctx->worker_fold.eq_slot_dups          += totals->eq_slot_dups;
  ctx->worker_fold.eq_slot_lamports_diff += totals->eq_slot_lamports_diff;

  /* Read the shared SlotHistory winner. */
  fd_snapio_snoop_hdr_t const * hdr = ctx->snoop_hdr;
  if( FD_LIKELY( hdr->slot_history.captured ) ) {
    ctx->slot_history.captured   = 1;
    ctx->slot_history.slot       = hdr->slot_history.slot;
    ctx->slot_history.lamports   = hdr->slot_history.lamports;
    ctx->slot_history.data_len   = hdr->slot_history.data_len;
    ctx->slot_history.executable = hdr->slot_history.executable;
    fd_memcpy( ctx->slot_history.owner, hdr->slot_history.owner, 32UL );
    fd_memcpy( ctx->slot_history.buf, hdr->slot_history.buf, hdr->slot_history.data_len );
  }

  /* Merge features seen in this attempt. */
  for( ulong i=0UL; i<FD_FEATURE_SNOOP_CNT; i++ ) {
    if( FD_LIKELY( !hdr->feature_snoop.present[ i ] ) ) continue;
    ctx->feature_snoop->present        [ i ] = 1;
    ctx->feature_snoop->is_active      [ i ] = hdr->feature_snoop.is_active      [ i ];
    ctx->feature_snoop->activation_slot[ i ] = hdr->feature_snoop.activation_slot[ i ];
  }
}

/* Log snoop checksums for single-tile comparisons. */

static void
log_snoop_checksums( fd_snapin_tile_t * ctx ) {
  fd_stake_delegations_t * sd = ctx->stake_delegations;
  fd_stake_delegation_t const * root_pool  = fd_type_pun_const( (uchar const *)sd + sd->pool_offset_ );
  fd_stake_delegation_t const * delta_pool = fd_type_pun_const( (uchar const *)sd + sd->delta_pool_offset_ );
  ulong stake_cs  = 0UL;
  ulong stake_cnt = 0UL;
  for( ulong i=0UL; i<sd->pool_idx_wmk_; i++ ) {
    fd_stake_delegation_t const * d = &root_pool[ i ];
    if( !d->in_use ) continue;
    if( d->delta_idx!=UINT_MAX ) d = &delta_pool[ d->delta_idx ];
    if( d->is_tombstone ) continue;
    ulong h = fd_hash( 0x57A4EUL, d->stake_account.uc, 32UL );
    h = fd_hash( h, d->vote_account.uc, 32UL );
    ulong nums[ 6 ] = { d->stake, d->lamports, d->credits_observed,
                        (ulong)d->activation_epoch, (ulong)d->deactivation_epoch, (ulong)d->acc_dlen };
    h = fd_hash( h, nums, sizeof(nums) );
    stake_cs += h; /* order independent */
    stake_cnt++;
  }
  ulong feature_cs = fd_hash( 0xFEA7UL, ctx->feature_snoop, sizeof(fd_feature_snoop_t) );
  ulong sh_cs      = ctx->slot_history.captured ? fd_hash( 0x5107UL, ctx->slot_history.buf, ctx->slot_history.data_len ) : 0UL;
  FD_LOG_NOTICE(( "snoop A/B: stake_cnt=%lu stake_cs=%016lx feature_cs=%016lx slot_history_slot=%lu slot_history_cs=%016lx",
                  stake_cnt, stake_cs, feature_cs, ctx->slot_history.captured ? ctx->slot_history.slot : 0UL, sh_cs ));
}

/* Log appendvec sizes that limit parallel speed. */

static void
log_appendvec_stats( fd_snapin_tile_t * ctx ) {
  if( FD_UNLIKELY( !ctx->av_stats.cnt ) ) return;

  /* Use the top of each log2 bucket. */
  ulong p50 = 0UL, p90 = 0UL;
  ulong seen = 0UL;
  for( ulong b=0UL; b<48UL; b++ ) {
    seen += ctx->av_stats.log2_hist[ b ];
    if( !p50 && seen*2UL >=      ctx->av_stats.cnt ) p50 = 2UL<<b;
    if( !p90 && seen*10UL>= 9UL*ctx->av_stats.cnt  ) p90 = 2UL<<b;
  }
  FD_LOG_NOTICE(( "appendvecs: cnt=%lu total=%.1f GiB avg=%.1f MiB p50<=%lu p90<=%lu max=%lu, >64MiB cnt=%lu, >256MiB bytes=%.1f GiB",
                  ctx->av_stats.cnt,
                  (double)ctx->av_stats.bytes/(double)(1UL<<30),
                  (double)ctx->av_stats.bytes/(double)ctx->av_stats.cnt/(double)(1UL<<20),
                  p50, p90, ctx->av_stats.max_sz,
                  ctx->av_stats.over_64m_cnt,
                  (double)ctx->av_stats.over_256m_bytes/(double)(1UL<<30) ));
}

/* Roll back after every tile has sent its FAIL ack. */

static void
tile0_rollback_failed_attempt( fd_snapin_tile_t * ctx,
                               int                retry_full ) {
  ctx->rollback.pending = 0;

  /* Save failed partitions until purge or reset finishes. */
  for( ulong w=0UL; w<ctx->tile_cnt; w++ ) {
    fd_snapio_worker_t * ws = ctx->snoops[ w ];
    for( ulong i=0UL; i<ws->fail_partition_cnt; i++ ) {
      FD_TEST( ctx->doomed_partition_cnt<FD_SNAPIO_FAIL_PARTITION_MAX );
      ctx->doomed_partitions[ ctx->doomed_partition_cnt++ ] = ws->fail_partitions[ i ];
    }
    ws->fail_partition_cnt = 0UL;
  }

  if( !ctx->rollback.full ) {
    /* Purge failed incremental state unless a full reset follows. */
    if( FD_LIKELY( !retry_full ) ) fd_accdb_purge( ctx->accdb, ctx->rollback.fork );
    *ctx->feature_snoop = ctx->recovery.feature_snoop;
  } else {
    /* A failed full load must retry as full. */
    FD_TEST( retry_full );
  }
}

/* Only a completed INIT has valid state to roll back. */

static void
tile0_defer_rollback( fd_snapin_tile_t * ctx ) {
  if( FD_LIKELY( ctx->init_completed ) ) {
    ctx->rollback.pending = 1;
    ctx->rollback.full    = ctx->full;
    ctx->rollback.fork    = ctx->accdb_incr_fork_id;
    if( ctx->full ) ctx->accdb_root_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
    ctx->accdb_incr_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  }
  ctx->init_completed = 0;
}

/* Tile 0 prepares shared state, then publishes the attempt slot. */

static void
tile0_init_attempt( fd_snapin_tile_t * ctx,
                    ulong              in_idx,
                    ulong              chunk ) {
  /* Roll back before publishing this attempt. */
  if( FD_UNLIKELY( ctx->rollback.pending ) ) tile0_rollback_failed_attempt( ctx, ctx->full );

  ctx->blockhash_groups_len    = 0UL;
  ctx->manifest_capitalization = 0UL;
  ctx->txncache_slots_len      = 0UL;
  ctx->attempt_folded          = 0;
  fd_memset( &ctx->worker_fold, 0, sizeof(ctx->worker_fold) );
  fd_memset( &ctx->av_stats,    0, sizeof(ctx->av_stats)    );

  fd_txncache_reset( ctx->txncache );
  fd_ssmanifest_parser_init( ctx->manifest_parser, fd_chunk_to_laddr( ctx->manifest_out.mem, ctx->manifest_out.chunk ) );
  fd_slot_delta_parser_init( ctx->slot_delta_parser );

  /* Rewind metric counters (no-op unless recovering from a fail) */
  if( ctx->full ) {
    fd_memset( &ctx->totals_fold, 0, sizeof(ctx->totals_fold) );
    ctx->full_genesis_creation_time_seconds = 0UL;
    ctx->capitalization          = 0UL;
    ctx->dup_capitalization      = 0UL;
    ctx->recovery.capitalization = 0UL;

    fd_stake_delegations_reset( ctx->stake_delegations );
    fd_accdb_reset( ctx->accdb );
    /* Reset also releases failed partitions. */
    ctx->doomed_partition_cnt = 0UL;
    fd_accdb_fork_id_t null_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
    ctx->accdb_root_fork_id = fd_accdb_attach_child( ctx->accdb, null_fork_id );

    fd_accdb_snapshot_load_begin( ctx->accdb );

    ctx->slot_history.captured = 0;

    fd_memset( ctx->feature_snoop, 0, sizeof(ctx->feature_snoop) );
  } else {
    ctx->capitalization     = ctx->recovery.capitalization;
    ctx->dup_capitalization = 0UL;

    /* Discard stale capture so the retry's sysvar is snooped fresh */
    ctx->slot_history.captured = 0;

    /* Create a child fork for incremental writes.  On failure,
       fd_accdb_purge(child) reverts just the incremental changes.
       On success, fd_accdb_advance_root(child) promotes them. */
    ctx->accdb_incr_fork_id = fd_accdb_attach_child( ctx->accdb, ctx->accdb_root_fork_id );

    /* Purge is done. Reuse the failed attempt's partitions. */
    if( FD_UNLIKELY( ctx->doomed_partition_cnt ) ) {
      fd_accdb_snapshot_worker_release_partitions( ctx->accdb, ctx->doomed_partitions, ctx->doomed_partition_cnt );
      ctx->doomed_partition_cnt = 0UL;
    }
  }

  /* Save the slot advertised by the snapshot peer and verify it
     against the slot in the snapshot manifest.  For redirect-based
     HTTP downloads, these are initial estimates from gossip and
     will be updated by the META message below once the redirect
     resolves to a concrete snapshot filename. */
  fd_ssctrl_init_t const * msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].wksp, chunk );
  ctx->advertised_slot = msg->slot;
  fd_memcpy( ctx->advertised_hash, msg->snapshot_hash, FD_HASH_FOOTPRINT );
  ctx->init_completed = 1;

  /* Reset shared state before publishing the attempt slot. */
  fd_snapio_snoop_hdr_t * hdr = ctx->snoop_hdr;
  fd_memset( &hdr->totals,        0, sizeof(hdr->totals)        );
  fd_memset( &hdr->slot_history,  0, sizeof(hdr->slot_history)  );
  fd_memset( &hdr->feature_snoop, 0, sizeof(hdr->feature_snoop) );
  FD_VOLATILE( hdr->next_appendvec ) = 0UL;
  FD_COMPILER_MFENCE();

  /* Publish last. Other tiles wait for this. */
  FD_VOLATILE( hdr->attempt.fork_id ) = ctx->full ? (ulong)USHORT_MAX : (ulong)ctx->accdb_incr_fork_id.val;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->attempt.generation ) = ctx->generation;
}

/* Attempt slot gate */

/* Tile 0 publishes the slot after INIT work.
   Other tiles hold DATA until then.
   Controls still pass, so ERROR and FAIL can cancel the attempt. */

static void
attempt_gate_open( fd_snapin_tile_t * ctx ) {
  FD_COMPILER_MFENCE();
  FD_TEST( FD_VOLATILE_CONST( ctx->snoop_hdr->attempt.generation )==ctx->generation );
  ctx->incr_fork = FD_VOLATILE_CONST( ctx->snoop_hdr->attempt.fork_id );
  if( FD_UNLIKELY( ctx->full ? ctx->incr_fork!=(ulong)USHORT_MAX : ctx->incr_fork>=(ulong)USHORT_MAX ) ) {
    FD_LOG_ERR(( "invalid attempt fork %lu (full=%d); this is a bug", ctx->incr_fork, (int)ctx->full ));
  }
  writer_begin( &ctx->writer );
  fd_accdb_snapshot_writer_begin( ctx->accdb );

  /* Claim before the first data fragment. */
  ctx->claimed_appendvec = FD_ATOMIC_FETCH_AND_ADD( &ctx->snoop_hdr->next_appendvec, 1UL );
  ctx->gate_pending      = 0;
}

/* Returns 1 when writes may start. */

static inline int
attempt_gate_ready( fd_snapin_tile_t * ctx ) {
  if( FD_LIKELY( !ctx->gate_pending ) ) return 1;
  if( FD_UNLIKELY( FD_VOLATILE_CONST( ctx->snoop_hdr->attempt.generation )!=ctx->generation ) ) {
    long now = fd_log_wallclock();
    if( FD_UNLIKELY( now>=ctx->gate_warn_ts ) ) {
      ctx->gate_warn_ts = now + FD_SNAPIN_GATE_WARN_NS;
      FD_LOG_WARNING(( "tile %lu holding snapshot data: attempt slot for generation %lu not published yet (slot holds %lu)",
                       ctx->tile_idx, ctx->generation, FD_VOLATILE_CONST( ctx->snoop_hdr->attempt.generation ) ));
    }
    return 0;
  }
  attempt_gate_open( ctx );
  return 1;
}

static void
handle_control_frag( fd_snapin_tile_t *  ctx,
                     fd_stem_context_t * stem,
                     ulong               in_idx,
                     ulong               sig,
                     ulong               chunk,
                     ulong               sz ) {
  if( ctx->state==FD_SNAPSHOT_STATE_ERROR && sig!=FD_SNAPSHOT_MSG_CTRL_FAIL ) {
    /* Control messages move along the snapshot load pipeline.  Since
       error conditions can be triggered by any tile in the pipeline,
       it is possible to be in error state and still receive otherwise
       valid messages.  Only a fail message can revert this. */
    return;
  };

  int forward_msg = 1;

  switch( sig ) {
    case FD_SNAPSHOT_MSG_CTRL_INIT_FULL:
    case FD_SNAPSHOT_MSG_CTRL_INIT_INCR: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      /* Generation was bumped at the first INIT fragment. */
      ctx->state = FD_SNAPSHOT_STATE_PROCESSING;
      ctx->full = sig==FD_SNAPSHOT_MSG_CTRL_INIT_FULL;

      worker_reset_attempt( ctx );
      fd_memset( &ctx->flags, 0, sizeof(ctx->flags) );
      if( ctx->full ) ctx->metrics.full_bytes_read = 0UL;
      ctx->metrics.incremental_bytes_read = 0UL;

      /* Full loads start at zero.
         Incremental loads start from saved full counts. */
      if( ctx->full ) {
        ctx->metrics.accounts_loaded        = 0UL;
        ctx->metrics.accounts_replaced      = 0UL;
        ctx->metrics.accounts_ignored       = 0UL;
        ctx->metrics.full_accounts_loaded   = 0UL;
        ctx->metrics.full_accounts_replaced = 0UL;
        ctx->metrics.full_accounts_ignored  = 0UL;
      } else {
        ctx->metrics.accounts_loaded   = ctx->metrics.full_accounts_loaded;
        ctx->metrics.accounts_replaced = ctx->metrics.full_accounts_replaced;
        ctx->metrics.accounts_ignored  = ctx->metrics.full_accounts_ignored;
      }

      if( FD_UNLIKELY( is_lead( ctx ) ) ) tile0_init_attempt( ctx, in_idx, chunk );

      /* Tile 0 opens now. Other tiles open in before_frag. */
      ctx->gate_pending = 1;
      ctx->gate_warn_ts = fd_log_wallclock() + FD_SNAPIN_GATE_WARN_NS;
      if( FD_UNLIKELY( is_lead( ctx ) ) ) attempt_gate_open( ctx );
      break;
    }

    case FD_SNAPSHOT_MSG_META: {
      /* For redirect-based HTTP downloads, the META message carries
         the resolved slot and hash from the actual snapshot filename
         the server redirected to.  Update the advertised values so
         that process_manifest can verify the manifest against them. */
      FD_TEST( sz==sizeof(fd_ssctrl_meta_t) );
      fd_ssctrl_meta_t const * meta = fd_chunk_to_laddr_const( ctx->in[ in_idx ].wksp, chunk );
      if( meta->resolved_slot!=ULONG_MAX ) {
        ctx->advertised_slot = meta->resolved_slot;
        fd_memcpy( ctx->advertised_hash, meta->resolved_hash, FD_HASH_FOOTPRINT );
      }
      forward_msg = 0; /* snapct already receives META directly from snapld */
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_FINI: {
      /* This is a special case: handle_data_frag must have already
         processed FD_SSPARSE_ADVANCE_DONE and moved the state into
         FD_SNAPSHOT_STATE_FINISHING.  Otherwise, treat this as a
         malformed snapshot so that the pipeline can retry. */
      if( FD_UNLIKELY( ctx->state!=FD_SNAPSHOT_STATE_FINISHING ) ) {
        FD_LOG_WARNING(( "received FINI while in state %s (%lu), expected FINISHING (possibly truncated tar stream)",
                         fd_ssctrl_state_str( (ulong)ctx->state ), (ulong)ctx->state ));
        transition_malformed( ctx, stem );
        forward_msg = 0;
        break;
      }

      /* Flush records before the FINI ack. */
      if( FD_UNLIKELY( writer_end( &ctx->writer ) ) ) {
        transition_malformed( ctx, stem );
        forward_msg = 0;
        break;
      }
      fd_accdb_snapshot_worker_close( ctx->accdb, &ctx->whead );
      fd_accdb_snapshot_writer_end( ctx->accdb );
      fd_accdb_snapshot_flush_worker_metrics( ctx->accdb, ctx->worker_metrics );

      FD_LOG_NOTICE(( "snapin %lu: owned appendvecs=%lu owned_bytes=%lu bytes_written=%lu",
                      ctx->tile_idx, ctx->owned_appendvecs, ctx->owned_bytes, ctx->writer.bytes_written ));
      if( FD_UNLIKELY( is_lead( ctx ) ) ) log_appendvec_stats( ctx );

      /* Agave accepts equal-slot duplicates. */

      /* Add this tile's counters before the FINI ack. */
      fd_snapio_totals_t * totals = &ctx->snoop_hdr->totals;
      FD_ATOMIC_FETCH_AND_ADD( &totals->accounts_loaded,       ctx->worker.accounts_loaded                );
      FD_ATOMIC_FETCH_AND_ADD( &totals->accounts_replaced,     ctx->worker.accounts_replaced              );
      FD_ATOMIC_FETCH_AND_ADD( &totals->accounts_ignored,      ctx->worker.accounts_ignored               );
      FD_ATOMIC_FETCH_AND_ADD( &totals->input_lamports,        ctx->worker.input_lamports                 );
      FD_ATOMIC_FETCH_AND_ADD( &totals->replaced_lamports,     ctx->worker.replaced_lamports              );
      FD_ATOMIC_FETCH_AND_ADD( &totals->ignored_lamports,      ctx->worker.ignored_lamports               );
      FD_ATOMIC_FETCH_AND_ADD( &totals->eq_slot_dups,          ctx->worker_metrics->eq_slot_dups          );
      FD_ATOMIC_FETCH_AND_ADD( &totals->eq_slot_lamports_diff, ctx->worker_metrics->eq_slot_lamports_diff );
      FD_ATOMIC_FETCH_AND_ADD( &totals->appendvecs_processed,  ctx->owned_appendvecs                      );
      FD_COMPILER_MFENCE(); /* publish before ack */

      /* Keep per-tile gauges. Dashboards sum them. */
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_NEXT: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_FINISHING );
      ctx->state = FD_SNAPSHOT_STATE_IDLE;

      /* Save this tile's full-snapshot counts. */
      ctx->metrics.full_accounts_loaded   = ctx->metrics.accounts_loaded;
      ctx->metrics.full_accounts_replaced = ctx->metrics.accounts_replaced;
      ctx->metrics.full_accounts_ignored  = ctx->metrics.accounts_ignored;

      if( FD_LIKELY( !is_lead( ctx ) ) ) break;

      /* FINI acks make shared data stable. */
      tile0_fold_attempt( ctx );

      if( FD_UNLIKELY( verify_slot_deltas_with_slot_history( ctx ) ) ) {
        FD_LOG_WARNING(( "slot deltas verification failed for full snapshot" ));
        transition_malformed( ctx, stem );
        forward_msg = 0;
        break;
      }

      ctx->capitalization = fd_ulong_sat_sub( ctx->capitalization, ctx->dup_capitalization );
      if( FD_UNLIKELY( validate_capitalization( ctx )!=0 ) ) {
        transition_malformed( ctx, stem );
        forward_msg = 0;
        break;
      }

      ctx->recovery.capitalization = ctx->capitalization;
      ctx->recovery.feature_snoop = *ctx->feature_snoop;
      ctx->init_completed = 0;
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_DONE: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_FINISHING );
      ctx->state = FD_SNAPSHOT_STATE_IDLE;
      if( FD_LIKELY( !is_lead( ctx ) ) ) break;

      tile0_fold_attempt( ctx );

      if( FD_UNLIKELY( verify_slot_deltas_with_slot_history( ctx ) ) ) {
        if( ctx->full ) FD_LOG_WARNING(( "slot deltas verification failed for full snapshot" ));
        else            FD_LOG_WARNING(( "slot deltas verification failed for incremental snapshot" ));
        transition_malformed( ctx, stem );
        forward_msg = 0;
        break;
      }

      ctx->capitalization = fd_ulong_sat_sub( ctx->capitalization, ctx->dup_capitalization );
      if( FD_UNLIKELY( validate_capitalization( ctx )!=0 ) ) {
        transition_malformed( ctx, stem );
        forward_msg = 0;
        break;
      }

      /* Verify disk reads before advance_root recycles old entries. */
      fd_accdb_snapshot_verify_readback( ctx->accdb, 100000UL );

      if( !ctx->full ) {
        fd_accdb_snapshot_recover_delta( ctx->accdb, ctx->accdb_incr_fork_id );
        /* ensure that snapin tile sees all delta changes before rooting */
        __atomic_thread_fence( __ATOMIC_SEQ_CST );
        fd_accdb_advance_root( ctx->accdb, ctx->accdb_incr_fork_id );
        ctx->accdb_root_fork_id = ctx->accdb_incr_fork_id;
        ctx->accdb_incr_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
      }

      fd_accdb_snapshot_load_end( ctx->accdb );

      fd_feature_snoop_finalize( &ctx->bank->f.features, ctx->bank_slot, &ctx->epoch_schedule, ctx->feature_snoop );

      FD_LOG_NOTICE(( "parallel loader: equal-slot cross-appendvec dups=%lu (lamports-diff=%lu)",
                      ctx->worker_fold.eq_slot_dups, ctx->worker_fold.eq_slot_lamports_diff ));
      if( FD_UNLIKELY( ctx->worker_fold.eq_slot_dups ) ) {
        FD_LOG_WARNING(( "parallel loader: accepted %lu equal-slot cross-appendvec duplicates (lamports-diff=%lu); "
                         "stripe-lock arrival order picked the winner",
                         ctx->worker_fold.eq_slot_dups, ctx->worker_fold.eq_slot_lamports_diff ));
      }
      log_snoop_checksums( ctx );

      /* Notify replay when snapshot is fully loaded and verified. */
      fd_stem_publish( stem, ctx->manifest_out.idx, fd_ssmsg_sig( FD_SSMSG_DONE ), 0UL, 0UL, 0UL, 0UL, 0UL );
      ctx->init_completed = 0;
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_ERROR: {
      FD_TEST( ctx->state!=FD_SNAPSHOT_STATE_SHUTDOWN );
      ctx->state = FD_SNAPSHOT_STATE_ERROR;
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_FAIL: {
      FD_TEST( ctx->state!=FD_SNAPSHOT_STATE_SHUTDOWN );
      /* Drop buffered data and save failed partitions. */
      writer_abort( &ctx->writer );
      fd_accdb_snapshot_worker_close( ctx->accdb, &ctx->whead );
      fd_accdb_snapshot_flush_worker_metrics( ctx->accdb, ctx->worker_metrics );
      ctx->my_snoop->fail_partition_cnt = ctx->whead.attempt_partition_cnt;
      FD_COMPILER_MFENCE(); /* publish before ack */
      worker_reset_attempt( ctx );
      fd_accdb_snapshot_writer_end( ctx->accdb );

      /* Tile 0 rolls back at the next INIT, after all FAIL acks. */
      if( FD_UNLIKELY( is_lead( ctx ) ) ) tile0_defer_rollback( ctx );

      ctx->state = FD_SNAPSHOT_STATE_IDLE;
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      ctx->state = FD_SNAPSHOT_STATE_SHUTDOWN;
      break;
    }

    default: {
      FD_LOG_ERR(( "unexpected control frag %s (%lu) in state %s (%lu)",
                   fd_ssctrl_msg_ctrl_str( sig ), sig,
                   fd_ssctrl_state_str( (ulong)ctx->state ), (ulong)ctx->state ));
      break;
    }
  }

  /* Forward the control message down the pipeline */
  if( FD_LIKELY( forward_msg ) ) {
    fd_stem_publish( stem, ctx->ct_out.idx, sig, 0UL, 0UL, 0UL, 0UL, 0UL );
  }
}

static inline int
all_controls_seen( fd_snapin_tile_t const * ctx ) {
  int all_seen = 1;
  for( ulong i=0UL; i<ctx->lane_cnt; i++ ) {
    all_seen &= !!ctx->control_seen[ i ];
  }
  return all_seen;
}

static inline int
before_frag( fd_snapin_tile_t * ctx,
             ulong              in_idx,
             ulong              seq    FD_PARAM_UNUSED,
             ulong              sig ) {
  /* If we're currently in ERROR state we should only process FAIL
     control frags */
  if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_ERROR ) ) {
    return sig!=FD_SNAPSHOT_MSG_CTRL_FAIL;
  }

  if( FD_UNLIKELY( sig==FD_SNAPSHOT_MSG_CTRL_ERROR ) ) {
    return 0;
  }

  /* Once this lane sends the pending control, hold its later frags
     until all snapdc lanes send the same control. */
  if( FD_UNLIKELY( ctx->pending_control!=ULONG_MAX && ctx->control_seen[ in_idx ] ) ) {
    FD_TEST( sig!=ctx->pending_control );
    return -1;
  }

  if( FD_UNLIKELY( sig==FD_SNAPSHOT_MSG_DATA ) ) {
    /* Only accept DATA frags from the expected lane */
    if( FD_UNLIKELY( in_idx!=ctx->expected_frame%ctx->lane_cnt ) ) return -1;

    /* Wait for tile 0. Controls still pass. */
    if( FD_UNLIKELY( !attempt_gate_ready( ctx ) ) ) return -1;
  }

  return 0;
}

static inline int
handle_lane_data_frag( fd_snapin_tile_t *  ctx,
                       fd_stem_context_t * stem,
                       ulong               in_idx,
                       ulong               chunk,
                       ulong               sz,
                       ulong               ctl ) {
  /* EOM marks the end of a frame */
  int eom = !!fd_frag_meta_ctl_eom( ctl );

  /* The tar parser can reach EOF before snapdc reports the end of the
     zstd frame.  Only the empty EOM is valid (any payload after EOF is
     malformed). */
  int trailing_eom = ctx->state==FD_SNAPSHOT_STATE_FINISHING && eom && !sz;
  if( FD_UNLIKELY( !trailing_eom && handle_data_frag( ctx, in_idx, chunk, sz, stem ) ) ) {
    return 1;
  }

  if( FD_UNLIKELY( eom ) ) {
    ctx->expected_frame++;
  }

  return 0;
}

static inline void
handle_control_barrier( fd_snapin_tile_t *  ctx,
                        fd_stem_context_t * stem,
                        ulong               in_idx,
                        ulong               sig,
                        ulong               chunk,
                        ulong               sz ) {
  /* Error control frags must be immediately handled. */
  if( FD_UNLIKELY( sig==FD_SNAPSHOT_MSG_CTRL_ERROR ) ) {
    handle_control_frag( ctx, stem, in_idx, sig, chunk, sz );
    return;
  }

  if( FD_UNLIKELY( sig!=ctx->pending_control ) ) {
    FD_TEST( ctx->pending_control==ULONG_MAX || sig==FD_SNAPSHOT_MSG_CTRL_FAIL );
    clear_control_barrier( ctx );
    ctx->pending_control = sig;

    /* Bump on the first INIT fragment, even if ERROR stops the barrier. */
    if( FD_UNLIKELY( sig==FD_SNAPSHOT_MSG_CTRL_INIT_FULL || sig==FD_SNAPSHOT_MSG_CTRL_INIT_INCR ) ) {
      ctx->generation++;
    }
  }

  /* Only process the control frag when all upstream tiles have sent
     the same control message. */
  FD_TEST( !ctx->control_seen[ in_idx ] );
  ctx->control_seen[ in_idx ] = 1U;
  if( FD_LIKELY( !all_controls_seen( ctx ) ) ) {
    return;
  }

  /* All controls received, process the control frag. */
  clear_control_barrier( ctx );
  handle_control_frag( ctx, stem, in_idx, sig, chunk, sz );
}

static inline int
returnable_frag( fd_snapin_tile_t *  ctx,
                 ulong               in_idx,
                 ulong               seq    FD_PARAM_UNUSED,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig FD_PARAM_UNUSED,
                 ulong               tspub  FD_PARAM_UNUSED,
                 fd_stem_context_t * stem ) {
  FD_TEST( ctx->state!=FD_SNAPSHOT_STATE_SHUTDOWN );

  if( FD_UNLIKELY( sig==FD_SNAPSHOT_MSG_DATA ) ) return handle_lane_data_frag( ctx, stem, in_idx, chunk, sz, ctl );
  else                                           handle_control_barrier( ctx, stem, in_idx, sig, chunk, sz );

  return 0;
}

static ulong
populate_allowed_fds( fd_topo_t      const * topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "invalid out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2UL; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) {
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  }
  out_fds[ out_cnt++ ] = FD_ACCDB_FD_RW; /* accounts db */

  return out_cnt;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo; (void)tile;
  populate_sock_filter_policy_fd_snapin_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), FD_ACCDB_FD_RW );
  return sock_filter_policy_fd_snapin_tile_instr_cnt;
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  fd_snapin_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( ctx, 0, sizeof(fd_snapin_tile_t) );
  FD_TEST( fd_rng_secure( &ctx->seed, 8UL ) );
}

static inline fd_snapin_out_link_t
out1( fd_topo_t const *      topo,
      fd_topo_tile_t const * tile,
      char const *           name,
      ulong                  kind_id ) {
  ulong idx = fd_topo_find_tile_out_link( topo, tile, name, kind_id );

  if( FD_UNLIKELY( idx==ULONG_MAX ) ) return (fd_snapin_out_link_t){ .idx = ULONG_MAX, .mem = NULL, .chunk0 = 0, .wmark = 0, .chunk = 0, .mtu = 0 };

  ulong mtu = topo->links[ tile->out_link_id[ idx ] ].mtu;
  if( FD_UNLIKELY( mtu==0UL ) ) return (fd_snapin_out_link_t){ .idx = idx, .mem = NULL, .chunk0 = ULONG_MAX, .wmark = ULONG_MAX, .chunk = ULONG_MAX, .mtu = mtu };

  void * mem   = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ulong chunk0 = fd_dcache_compact_chunk0( mem, topo->links[ tile->out_link_id[ idx ] ].dcache );
  ulong wmark  = fd_dcache_compact_wmark ( mem, topo->links[ tile->out_link_id[ idx ] ].dcache, mtu );
  return (fd_snapin_out_link_t){ .idx = idx, .mem = mem, .chunk0 = chunk0, .wmark = wmark, .chunk = chunk0, .mtu = mtu };
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapin_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapin_tile_t), sizeof(fd_snapin_tile_t) );
  void * _accdb          = FD_SCRATCH_ALLOC_APPEND( l, fd_accdb_align(),          fd_accdb_footprint( tile->snapin.max_live_slots ) );

  ctx->tile_idx = tile->kind_id;
  if( FD_UNLIKELY( ctx->tile_idx>=FD_TOPO_MAX_TILE_IN_LINKS ) ) {
    FD_LOG_ERR(( "tile `" NAME "` has unsupported kind id %lu", tile->kind_id ));
  }
  ctx->full            = 1;
  ctx->init_completed  = 0;
  ctx->state           = FD_SNAPSHOT_STATE_IDLE;
  ctx->lane_cnt        = tile->in_cnt;
  ctx->generation      = 0UL;
  ctx->expected_frame  = 0UL;
  clear_control_barrier( ctx );
  fd_memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  void * _accdb_shmem = fd_topo_obj_laddr( topo, tile->snapin.accdb_obj_id );
  fd_accdb_shmem_t * accdb_shmem = fd_accdb_shmem_join( _accdb_shmem );
  FD_TEST( accdb_shmem );
  ctx->accdb = fd_accdb_join( fd_accdb_new( _accdb, accdb_shmem, FD_ACCDB_FD_RW, 0UL, NULL ) );
  FD_TEST( ctx->accdb );

  fd_snapio_snoop_hdr_t * snoop_hdr = fd_snapio_snoop_join( fd_topo_obj_laddr( topo, tile->snapin.snoop_obj_id ) );
  FD_TEST( snoop_hdr );
  FD_TEST( snoop_hdr->worker_cnt<=FD_TOPO_MAX_TILE_IN_LINKS );
  FD_TEST( ctx->tile_idx<snoop_hdr->worker_cnt );
  ctx->snoop_hdr     = snoop_hdr;
  ctx->tile_cnt      = snoop_hdr->worker_cnt;
  ctx->stripe_locks  = fd_snapio_snoop_stripes( snoop_hdr );
  ctx->my_snoop      = fd_snapio_snoop_worker( snoop_hdr, ctx->tile_idx );
  if( FD_UNLIKELY( is_lead( ctx ) ) ) {
    for( ulong w=0UL; w<ctx->tile_cnt; w++ ) ctx->snoops[ w ] = fd_snapio_snoop_worker( snoop_hdr, w );
  }

  /* Store failed partitions in shared staging. */
  ctx->whead.attempt_partitions    = ctx->my_snoop->fail_partitions;
  ctx->whead.attempt_partition_cnt = 0UL;
  ctx->whead.attempt_partition_max = FD_SNAPIO_FAIL_PARTITION_MAX;

  /* Every tile updates stakes. Only tile 0 owns the bank. */
  ctx->banks = fd_banks_join( fd_topo_obj_laddr( topo, tile->snapin.banks_obj_id ) );
  FD_TEST( ctx->banks );
  ctx->stake_delegations = fd_banks_stake_delegations_root_query( ctx->banks );
  FD_TEST( ctx->stake_delegations );

  if( FD_UNLIKELY( is_lead( ctx ) ) ) {
    void * _txncache        = FD_SCRATCH_ALLOC_APPEND( l, fd_txncache_align(),           fd_txncache_footprint( tile->snapin.max_live_slots )        );
    void * _manifest_parser = FD_SCRATCH_ALLOC_APPEND( l, fd_ssmanifest_parser_align(),  fd_ssmanifest_parser_footprint()                            );
    void * _sd_parser       = FD_SCRATCH_ALLOC_APPEND( l, fd_slot_delta_parser_align(),  fd_slot_delta_parser_footprint()                            );
    ctx->blockhash_groups   = FD_SCRATCH_ALLOC_APPEND( l, alignof(blockhash_group_t),    sizeof(blockhash_group_t)*FD_SNAPIN_MAX_SLOT_DELTA_GROUPS   );
    ctx->txncache_entries   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sstxncache_hash_t), sizeof(fd_sstxncache_hash_t)*FD_SNAPIN_TXNCACHE_MAX_ENTRIES );

    void * _txncache_shmem = fd_topo_obj_laddr( topo, tile->snapin.txncache_obj_id );
    fd_txncache_shmem_t * txncache_shmem = fd_txncache_shmem_join( _txncache_shmem );
    FD_TEST( txncache_shmem );
    ctx->txncache = fd_txncache_join( fd_txncache_new( _txncache, txncache_shmem ) );
    FD_TEST( ctx->txncache );

    ctx->bank = fd_banks_init_bank( ctx->banks );
    FD_TEST( ctx->bank );
    FD_TEST( ctx->bank->idx==0UL );

    ctx->manifest_parser = fd_ssmanifest_parser_join( fd_ssmanifest_parser_new( _manifest_parser ) );
    FD_TEST( ctx->manifest_parser );

    ctx->slot_delta_parser = fd_slot_delta_parser_join( fd_slot_delta_parser_new( _sd_parser ) );
    FD_TEST( ctx->slot_delta_parser );
  }

  uchar * write_buf = FD_SCRATCH_ALLOC_APPEND( l, 4096UL, FD_SNAPIN_WRITE_BUF_SZ );
  writer_init( &ctx->writer, FD_ACCDB_FD_RW, write_buf );

  ctx->alpenglow = tile->snapin.alpenglow;
  ctx->blockhash_groups_len = 0UL;

  ctx->ct_out       = out1( topo, tile, "snapin_ct",    ctx->tile_idx );
  ctx->manifest_out = out1( topo, tile, "snapin_manif", 0UL           );
  ctx->gui_out      = out1( topo, tile, "snapin_gui",   0UL           );

  if( FD_UNLIKELY( ctx->ct_out.idx==ULONG_MAX ) ) FD_LOG_ERR(( "tile `" NAME ":%lu` missing required out link `snapin_ct`", ctx->tile_idx ));
  if( FD_UNLIKELY( is_lead( ctx ) && ctx->manifest_out.idx==ULONG_MAX ) ) FD_LOG_ERR(( "tile `" NAME "` missing required out link `snapin_manif`" ));

  if( FD_UNLIKELY( is_lead( ctx ) ) ) {
    fd_ssmanifest_parser_init( ctx->manifest_parser, fd_chunk_to_laddr( ctx->manifest_out.mem, ctx->manifest_out.chunk ) );
    fd_slot_delta_parser_init( ctx->slot_delta_parser );
  }

  for( ulong i=0UL; i<ctx->lane_cnt; i++ ) {
    fd_topo_link_t const * in_link = &topo->links[ tile->in_link_id[ i ] ];
    FD_TEST( 0==strcmp( in_link->name, "snapdc_in" ) );
    FD_TEST( in_link->kind_id==i );
    fd_topo_wksp_t const * in_wksp = &topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ];
    ctx->in[ i ].wksp   = in_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].wksp, in_link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark( ctx->in[ i ].wksp, in_link->dcache, in_link->mtu );
    ctx->in[ i ].mtu    = in_link->mtu;
    ctx->in[ i ].pos    = 0UL;
  }
  if( FD_UNLIKELY( !ctx->lane_cnt || ctx->lane_cnt>FD_SNAPIN_IO_LANE_MAX ) ) {
    FD_LOG_ERR(( "tile `" NAME ":%lu` has %lu snapshot data lanes, expected 1..%lu", ctx->tile_idx, ctx->lane_cnt, FD_SNAPIN_IO_LANE_MAX ));
  }

  worker_reset_attempt( ctx );

  ctx->gui_config_acct_sz  = 0UL;
  ctx->gui_config_acct_off = 0UL;

  ctx->advertised_slot = 0UL;
  ctx->bank_slot       = 0UL;
  ctx->epoch           = 0UL;

  ctx->full_genesis_creation_time_seconds = 0UL;
  ctx->manifest_capitalization            = 0UL;
  ctx->capitalization                     = 0UL;
  ctx->dup_capitalization                 = 0UL;
  ctx->recovery.capitalization            = 0UL;

  ctx->attempt_folded = 0;
  fd_memset( &ctx->worker_fold, 0, sizeof(ctx->worker_fold) );
  fd_memset( &ctx->av_stats,    0, sizeof(ctx->av_stats)    );
  ctx->doomed_partition_cnt = 0UL;

  ctx->accdb_root_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  ctx->accdb_incr_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };

  fd_memset( &ctx->flags, 0, sizeof(ctx->flags) );
  ctx->boot_timestamp = fd_log_wallclock();
}

/* There are 3 output links that affect the calculation of STEM_BURST:
    1. snapin_ct    - worst case: 1 message (ack or unsolicited ERROR)
    2. snapin_manif - worst case: 1 message (tile 0 only)
    3. snapin_gui   - worst case: 1 message (config program account,
       tile 0 only)
   The STEM_BURST is the max value across these 3 links (not the sum).
   Note that snapin_txn is excluded from this calculation, since it is
   an unreliable link, working as a dcache place holder. */
#define STEM_BURST 1UL

/* Refresh flow-control credits before producer lanes stall. */
#define STEM_LAZY  (128L*250L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snapin_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snapin_tile_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_BEFORE_FRAG     before_frag
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

static ulong
max_event_sz( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return sizeof(fd_event_accdb_partition_added_t);
}

fd_topo_run_tile_t fd_tile_snapin = {
  .name                     = NAME,
  .populate_allowed_fds     = populate_allowed_fds,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .max_event_sz             = max_event_sz,
  .run                      = stem_run,
};

#undef NAME

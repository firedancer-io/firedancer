#include "utils/fd_ssctrl.h"
#include "utils/fd_ssload.h"
#include "utils/fd_ssmsg.h"
#include "utils/fd_ssparse.h"
#include "utils/fd_ssmanifest_parser.h"
#include "utils/fd_slot_delta_parser.h"
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
#include "../../flamenco/features/fd_features.h"
#include "../../flamenco/stakes/fd_stake_types.h"
#include "../../disco/stem/fd_stem.h"
#include "../../flamenco/accdb/fd_accdb.h"
#include "../../disco/events/generated/fd_event_gen.h"

#include "generated/fd_snapin_tile_seccomp.h"

#include <errno.h>
#include <unistd.h>

#define NAME "snapin"

#define FD_SNAPIN_WRITE_BUF_SZ      (16UL<<20)
#define FD_SNAPIN_WRITE_ACCOUNT_MAX (FD_SNAPIN_WRITE_BUF_SZ/sizeof(fd_accdb_disk_meta_t))

FD_STATIC_ASSERT( FD_SNAPSHOT_DATA_MTU<FD_SNAPIN_WRITE_BUF_SZ, write_buf );
FD_STATIC_ASSERT( sizeof(fd_accdb_disk_meta_t)+FD_RUNTIME_ACC_SZ_MAX<=FD_SNAPIN_WRITE_BUF_SZ, max_account );

/* The snapin tiles are state machines that parse and load a full and
   optionally an incremental snapshot.  They are responsible for loading
   accounts into the accounts database and writing their records to
   disk. */

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
   This means that only transactions executed in the latest 151 rooted
   blocks can be in the txncache.  The remaining entries can be ignored.

   A slot delta holds the transactions of one block, each twice ,once as
   signature and once as message hash.  When slot deltas are ingested,
   their entries are staged in a grid of FD_TXNCACHE_MAX_SLOT_DELTAS
   rows of txncache_max_entries_per_slot entries per row, one row per
   retained slot delta. */

FD_STATIC_ASSERT( FD_TXNCACHE_MAX_SLOT_DELTAS<=FD_SLOT_DELTA_MAX_ENTRIES, txncache_staging_slot_cnt );

/* A blockhash group is one (slot, blockhash) pair in the status cache,
   holding the txnhash offset for that blockhash and the entries of the
   transactions executed in that slot which referenced the blockhash.
   Agave inserts every processed transaction into the status cache twice
   (once with message hash and once with signature), both times under
   the same blockhash and slot.  Groups can reference any blockhash,
   including durable nonces that are not in the recent blockhash queue.
   So an honest slot has at most txncache_max_groups_per_slot groups
   (config->limits.max_txn_per_slot).  Snapshots exceeding this are
   rejected as malformed. */

struct blockhash_group {
  uchar blockhash[ 32UL ];
  uint  txnhash_offset;
  uint  txncache_entry_cnt;
};

typedef struct blockhash_group blockhash_group_t;

FD_STATIC_ASSERT( sizeof(blockhash_group_t)==40UL, blockhash_group );

/* After filtering with the recent blockhash queue, there is at most one
   group per retained (slot, recent blockhash) pair.  Filtering can only
   happen after we receive the manifest, hence we still need
   FD_TXNCACHE_MAX_SLOT_DELTAS*txncache_max_groups_per_slot worst case
   slot deltas buffered. */
#define FD_SNAPIN_MAX_RECENT_GROUPS (FD_TXNCACHE_MAX_SLOT_DELTAS*FD_TXNCACHE_MAX_SLOT_DELTAS)

struct recent_blockhash_group {
  ulong blockhash_bank_i;
  ulong execution_slot;
  ulong execution_bank_i;
  ulong txnhash_offset;
  ulong txncache_entry_idx;
  ulong txncache_entry_cnt;
};

typedef struct recent_blockhash_group recent_blockhash_group_t;

struct txncache_staging_slot {
  ulong slot;
  ulong entry_cnt;
  ulong group_cnt;
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

struct fd_snapin_account_batch {
  ulong cnt;
  ulong lamports    [ FD_SNAPIN_WRITE_ACCOUNT_MAX ];
  uint  slots       [ FD_SNAPIN_WRITE_ACCOUNT_MAX ];
  uint  data_lens   [ FD_SNAPIN_WRITE_ACCOUNT_MAX ];
  int   executables [ FD_SNAPIN_WRITE_ACCOUNT_MAX ];
};

typedef struct fd_snapin_account_batch fd_snapin_account_batch_t;

/* Only tile 0 uses this state. */
struct fd_snapin_lead {
  uint init_completed : 1;  /* did INIT complete for this attempt? */

  ulong seed;
  long boot_timestamp;

  fd_txncache_t * txncache;
  fd_bank_t *  bank;

  fd_ssmanifest_parser_t * manifest_parser;
  fd_slot_delta_parser_t * slot_delta_parser;

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

  ulong manifest_capitalization; /* capitalization according to the current snapshot manifest */

  struct {
    ulong loaded;
    ulong duplicates;
  } account_counts;

  struct {
    ulong                        capitalization;
    fd_accdb_snapshot_recovery_t accdb_metadata;
  } recovery; /* stores state from the last full snapshot for incremental revert */

  blockhash_group_t *        blockhash_groups;
  ulong                      blockhash_groups_cnt; /* every group parsed, including those from dropped slots */
  recent_blockhash_group_t * recent_groups;
  ulong                      recent_groups_len;

  fd_sstxncache_hash_t *  txncache_entries;
  txncache_staging_slot_t txncache_slots[ FD_TXNCACHE_MAX_SLOT_DELTAS ];
  ulong                   txncache_slots_len;
  ulong                   txncache_current_slot_idx;
  ulong                   txncache_current_slot_group_cnt;
  ulong                   txncache_current_slot_entry_cnt; /* entries of the slot delta being parsed, retained or not */
  ulong                   txncache_max_groups_per_slot;  /* config->limits.max_txn_per_slot */
  ulong                   txncache_max_entries_per_slot; /* 2x, signature and message hash entries */

  fd_accdb_fork_id_t accdb_root_fork_id;
  fd_accdb_fork_id_t accdb_incr_fork_id; /* child fork for incremental writes (purge on failure) */
  fd_txncache_fork_id_t txncache_root_fork_id;

  fd_snapin_out_link_t manifest_out;

  /* Roll back a failure at the next INIT. */
  struct {
    int                pending;
    int                full;  /* failed attempt type */
    fd_accdb_fork_id_t fork;  /* failed incremental fork */
  } rollback;
};

typedef struct fd_snapin_lead fd_snapin_lead_t;

/* Shared state for parallel snapin tiles. */
struct fd_snapin_shmem {
  /* After each INIT, tile 0 publishes fork_id, then number.  Workers
     wait for the matching number before processing. */
  struct {
    ulong number;
    ulong fork_id;
  } attempt;

  /* Workers atomically add per-attempt totals before FINI ACK. */
  struct {
    ulong loaded;
    ulong duplicates;
    ulong input_lamports;
    ulong duplicate_lamports;
  } totals;

  /* Atomic index of the next unclaimed appendvec. */
  ulong next_appendvec __attribute__((aligned(128)));
};

typedef struct fd_snapin_shmem fd_snapin_shmem_t;

struct fd_snapin_tile {
  int  state;
  uint full              : 1;  /* loading a full snapshot? */
  uint waiting_for_tile0 : 1;

  fd_snapin_lead_t lead;

  ulong tile_idx;           /* tile kind ID */
  ulong lane_cnt;
  ulong attempt_number;
  ulong expected_frame;
  ulong pending_control;    /* control message expected from snapdc tiles */
  uchar control_seen[ FD_TOPO_MAX_TILE_IN_LINKS ];

  fd_accdb_t * accdb;

  /* Shared stake data updated by every tile. */
  fd_stake_delegations_t * stake_delegations;

  fd_ssparse_t ssparse[1];

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
    ulong disk_bytes_written;
  } metrics;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
    ulong       pos;
  } in[ FD_TOPO_MAX_TILE_IN_LINKS ];

  fd_snapin_out_link_t ct_out;
  fd_snapin_out_link_t gui_out;

  /* Shared snapshot state. */
  fd_snapin_shmem_t * shmem;

  /* Parse state for one attempt. */
  ulong appendvec_seq;      /* next appendvec number */
  ulong claimed_appendvec;  /* current claim */
  ulong incr_fork;          /* insert fork; USHORT_MAX for full */

  /* Added to shared totals at FINI. */
  struct {
    ulong loaded;
    ulong duplicates;
    ulong input_lamports;
    ulong duplicate_lamports;
  } worker;

  struct {
    uchar                     buf[ FD_SNAPIN_WRITE_BUF_SZ ] __attribute__((aligned(64)));
    ulong                     buf_used;
    fd_snapin_account_batch_t batch;
  } writer;

  /* Buffer streamed account data before inserting. */
  struct {
    int   executable;
    ulong slot;
    ulong lamports;
    ulong data_len;
    ulong bytes_received;
    uchar pubkey[ 32UL ];
    uchar owner [ 32UL ];
    uchar data[ FD_RUNTIME_ACC_SZ_MAX ] __attribute__((aligned(64)));
  } staged;
};

typedef struct fd_snapin_tile fd_snapin_tile_t;

static inline int
is_lead( fd_snapin_tile_t const * ctx ) {
  return ctx->tile_idx==0UL;
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
    long  elapsed_ns   = fd_log_wallclock() - ctx->lead.boot_timestamp;
    char  loaded_buf[ 32 ];
    char  dup_buf   [ 32 ];
    format_count( loaded_buf, sizeof(loaded_buf), ctx->lead.account_counts.loaded );
    format_count( dup_buf,    sizeof(dup_buf),    ctx->lead.account_counts.duplicates );
    FD_LOG_NOTICE(( "loaded %s accounts %s(%s dups)%s from snapshot in %.3f seconds",
                    loaded_buf, fd_log_style_dim(), dup_buf, fd_log_style_normal(), (double)elapsed_ns/1e9 ));
  }
  return ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN;
}

static ulong
scratch_align( void ) {
  return 512UL;
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapin_tile_t),         sizeof(fd_snapin_tile_t)                                          );
  l = FD_LAYOUT_APPEND( l, fd_accdb_align(),                  fd_accdb_footprint( tile->snapin.max_live_slots ) );

  /* Only tile 0 can handle the manifest */
  if( FD_LIKELY( !tile->kind_id ) ) {
    l = FD_LAYOUT_APPEND( l, fd_txncache_align(),               fd_txncache_footprint( tile->snapin.max_live_slots )         );
    l = FD_LAYOUT_APPEND( l, fd_ssmanifest_parser_align(),      fd_ssmanifest_parser_footprint()                             );
    l = FD_LAYOUT_APPEND( l, fd_slot_delta_parser_align(),      fd_slot_delta_parser_footprint()                             );
    l = FD_LAYOUT_APPEND( l, alignof(recent_blockhash_group_t), sizeof(recent_blockhash_group_t)*FD_SNAPIN_MAX_RECENT_GROUPS );
    l = FD_LAYOUT_APPEND( l, alignof(fd_sstxncache_hash_t),     sizeof(fd_sstxncache_hash_t)*FD_TXNCACHE_MAX_SLOT_DELTAS*2UL*tile->snapin.max_txn_per_slot );
  }
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
metrics_write( fd_snapin_tile_t * ctx ) {
  fd_accdb_flush_metrics( ctx->accdb );

  FD_MGAUGE_SET( SNAPIN, STATE,                  (ulong)ctx->state );
  FD_MGAUGE_SET( SNAPIN, FULL_BYTES_READ,        ctx->metrics.full_bytes_read );
  FD_MGAUGE_SET( SNAPIN, INCREMENTAL_BYTES_READ, ctx->metrics.incremental_bytes_read );
  FD_MCNT_SET  ( SNAPIN, DISK_BYTES_WRITTEN,     ctx->metrics.disk_bytes_written );
  FD_MGAUGE_SET( SNAPIN, ACCOUNT_LOADED,         ctx->metrics.accounts_loaded );
  FD_MGAUGE_SET( SNAPIN, ACCOUNT_REPLACED,       ctx->metrics.accounts_replaced );
  FD_MGAUGE_SET( SNAPIN, ACCOUNT_IGNORED,        ctx->metrics.accounts_ignored );
  FD_MCNT_SET  ( SNAPIN, ACCOUNT_PROCESSED,       ctx->metrics.total_accounts_processed );
  FD_MCNT_SET  ( SNAPIN, ACCOUNT_BATCH_PROCESSED, ctx->metrics.total_account_batches_processed );
}

/* verify_slot_deltas_with_slot_history verifies the 'SlotHistory'
   sysvar account after loading a snapshot.  Returns 0 if verification
   passed, -1 if not. */

static int
verify_slot_deltas_with_slot_history( fd_snapin_tile_t * ctx ) {
  fd_accdb_fork_id_t fork_id = ctx->full ? ctx->lead.accdb_root_fork_id
                                         : ctx->lead.accdb_incr_fork_id;
  ulong lamports;
  ulong data_len;
  int   executable;
  uchar owner[ 32UL ];
  int   source = fd_accdb_read_one_nocache( ctx->accdb, fork_id,
                                            fd_sysvar_slot_history_id.uc,
                                            &lamports, &executable, owner,
                                            ctx->staged.data, &data_len );
  if( FD_UNLIKELY( source==FD_ACCDB_READ_ONE_NOCACHE_MISS ) ) {
    FD_LOG_WARNING(( "SlotHistory sysvar account was not present in the accounts database" ));
    return -1;
  }
  if( FD_UNLIKELY( data_len!=FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ) ) {
    FD_LOG_WARNING(( "SlotHistory sysvar account data size is %lu, expected %lu", data_len, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ));
    return -1;
  }
  if( FD_UNLIKELY( !fd_memeq( owner, fd_sysvar_owner_id.uc, sizeof(fd_pubkey_t) ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( owner, owner_b58 );
    FD_LOG_WARNING(( "SlotHistory sysvar owner is invalid: %s != sysvar_owner_id", owner_b58 ));
    return -1;
  }

  fd_slot_history_view_t view[1];
  if( FD_UNLIKELY( !fd_sysvar_slot_history_view( view, ctx->staged.data, data_len ) ) ) {
    FD_LOG_WARNING(( "SlotHistory sysvar account data is corrupt" ));
    return -1;
  }

  /* Sanity checks for slot history:
     https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L586 */

  ulong newest_slot = view->next_slot - 1UL;
  if( FD_UNLIKELY( newest_slot!=ctx->lead.bank_slot ) ) {
    /* VerifySlotHistoryError::InvalidNewestSlot
       https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L621 */
    FD_LOG_WARNING(( "SlotHistory sysvar has an invalid newest slot: %lu != bank slot: %lu", newest_slot, ctx->lead.bank_slot ));
    return -1;
  }

  if( FD_UNLIKELY( view->bits_len!=FD_SLOT_HISTORY_MAX_ENTRIES ) ) {
    /* VerifySlotHistoryError::InvalidNumEntries
       https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L625 */
    FD_LOG_WARNING(( "SlotHistory sysvar has invalid number of entries: %lu != expected: %lu", view->bits_len, FD_SLOT_HISTORY_MAX_ENTRIES ));
    return -1;
  }

  /* Stricter than Agave, which only checks bits_len (the bv crate
     merely requires bits_len<=blocks_len*64).  An exact block count is
     what makes fd_sysvar_slot_history_find_slot's (slot/64)%blocks_len
     indexing agree with Agave's bits.get(slot%MAX_ENTRIES); the runtime
     always writes exactly this many blocks. */
  if( FD_UNLIKELY( view->blocks_len!=FD_SLOT_HISTORY_MAX_ENTRIES/64UL ) ) {
    FD_LOG_WARNING(( "SlotHistory sysvar has invalid bitvec block count: %lu != expected: %lu", view->blocks_len, FD_SLOT_HISTORY_MAX_ENTRIES/64UL ));
    return -1;
  }

  /* All slots in slot deltas should be present in the slot history */
  fd_slot_delta_slot_set_t slot_set = fd_slot_delta_parser_slot_set( ctx->lead.slot_delta_parser );
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

  ulong scan_cnt  = fd_ulong_min( view->next_slot, FD_SLOT_HISTORY_MAX_ENTRIES );
  ulong found_cnt = 0UL;
  for( ulong i=0UL; i<scan_cnt && found_cnt<FD_SLOT_DELTA_MAX_ENTRIES; i++ ) {
    ulong slot = newest_slot - i;
    if( FD_UNLIKELY( fd_sysvar_slot_history_find_slot( view, slot )!=FD_SLOT_HISTORY_SLOT_FOUND ) ) continue;
    found_cnt++;
    if( FD_UNLIKELY( slot_set_ele_query( slot_set.map, &slot, NULL, slot_set.pool )==NULL ) ) {
      /* VerifySlotDeltasError::SlotNotFoundInDeltas
         https://github.com/anza-xyz/agave/blob/v3.1.8/snapshots/src/error.rs#L147
         https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L609 */
      FD_LOG_WARNING(( "slot %lu missing from slot deltas but present in SlotHistory", slot ));
      return -1;
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
  fd_slot_delta_slot_set_t slot_set = fd_slot_delta_parser_slot_set( ctx->lead.slot_delta_parser );
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
                     ctx->full?"full":"incr", ctx->lead.epoch, manifest->slot ));
    return -1;
  }

  if( FD_UNLIKELY( !manifest->has_accounts_lthash ) ) {
    FD_LOG_WARNING(( "%s manifest for epoch %lu and slot %lu is missing accounts lthash",
                     ctx->full?"full":"incr", ctx->lead.epoch, manifest->slot ));
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
                     ctx->full?"full":"incr", ctx->lead.epoch, manifest->slot,
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

static blockhash_group_t *
txncache_staging_groups_join( void * scratch,
                              ulong  scratch_sz,
                              ulong  groups_max ) {
  ulong start = fd_ulong_align_up( (ulong)scratch, alignof(blockhash_group_t) );
  ulong pad   = start-(ulong)scratch;
  if( FD_UNLIKELY( pad>scratch_sz ) ) return NULL;
  if( FD_UNLIKELY( scratch_sz-pad<groups_max*sizeof(blockhash_group_t) ) ) return NULL;
  return (blockhash_group_t *)start;
}

static blockhash_group_t *
txncache_staging_scratch( fd_snapin_tile_t * ctx ) {
  ulong  scratch_sz;
  void * scratch    = fd_txncache_snapin_scratch( ctx->lead.txncache, &scratch_sz );
  ulong  groups_max = FD_TXNCACHE_MAX_SLOT_DELTAS*ctx->lead.txncache_max_groups_per_slot;
  blockhash_group_t * groups = txncache_staging_groups_join( scratch, scratch_sz, groups_max );
  if( FD_UNLIKELY( !groups ) ) FD_LOG_ERR(( "txncache scratch (%lu bytes) too small to stage %lu blockhash groups (%lu bytes)", scratch_sz, groups_max, groups_max*sizeof(blockhash_group_t) ));
  return groups;
}

static void
txncache_staging_reset( fd_snapin_tile_t * ctx ) {
  ctx->lead.blockhash_groups_cnt            = 0UL;
  ctx->lead.recent_groups_len               = 0UL;
  ctx->lead.txncache_slots_len              = 0UL;
  ctx->lead.txncache_current_slot_entry_cnt = 0UL;
  ctx->lead.txncache_current_slot_idx       = ULONG_MAX;
  ctx->lead.txncache_current_slot_group_cnt = 0UL;
}

static ulong
txncache_staging_slot_begin( fd_snapin_tile_t * ctx,
                             ulong              slot ) {
  ulong candidate_idx;
  if( FD_LIKELY( ctx->lead.txncache_slots_len<FD_TXNCACHE_MAX_SLOT_DELTAS ) ) {
    candidate_idx = ctx->lead.txncache_slots_len++;
  } else {
    candidate_idx = 0UL;
    for( ulong i=1UL; i<FD_TXNCACHE_MAX_SLOT_DELTAS; i++ ) {
      if( ctx->lead.txncache_slots[ i ].slot<ctx->lead.txncache_slots[ candidate_idx ].slot ) candidate_idx = i;
    }
    if( FD_UNLIKELY( slot<ctx->lead.txncache_slots[ candidate_idx ].slot ) ) candidate_idx = ULONG_MAX;
  }

  if( FD_LIKELY( candidate_idx!=ULONG_MAX ) ) {
    ctx->lead.txncache_slots[ candidate_idx ].slot       = slot;
    ctx->lead.txncache_slots[ candidate_idx ].entry_cnt  = 0UL;
    ctx->lead.txncache_slots[ candidate_idx ].group_cnt  = 0UL;
  }
  ctx->lead.txncache_current_slot_idx       = candidate_idx;
  ctx->lead.txncache_current_slot_entry_cnt = 0UL;
  ctx->lead.txncache_current_slot_group_cnt = 0UL;
  return candidate_idx;
}

static int
txncache_staging_group_begin( fd_snapin_tile_t * ctx,
                              uchar const *      blockhash,
                              ulong              txnhash_offset ) {
  if( FD_UNLIKELY( ctx->lead.txncache_current_slot_group_cnt>=ctx->lead.txncache_max_groups_per_slot ) ) return -1;
  ctx->lead.txncache_current_slot_group_cnt++;
  ctx->lead.blockhash_groups_cnt++;

  ulong slot_idx = ctx->lead.txncache_current_slot_idx;
  if( FD_UNLIKELY( slot_idx==ULONG_MAX ) ) return 0;

  FD_TEST( slot_idx<ctx->lead.txncache_slots_len );
  txncache_staging_slot_t * staging_slot = &ctx->lead.txncache_slots[ slot_idx ];
  FD_TEST( staging_slot->group_cnt<ctx->lead.txncache_max_groups_per_slot );
  blockhash_group_t * group = &ctx->lead.blockhash_groups[ slot_idx*ctx->lead.txncache_max_groups_per_slot+staging_slot->group_cnt ];
  memcpy( group->blockhash, blockhash, 32UL );
  group->txnhash_offset     = (uint)txnhash_offset;
  group->txncache_entry_cnt = 0U;
  staging_slot->group_cnt++;
  return 0;
}

static int
txncache_staging_entry_add( fd_snapin_tile_t * ctx,
                            ulong              slot,
                            uchar const *      txnhash ) {
  if( FD_UNLIKELY( ctx->lead.txncache_current_slot_entry_cnt>=ctx->lead.txncache_max_entries_per_slot ) ) return -1;
  ctx->lead.txncache_current_slot_entry_cnt++;

  ulong slot_idx = ctx->lead.txncache_current_slot_idx;
  if( FD_UNLIKELY( slot_idx==ULONG_MAX ) ) return 0; /* discarded older delta */

  FD_TEST( slot_idx<ctx->lead.txncache_slots_len );
  txncache_staging_slot_t * staging_slot = &ctx->lead.txncache_slots[ slot_idx ];
  FD_TEST( staging_slot->slot==slot );
  FD_TEST( staging_slot->group_cnt );
  FD_TEST( staging_slot->entry_cnt<ctx->lead.txncache_max_entries_per_slot );
  blockhash_group_t * group = &ctx->lead.blockhash_groups[ slot_idx*ctx->lead.txncache_max_groups_per_slot+staging_slot->group_cnt-1UL ];
  memcpy( ctx->lead.txncache_entries[ slot_idx*ctx->lead.txncache_max_entries_per_slot+staging_slot->entry_cnt ].txnhash, txnhash, sizeof(fd_sstxncache_hash_t) );
  staging_slot->entry_cnt++;
  group->txncache_entry_cnt++;
  return 0;
}

static ulong
txncache_staging_rank_slots( fd_snapin_tile_t const * ctx,
                             ulong                    execution_bank_i_by_staging_idx[ static FD_TXNCACHE_MAX_SLOT_DELTAS ] ) {
  ulong staging_slot_cnt = ctx->lead.txncache_slots_len;
  ulong staging_idx_by_bank_i[ FD_TXNCACHE_MAX_SLOT_DELTAS ];
  for( ulong staging_idx=0UL; staging_idx<staging_slot_cnt; staging_idx++ ) {
    ulong bank_i = staging_idx;
    while( bank_i>0UL && ctx->lead.txncache_slots[ staging_idx_by_bank_i[ bank_i-1UL ] ].slot<ctx->lead.txncache_slots[ staging_idx ].slot ) {
      staging_idx_by_bank_i[ bank_i ] = staging_idx_by_bank_i[ bank_i-1UL ];
      bank_i--;
    }
    staging_idx_by_bank_i[ bank_i ] = staging_idx;
  }
  for( ulong bank_i=0UL; bank_i<staging_slot_cnt; bank_i++ ) {
    execution_bank_i_by_staging_idx[ staging_idx_by_bank_i[ bank_i ] ] = bank_i;
  }
  return staging_slot_cnt ? ctx->lead.txncache_slots[ staging_idx_by_bank_i[ 0UL ] ].slot : ULONG_MAX;
}

static int
txncache_staging_filter_groups( fd_snapin_tile_t *           ctx,
                                blockhash_map_t const *      blockhash_map,
                                fd_blockhash_entry_t const * blockhash_pool,
                                ulong                        snapshot_slot ) {
  ulong execution_bank_i_by_staging_idx[ FD_TXNCACHE_MAX_SLOT_DELTAS ];
  ulong newest_staged_slot = txncache_staging_rank_slots( ctx, execution_bank_i_by_staging_idx );
  if( FD_UNLIKELY( newest_staged_slot!=ULONG_MAX && newest_staged_slot!=snapshot_slot ) ) {
    FD_LOG_WARNING(( "corrupt snapshot: newest slot delta is for slot %lu, not the snapshot slot %lu", newest_staged_slot, snapshot_slot ));
    return 1;
  }

  ctx->lead.recent_groups_len = 0UL;
  for( ulong staging_idx=0UL; staging_idx<ctx->lead.txncache_slots_len; staging_idx++ ) {
    txncache_staging_slot_t const * staging_slot = &ctx->lead.txncache_slots[ staging_idx ];
    blockhash_group_t const *       groups       = &ctx->lead.blockhash_groups[ staging_idx*ctx->lead.txncache_max_groups_per_slot ];
    ulong                           entry_idx    = staging_idx*ctx->lead.txncache_max_entries_per_slot;

    for( ulong i=0UL; i<staging_slot->group_cnt; i++ ) {
      blockhash_group_t const * group = &groups[ i ];
      fd_hash_t key;
      fd_memcpy( key.uc, group->blockhash, 32UL );
      fd_blockhash_entry_t const * entry = blockhash_map_ele_query_const( blockhash_map, &key, NULL, blockhash_pool );
      if( FD_LIKELY( entry ) ) {
        if( FD_UNLIKELY( ctx->lead.recent_groups_len>=FD_SNAPIN_MAX_RECENT_GROUPS ) ) {
          FD_LOG_WARNING(( "corrupt snapshot: more than %lu blockhash groups reference recent blockhashes", FD_SNAPIN_MAX_RECENT_GROUPS ));
          return -1;
        }
        recent_blockhash_group_t * recent = &ctx->lead.recent_groups[ ctx->lead.recent_groups_len++ ];
        recent->blockhash_bank_i   = (ulong)(entry-blockhash_pool);
        recent->execution_slot     = staging_slot->slot;
        recent->execution_bank_i   = execution_bank_i_by_staging_idx[ staging_idx ];
        recent->txnhash_offset     = group->txnhash_offset;
        recent->txncache_entry_idx = entry_idx;
        recent->txncache_entry_cnt = group->txncache_entry_cnt;
      }
      entry_idx += group->txncache_entry_cnt;
    }
    FD_TEST( entry_idx==staging_idx*ctx->lead.txncache_max_entries_per_slot+staging_slot->entry_cnt );
  }
  return 0;
}

static int
populate_txncache( fd_snapin_tile_t *                     ctx,
                   fd_snapshot_manifest_blockhash_t const blockhashes[ static FD_BLOCKHASHES_MAX ],
                   ulong                                  blockhashes_len,
                   ulong                                  snapshot_slot ) {
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

    That is what populate does, with one shortcut.  Every rooted slot
    with a block has a slot delta, and every rooted block registered
    exactly one blockhash.  Both sequences end at the snapshot slot, so
    ranking the retained slot deltas newest first gives the chain index
    of the fork each delta's transactions executed in, without
    consulting the ancestors array.

    From there we are done.

    Well almost ...  The Agave status cache decided to only store 20
    bytes for 32 byte transaction hashes to save on memory.  That's OK,
    but they didn't just take the first 20 bytes.  They instead, for
    each blockhash, take a random offset between 0 and 11, and store
    bytes [ offset, offset+20 ) of the transaction hash.  We need to
    know this offset to be able to query the txncache later, so we
    retrieve it from the slot_deltas groups and key it into the bank of
    the referenced blockhash in our chain, checking that every group for
    a blockhash agrees on it. */

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
  blockhash_map_t * blockhash_map = blockhash_map_join( blockhash_map_new( _map, 1024UL, ctx->lead.seed ) );
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

  /* blockhash_groups aliases txncache memory, so filtering must finish
     before the first txncache insert. */
  if( FD_UNLIKELY( txncache_staging_filter_groups( ctx, blockhash_map, blockhash_pool, snapshot_slot ) ) ) return 1;

  /* Now load the blockhash offsets for these blockhashes ... */
  if( FD_UNLIKELY( !ctx->lead.blockhash_groups_cnt ) ) {
    fd_slot_delta_slot_set_t ss = fd_slot_delta_parser_slot_set( ctx->lead.slot_delta_parser );
    /* Rooted slots with no groups represent an empty status cache.
       No restored entry needs a hash offset, so finalization uses zero. */
    if( FD_UNLIKELY( !ss.ele_cnt ) ) {
      FD_LOG_WARNING(( "corrupt snapshot: no blockhash offsets found (rooted_slots=%lu)", ss.ele_cnt ));
      return 1;
    }
    FD_LOG_WARNING(( "status cache has no blockhash groups (rooted_slots=%lu); defaulting transaction hash offsets to zero", ss.ele_cnt ));
  }
  for( ulong i=0UL; i<ctx->lead.recent_groups_len; i++ ) {
    recent_blockhash_group_t const * group = &ctx->lead.recent_groups[ i ];
    ulong blockhash_bank_i = group->blockhash_bank_i;
    FD_TEST( blockhash_bank_i<chain_len );

    if( FD_UNLIKELY( banks[ blockhash_bank_i ].txnhash_offset!=ULONG_MAX && banks[ blockhash_bank_i ].txnhash_offset!=group->txnhash_offset ) ) {
      FD_BASE58_ENCODE_32_BYTES( banks[ blockhash_bank_i ].blockhash, blockhash_b58 );
      FD_LOG_WARNING(( "corrupt snapshot: conflicting txnhash offsets for blockhash %s", blockhash_b58 ));
      return 1;
    }

    if( FD_UNLIKELY( group->txncache_entry_cnt && blockhash_bank_i<=group->execution_bank_i ) ) {
      FD_BASE58_ENCODE_32_BYTES( banks[ blockhash_bank_i ].blockhash, blockhash_b58 );
      FD_LOG_WARNING(( "corrupt snapshot: %lu status cache entries of slot %lu reference blockhash %s, which is not older than that slot", group->txncache_entry_cnt, group->execution_slot, blockhash_b58 ));
      return 1;
    }

    banks[ blockhash_bank_i ].txnhash_offset = group->txnhash_offset;
  }

  /* Construct the linear fork chain in the txncache. */

  fd_txncache_fork_id_t parent = { .val = USHORT_MAX };
  for( ulong i=0UL; i<chain_len; i++ ) banks[ chain_len-1UL-i ].fork_id = parent = fd_txncache_attach_child( ctx->lead.txncache, parent );
  for( ulong i=0UL; i<chain_len; i++ ) fd_txncache_attach_blockhash( ctx->lead.txncache, banks[ i ].fork_id, banks[ i ].blockhash );

  for( ulong i=0UL; i<ctx->lead.recent_groups_len; i++ ) {
    recent_blockhash_group_t const * group   = &ctx->lead.recent_groups[ i ];
    fd_sstxncache_hash_t const *     entries = &ctx->lead.txncache_entries[ group->txncache_entry_idx ];
    for( ulong j=0UL; j<group->txncache_entry_cnt; j++ ) {
      fd_txncache_insert( ctx->lead.txncache, banks[ group->execution_bank_i ].fork_id, banks[ group->blockhash_bank_i ].blockhash, entries[ j ].txnhash );
    }
  }

  /* Then finalize all the banks (freezing them) and setting the txnhash
     offset so future queries use the correct offset.  If the offset is
     ULONG_MAX this is valid, it means the blockhash had no transactions
     in it, so there's nothing in the status cache under that blockhash.

     Just set the offset to 0 in this case, it doesn't matter, but
     should be valid between 0 and 11 inclusive. */
  for( ulong i=0UL; i<chain_len; i++ ) {
    ulong txnhash_offset = banks[ chain_len-1UL-i ].txnhash_offset==ULONG_MAX ? 0UL : banks[ chain_len-1UL-i ].txnhash_offset;
    fd_txncache_finalize_fork( ctx->lead.txncache, banks[ chain_len-1UL-i ].fork_id, txnhash_offset, banks[ chain_len-1UL-i ].blockhash );
  }

  for( ulong i=1UL; i<chain_len; i++ ) fd_txncache_advance_root( ctx->lead.txncache, banks[ chain_len-1UL-i ].fork_id );

  ctx->lead.txncache_root_fork_id = parent;

  return 0;
}

static void
process_manifest( fd_snapin_tile_t *  ctx,
                  fd_stem_context_t * stem ) {
  fd_snapshot_manifest_t * manifest = fd_chunk_to_laddr( ctx->lead.manifest_out.mem, ctx->lead.manifest_out.chunk );

  if( FD_UNLIKELY( ctx->lead.advertised_slot!=manifest->slot ) ) {
    /* SnapshotError::MismatchedSlot
       https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L472 */
    FD_LOG_WARNING(( "snapshot manifest bank slot %lu does not match advertised slot %lu from snapshot peer",
                     manifest->slot, ctx->lead.advertised_slot ));
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

  if( FD_UNLIKELY( memcmp( ctx->lead.advertised_hash, hash32, FD_HASH_FOOTPRINT ) ) ) {
    /* SnapshotError::MismatchedHash
        https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L479 */
    FD_BASE58_ENCODE_32_BYTES( ctx->lead.advertised_hash, advertised_hash_enc );
    FD_LOG_WARNING(( "snapshot manifest accounts lthash %s does not match advertised hash from snapshot peer %s",
                     hash32_enc, advertised_hash_enc ));
    transition_malformed( ctx, stem );
    return;
  }

  ctx->lead.bank_slot = manifest->slot;
  ctx->lead.manifest_capitalization = manifest->capitalization;
  if( FD_UNLIKELY( ctx->lead.manifest_capitalization>LONG_MAX ) ) {
    /* Calculations downstream require capitalization to be treated
       as long (to handle addition and subtraction). */
    FD_LOG_WARNING(( "snapshot manifest capitalization %lu exceeds LONG_MAX", ctx->lead.manifest_capitalization ));
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
  ctx->lead.epoch          = fd_slot_to_epoch( &epoch_schedule, manifest->slot, NULL );
  ctx->lead.epoch_schedule = epoch_schedule;

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

  if( FD_UNLIKELY( populate_txncache( ctx, manifest->blockhashes, manifest->blockhashes_len, manifest->slot ) ) ) {
    FD_LOG_WARNING(( "populating txncache failed" ));
    transition_malformed( ctx, stem );
    return;
  }

  if( ctx->full ) {
    ctx->lead.full_genesis_creation_time_seconds = manifest->creation_time_seconds;
  } else {
    if( FD_UNLIKELY( manifest->creation_time_seconds!=ctx->lead.full_genesis_creation_time_seconds ) ) {
      FD_LOG_WARNING(( "snapshot manifest genesis creation time seconds %lu does not match full snapshot genesis creation time seconds %lu",
                       manifest->creation_time_seconds, ctx->lead.full_genesis_creation_time_seconds ));
      transition_malformed( ctx, stem );
      return;
    }
  }

  manifest->accdb_fork_id    = fd_ushort_if( ctx->full, ctx->lead.accdb_root_fork_id.val, ctx->lead.accdb_incr_fork_id.val );
  manifest->txncache_fork_id = ctx->lead.txncache_root_fork_id.val;

  ulong sig = ctx->full ? fd_ssmsg_sig( FD_SSMSG_MANIFEST_FULL ) :
                          fd_ssmsg_sig( FD_SSMSG_MANIFEST_INCREMENTAL );
  fd_stem_publish( stem, ctx->lead.manifest_out.idx, sig, ctx->lead.manifest_out.chunk, sizeof(fd_snapshot_manifest_t), 0UL, 0UL, 0UL );
  ctx->lead.manifest_out.chunk = fd_dcache_compact_next( ctx->lead.manifest_out.chunk, sizeof(fd_snapshot_manifest_t), ctx->lead.manifest_out.chunk0, ctx->lead.manifest_out.wmark );
}

static void
snoop_stake_delegation( fd_snapin_tile_t *  ctx,
                        fd_pubkey_t const * stake_account,
                        ulong               lamports,
                        ulong               data_len,
                        uchar const *       data,
                        ulong               data_sz ) {
  fd_stake_state_t const * stake_state = fd_stake_state_view( data, data_sz );
  if( FD_UNLIKELY( !stake_state || stake_state->stake_type!=FD_STAKE_STATE_STAKE ) ) return;

  fd_delegation_t const * delegation = &stake_state->stake.stake.delegation;
  if( FD_UNLIKELY( ( delegation->activation_epoch!=ULONG_MAX &&
                     delegation->activation_epoch>=(ulong)USHORT_MAX ) ||
                   ( delegation->deactivation_epoch!=ULONG_MAX &&
                     delegation->deactivation_epoch>=(ulong)USHORT_MAX ) ) ) return;

  fd_stake_delegations_root_update(
      ctx->stake_delegations,
      stake_account,
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

/* Write engine */

static void
writer_pwrite( fd_snapin_tile_t * ctx,
               uchar const *      buf,
               ulong              sz,
               ulong              off ) {
  ulong done = 0UL;
  while( done<sz ) {
    long res = pwrite( FD_ACCDB_FD_RW, buf+done, sz-done, (long)(off+done) );
    if( FD_UNLIKELY( res<=0L ) ) {
      int err = res<0L ? errno : EIO;
      if( res<0L && err==EINTR ) continue;
      FD_LOG_ERR(( "snapshot write failed at offset %lu (%d-%s)", off+done, err, fd_io_strerror( err ) ));
    }
    done += (ulong)res;
    ctx->metrics.disk_bytes_written += (ulong)res;
  }
}

static int
writer_flush( fd_snapin_tile_t * ctx ) {
  if( FD_UNLIKELY( !ctx->writer.buf_used ) ) return 0;

  /* Write all buffered accounts as one contiguous range. */
  ulong base_off = fd_accdb_snapshot_reserve_write( ctx->accdb, ctx->writer.buf_used );
  writer_pwrite( ctx, ctx->writer.buf, ctx->writer.buf_used, base_off );

  fd_accdb_fork_id_t fork_id = { .val = ctx->full ? USHORT_MAX : (ushort)ctx->incr_fork };
  fd_snapin_account_batch_t * batch = &ctx->writer.batch;

  uchar const * pubkeys[ FD_SSPARSE_ACC_BATCH_MAX ];
  ulong slots          [ FD_SSPARSE_ACC_BATCH_MAX ];
  ulong data_lens      [ FD_SSPARSE_ACC_BATCH_MAX ];
  ulong file_offsets   [ FD_SSPARSE_ACC_BATCH_MAX ];
  ulong buf_off = 0UL;

  /* Flush accounts in batches of 8 */
  for( ulong batch_off=0UL; batch_off<batch->cnt; batch_off+=FD_SSPARSE_ACC_BATCH_MAX ) {
    ulong cnt = fd_ulong_min( FD_SSPARSE_ACC_BATCH_MAX, batch->cnt-batch_off );
    ulong input_lamports = 0UL;

    for( ulong i=0UL; i<cnt; i++ ) {
      ulong idx = batch_off+i;

      uchar const * meta_ptr = ctx->writer.buf+buf_off;
      uchar const * owner    = meta_ptr+offsetof(fd_accdb_disk_meta_t, owner);
      uchar const * data     = meta_ptr+sizeof(fd_accdb_disk_meta_t);

      pubkeys     [ i ] = meta_ptr;
      slots       [ i ] = (ulong)batch->slots    [ idx ];
      data_lens   [ i ] = (ulong)batch->data_lens[ idx ];
      file_offsets[ i ] = base_off+buf_off;

      buf_off += sizeof(fd_accdb_disk_meta_t)+data_lens[ i ];
      input_lamports = fd_ulong_sat_add( input_lamports, batch->lamports[ idx ] );

      if( FD_UNLIKELY( batch->lamports[ idx ] &&
                       !memcmp( owner, fd_solana_stake_program_id.uc, 32UL ) ) ) {
        snoop_stake_delegation( ctx, (fd_pubkey_t const *)pubkeys[ i ],
                                batch->lamports[ idx ], data_lens[ i ],
                                data, data_lens[ i ] );
      }
    }

    ulong accounts_ignored, accounts_replaced, accounts_loaded, replaced_lamports, ignored_lamports;
    if( FD_UNLIKELY( fd_accdb_snapshot_write_batch( ctx->accdb, fork_id, cnt, pubkeys,
                                                    slots, batch->lamports+batch_off,
                                                    data_lens, batch->executables+batch_off,
                                                    file_offsets, &accounts_ignored, &accounts_replaced,
                                                    &accounts_loaded, &replaced_lamports, &ignored_lamports ) ) ) {
      return 1;
    }

    ctx->metrics.accounts_ignored  += accounts_ignored;
    ctx->metrics.accounts_replaced += accounts_replaced;
    ctx->metrics.accounts_loaded   += accounts_loaded;
    ctx->worker.loaded             += accounts_loaded;
    ctx->worker.duplicates         += accounts_ignored + accounts_replaced;
    ctx->worker.input_lamports      = fd_ulong_sat_add( ctx->worker.input_lamports, input_lamports );
    ctx->worker.duplicate_lamports  = fd_ulong_sat_add( ctx->worker.duplicate_lamports, fd_ulong_sat_add( replaced_lamports, ignored_lamports ) );
  }

  FD_TEST( buf_off==ctx->writer.buf_used );
  ctx->writer.buf_used  = 0UL;
  ctx->writer.batch.cnt = 0UL;
  return 0;
}

static int
writer_append_account( fd_snapin_tile_t * ctx,
                       uchar const *      pubkey,
                       uchar const *      owner,
                       uchar const *      data,
                       ulong              slot,
                       ulong              lamports,
                       ulong              data_len,
                       int                executable ) {
  FD_TEST( slot<=UINT_MAX );
  ulong account_sz = sizeof(fd_accdb_disk_meta_t)+data_len;
  FD_TEST( account_sz<=FD_SNAPIN_WRITE_BUF_SZ );

  if( FD_UNLIKELY( account_sz>FD_SNAPIN_WRITE_BUF_SZ-ctx->writer.buf_used && writer_flush( ctx ) ) ) {
    return 1;
  }

  FD_TEST( ctx->writer.batch.cnt<FD_SNAPIN_WRITE_ACCOUNT_MAX );

  ulong idx     = ctx->writer.batch.cnt++;
  ulong buf_off = ctx->writer.buf_used;

  /* Serialize the account metadata into the buffer */
  fd_accdb_disk_meta_t meta = {
    .size       = (uint)data_len,
    .generation = 0U,
  };
  uchar * meta_ptr = ctx->writer.buf+buf_off;
  uchar * data_ptr = meta_ptr+sizeof(fd_accdb_disk_meta_t);
  fd_memcpy( meta.pubkey, pubkey, 32UL );
  fd_memcpy( meta.owner, owner, 32UL );
  fd_memcpy( meta_ptr, meta.b, sizeof(fd_accdb_disk_meta_t) );
  fd_memcpy( data_ptr, data, data_len );
  ctx->writer.buf_used += account_sz;

  /* Stage fields needed for index publication after pwrite. */
  ctx->writer.batch.lamports    [ idx ] = lamports;
  ctx->writer.batch.slots       [ idx ] = (uint)slot;
  ctx->writer.batch.data_lens   [ idx ] = (uint)data_len;
  ctx->writer.batch.executables [ idx ] = executable;
  ctx->metrics.total_accounts_processed++;
  return 0;
}

static int
writer_append_staged_account( fd_snapin_tile_t * ctx ) {
  if( FD_UNLIKELY( writer_append_account( ctx, ctx->staged.pubkey, ctx->staged.owner, ctx->staged.data,
                                          ctx->staged.slot, ctx->staged.lamports, ctx->staged.data_len,
                                          ctx->staged.executable ) ) ) {
    return 1;
  }
  ctx->metrics.total_account_batches_processed++;
  return 0;
}

static int
process_account_batch( fd_snapin_tile_t *            ctx,
                       fd_ssparse_advance_result_t * result ) {
  uchar const * const * entries    = result->account_batch.batch;
  ulong                 cnt        = result->account_batch.batch_cnt;
  ulong                 batch_slot = result->account_batch.slot;

  for( ulong i=0UL; i<cnt; i++ ) {
    uchar const * e = entries[ i ];
    if( FD_UNLIKELY( writer_append_account( ctx, e+16UL, e+64UL, e+136UL, batch_slot,
                                            fd_ulong_load_8_fast( e+48UL ), fd_ulong_load_8_fast( e+8UL ),
                                            (int)e[ 96UL ] ) ) ) {
      return 1;
    }
  }
  ctx->metrics.total_account_batches_processed++;
  return 0;
}

static int
process_account_header( fd_snapin_tile_t *            ctx,
                        fd_ssparse_advance_result_t * result ) {
  FD_TEST( ctx->staged.bytes_received==ctx->staged.data_len );
  FD_TEST( result->account_header.data_len<=FD_RUNTIME_ACC_SZ_MAX );

  ctx->staged.executable     = result->account_header.executable;
  ctx->staged.slot           = result->account_header.slot;
  ctx->staged.lamports       = result->account_header.lamports;
  ctx->staged.data_len       = result->account_header.data_len;
  ctx->staged.bytes_received = 0UL;
  fd_memcpy( ctx->staged.pubkey, result->account_header.pubkey, 32UL );
  fd_memcpy( ctx->staged.owner,  result->account_header.owner,  32UL );

  if( FD_LIKELY( ctx->staged.data_len ) ) {
    return 0;
  }

  /* No account data to receive, so we can just publish the account now. */
  return writer_append_staged_account( ctx );
}

static int
process_account_data( fd_snapin_tile_t *            ctx,
                      fd_ssparse_advance_result_t * result ) {
  FD_TEST( ctx->staged.bytes_received<ctx->staged.data_len );
  FD_TEST( result->account_data.data_sz<=ctx->staged.data_len-ctx->staged.bytes_received );

  fd_memcpy( ctx->staged.data+ctx->staged.bytes_received, result->account_data.data, result->account_data.data_sz );
  ctx->staged.bytes_received += result->account_data.data_sz;

  /* More bytes remain in account data, don't publish yet */
  if( FD_LIKELY( ctx->staged.bytes_received<ctx->staged.data_len ) ) {
    return 0;
  }

  return writer_append_staged_account( ctx );
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
        ulong appendvec_idx = ctx->appendvec_seq++;
        if( FD_UNLIKELY( appendvec_idx==ctx->claimed_appendvec ) ) {
          ctx->claimed_appendvec = FD_ATOMIC_FETCH_AND_ADD( &ctx->shmem->next_appendvec, 1UL );
          fd_ssparse_appendvec_parse( ctx->ssparse );
        }
        break;
      }
      case FD_SSPARSE_ADVANCE_MANIFEST:
      case FD_SSPARSE_ADVANCE_MANIFEST_DONE: {
         /* Tile 0 only. */
        if( FD_LIKELY( !is_lead( ctx ) ) ) break;

        if( FD_UNLIKELY( ctx->lead.flags.manifest_done ) ) {
          FD_LOG_WARNING(( "excess data after manifest" ));
          transition_malformed( ctx, stem );
          return 0;
        }
        int parser_res = fd_ssmanifest_parser_consume( ctx->lead.manifest_parser,
                                                       result->manifest.data,
                                                       result->manifest.data_sz );
        if( FD_UNLIKELY( parser_res==FD_SSMANIFEST_PARSER_ADVANCE_ERROR ) ) {
          FD_LOG_WARNING(( "error while parsing snapshot manifest" ));
          transition_malformed( ctx, stem );
          return 0;
        }
        if( res==FD_SSPARSE_ADVANCE_MANIFEST_DONE ) {
          if( FD_UNLIKELY( fd_ssmanifest_parser_fini( ctx->lead.manifest_parser )!=FD_SSMANIFEST_PARSER_ADVANCE_DONE ) ) {
            FD_LOG_WARNING(( "manifest stream ended before parser was done" ));
            transition_malformed( ctx, stem );
            return 0;
          }
          ctx->lead.flags.manifest_done = 1;
        }
        break;
      }
      case FD_SSPARSE_ADVANCE_STATUS_CACHE: {
        /* Tile 0 only. */
        if( FD_LIKELY( !is_lead( ctx ) ) ) break;

        fd_slot_delta_parser_advance_result_t sd_result[1];
        ulong bytes_remaining = result->status_cache.data_sz;

        while( bytes_remaining ) {
          int res = fd_slot_delta_parser_consume( ctx->lead.slot_delta_parser,
                                                  result->status_cache.data,
                                                  bytes_remaining,
                                                  sd_result );
          if( FD_UNLIKELY( res<0 ) ) {
            FD_LOG_WARNING(( "error while parsing slot deltas in status cache" ));
            transition_malformed( ctx, stem );
            return 0;
          } else if( FD_LIKELY( res==FD_SLOT_DELTA_PARSER_ADVANCE_SLOT ) ) {
            txncache_staging_slot_begin( ctx, sd_result->slot );
          } else if( FD_LIKELY( res==FD_SLOT_DELTA_PARSER_ADVANCE_GROUP ) ) {
            if( FD_UNLIKELY( txncache_staging_group_begin( ctx, sd_result->group.blockhash, sd_result->group.txnhash_offset ) ) ) {
              FD_LOG_WARNING(( "blockhash groups overflow for slot %lu, max is %lu", sd_result->group.slot, ctx->lead.txncache_max_groups_per_slot ));
              transition_malformed( ctx, stem );
              return 0;
            }
          } else if( FD_LIKELY( res==FD_SLOT_DELTA_PARSER_ADVANCE_ENTRY ) ) {
            if( FD_UNLIKELY( txncache_staging_entry_add( ctx, sd_result->entry->slot, sd_result->entry->txnhash ) ) ) {
              FD_LOG_WARNING(( "status cache slot %lu has more than %lu entries", sd_result->entry->slot, ctx->lead.txncache_max_entries_per_slot ));
              transition_malformed( ctx, stem );
              return 0;
            }
          }

          bytes_remaining           -= sd_result->bytes_consumed;
          result->status_cache.data += sd_result->bytes_consumed;
        }

        if( FD_UNLIKELY( result->status_cache.done ) ) {
          int fini_res = fd_slot_delta_parser_consume( ctx->lead.slot_delta_parser, result->status_cache.data, 0UL, sd_result );
          if( FD_UNLIKELY( fini_res<0 ) ) {
            FD_LOG_WARNING(( "error while finalizing slot deltas in status cache" ));
            transition_malformed( ctx, stem );
            return 0;
          }
          ctx->lead.flags.status_cache_done = fini_res==FD_SLOT_DELTA_PARSER_ADVANCE_DONE;
        }
        break;
      }
      case FD_SSPARSE_ADVANCE_ACCOUNT_HEADER:
        early_exit = process_account_header( ctx, result );
        if( FD_UNLIKELY( early_exit ) ) {
          transition_malformed( ctx, stem );
          return 0;
        }
        break;
      case FD_SSPARSE_ADVANCE_ACCOUNT_DATA:
        if( FD_UNLIKELY( process_account_data( ctx, result ) ) ) {
          transition_malformed( ctx, stem );
          return 0;
        }

        /* Account data may span multiple input chunks.  Once complete,
           copy the staged account into gui_out and publish it once.

           We expect ConfigKeys Vec to be length 2 (checked via the
           first byte of the accumulated data).  We expect the size of
           ConfigProgram-owned accounts to be at most
           FD_GUI_CONFIG_PARSE_MAX_VALID_ACCT_SZ, since this is the
           size that the Solana CLI allocates for them. Although the
           ConfigProgram itself does not enforce these invariants, the
           vast majority of accounts (with a tiny number of exceptions
           on devnet) are maintained with the Solana CLI. */
        if( FD_UNLIKELY( ctx->staged.bytes_received==ctx->staged.data_len
                      && ctx->gui_out.idx!=ULONG_MAX
                      && !memcmp( ctx->staged.owner, fd_solana_config_program_id.key, sizeof(fd_hash_t) )
                      && ctx->staged.data_len
                      && ctx->staged.data_len<=FD_GUI_CONFIG_PARSE_MAX_VALID_ACCT_SZ
                      && ctx->staged.data[ 0 ]==2UL ) ) {
          uchar * acct = fd_chunk_to_laddr( ctx->gui_out.mem, ctx->gui_out.chunk );
          fd_memcpy( acct, ctx->staged.data, ctx->staged.data_len );
          fd_stem_publish( stem, ctx->gui_out.idx, 0UL, ctx->gui_out.chunk, ctx->staged.data_len, 0UL, 0UL, 0UL );
          ctx->gui_out.chunk = fd_dcache_compact_next( ctx->gui_out.chunk, ctx->staged.data_len, ctx->gui_out.chunk0, ctx->gui_out.wmark );
          early_exit = 1;
        }
        break;
      case FD_SSPARSE_ADVANCE_ACCOUNT_BATCH:
        if( FD_UNLIKELY( process_account_batch( ctx, result ) ) ) {
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

    if( FD_UNLIKELY( is_lead( ctx ) && !ctx->lead.flags.manifest_processed && ctx->lead.flags.manifest_done && ctx->lead.flags.status_cache_done ) ) {
      process_manifest( ctx, stem );
      if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_ERROR ) ) break;
      ctx->lead.flags.manifest_processed = 1;
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

/* Resets local worker state */

static void
reset_attempt_state( fd_snapin_tile_t * ctx ) {
  for( ulong lane=0UL; lane<ctx->lane_cnt; lane++ ) {
    ctx->in[ lane ].pos = 0UL;
  }
  ctx->expected_frame         = 0UL;
  ctx->appendvec_seq          = 0UL;
  ctx->incr_fork              = ULONG_MAX;
  ctx->waiting_for_tile0      = 0;
  ctx->writer.buf_used        = 0UL;
  ctx->writer.batch.cnt       = 0UL;
  ctx->staged.data_len        = 0UL;
  ctx->staged.bytes_received  = 0UL;

  fd_memset( &ctx->worker, 0, sizeof(ctx->worker) );
  fd_ssparse_init( ctx->ssparse );
  fd_ssparse_batch_enable( ctx->ssparse, 1 );
}

/* Other tiles wait for tile 0 to finish shared setup before processing
   data.  Control messages are not blocked. */

static void
start_processing_attempt( fd_snapin_tile_t * ctx ) {
  FD_COMPILER_MFENCE();
  FD_TEST( FD_VOLATILE_CONST( ctx->shmem->attempt.number )==ctx->attempt_number );
  ctx->incr_fork = FD_VOLATILE_CONST( ctx->shmem->attempt.fork_id );
  if( FD_UNLIKELY( ctx->full ? ctx->incr_fork!=(ulong)USHORT_MAX : ctx->incr_fork>=(ulong)USHORT_MAX ) ) {
    FD_LOG_ERR(( "invalid attempt fork %lu (full=%d); this is a bug", ctx->incr_fork, (int)ctx->full ));
  }

  /* Claim before the first data fragment. */
  ctx->claimed_appendvec = FD_ATOMIC_FETCH_AND_ADD( &ctx->shmem->next_appendvec, 1UL );
  ctx->waiting_for_tile0 = 0;
}

static int
validate_capitalization( fd_snapin_tile_t * ctx ) {
  ulong capitalization = fd_ulong_if( ctx->full, 0UL, ctx->lead.recovery.capitalization );
  capitalization = fd_ulong_sat_add( capitalization, ctx->shmem->totals.input_lamports     );
  capitalization = fd_ulong_sat_sub( capitalization, ctx->shmem->totals.duplicate_lamports );
  if( FD_UNLIKELY( capitalization!=ctx->lead.manifest_capitalization ) ) {
    /* SnapshotError::MismatchedCapitalization
        https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/snapshot_bank_utils.rs#L217 */
    FD_LOG_WARNING(( "%s snapshot manifest capitalization %lu does not match computed capitalization %lu",
                     ctx->full?"full":"incr", ctx->lead.manifest_capitalization, capitalization ));
    return -1;
  }
  return 0;
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
      ctx->state = FD_SNAPSHOT_STATE_PROCESSING;
      ctx->full = sig==FD_SNAPSHOT_MSG_CTRL_INIT_FULL;

      reset_attempt_state( ctx );

      /* Rewind metric counters (no-op unless recovering from a fail) */
      if( sig==FD_SNAPSHOT_MSG_CTRL_INIT_FULL ) {
        ctx->metrics.accounts_loaded   = ctx->metrics.full_accounts_loaded   = 0;
        ctx->metrics.accounts_replaced = ctx->metrics.full_accounts_replaced = 0;
        ctx->metrics.accounts_ignored  = ctx->metrics.full_accounts_ignored  = 0;
        ctx->metrics.full_bytes_read   = 0UL;
        ctx->metrics.incremental_bytes_read = 0UL;
      } else {
        ctx->metrics.accounts_loaded   = ctx->metrics.full_accounts_loaded;
        ctx->metrics.accounts_replaced = ctx->metrics.full_accounts_replaced;
        ctx->metrics.accounts_ignored  = ctx->metrics.full_accounts_ignored;
        ctx->metrics.incremental_bytes_read = 0UL;
      }

      ctx->waiting_for_tile0 = 1;
      if( FD_LIKELY( !is_lead( ctx ) ) ) break;

      /* Roll back before publishing this attempt. */
      if( FD_UNLIKELY( ctx->lead.rollback.pending ) ) {
        ctx->lead.rollback.pending = 0;
        /* Purge failed incremental state unless a full reset follows. */
        if( !ctx->lead.rollback.full && FD_LIKELY( !ctx->full ) ) {
          fd_accdb_purge( ctx->accdb, ctx->lead.rollback.fork );
          fd_accdb_snapshot_revert_whead( ctx->accdb, &ctx->lead.recovery.accdb_metadata );
        }
      }

      ctx->lead.manifest_capitalization = 0UL;

      fd_txncache_reset( ctx->lead.txncache );
      txncache_staging_reset( ctx );
      ctx->lead.blockhash_groups = txncache_staging_scratch( ctx );
      fd_ssmanifest_parser_init( ctx->lead.manifest_parser, fd_chunk_to_laddr( ctx->lead.manifest_out.mem, ctx->lead.manifest_out.chunk ) );
      fd_slot_delta_parser_init( ctx->lead.slot_delta_parser );
      fd_memset( &ctx->lead.flags,    0, sizeof(ctx->lead.flags)    );

      if( sig==FD_SNAPSHOT_MSG_CTRL_INIT_FULL ) {
        ctx->lead.full_genesis_creation_time_seconds = 0UL;
        ctx->lead.recovery.capitalization            = 0UL;
        fd_memset( &ctx->lead.account_counts, 0, sizeof(ctx->lead.account_counts) );

        fd_stake_delegations_reset( ctx->stake_delegations );
        fd_accdb_reset( ctx->accdb );
        fd_accdb_fork_id_t null_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
        ctx->lead.accdb_root_fork_id = fd_accdb_attach_child( ctx->accdb, null_fork_id );

        fd_accdb_snapshot_load_begin( ctx->accdb );
      } else {
        /* Create a child fork for incremental writes.  On failure,
           fd_accdb_purge(child) reverts just the incremental changes.
           On success, fd_accdb_advance_root(child) promotes them. */
        ctx->lead.accdb_incr_fork_id = fd_accdb_attach_child( ctx->accdb, ctx->lead.accdb_root_fork_id );
      }

      /* Save the slot advertised by the snapshot peer and verify it
         against the slot in the snapshot manifest.  For redirect-based
         HTTP downloads, these are initial estimates from gossip and
         will be updated by the META message below once the redirect
         resolves to a concrete snapshot filename. */
      fd_ssctrl_init_t const * msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].wksp, chunk );
      ctx->lead.advertised_slot = msg->slot;
      fd_memcpy( ctx->lead.advertised_hash, msg->snapshot_hash, FD_HASH_FOOTPRINT );
      ctx->lead.init_completed = 1;

      /* Reset shared state before publishing the attempt slot. */
      fd_memset( &ctx->shmem->totals, 0, sizeof(ctx->shmem->totals) );
      FD_VOLATILE( ctx->shmem->next_appendvec ) = 0UL;
      FD_COMPILER_MFENCE();

      /* Publish last. Other tiles wait for this. */
      FD_VOLATILE( ctx->shmem->attempt.fork_id ) = ctx->full ? (ulong)USHORT_MAX : (ulong)ctx->lead.accdb_incr_fork_id.val;
      FD_COMPILER_MFENCE();
      FD_VOLATILE( ctx->shmem->attempt.number ) = ctx->attempt_number;

      /* Tile 0 opens now. Other tiles open in before_frag. */
      start_processing_attempt( ctx );
      break;
    }

    case FD_SNAPSHOT_MSG_META: {
      forward_msg = 0; /* snapct already receives META directly from snapld */
      if( FD_LIKELY( !is_lead( ctx ) ) ) break;

      /* For redirect-based HTTP downloads, the META message carries
         the resolved slot and hash from the actual snapshot filename
         the server redirected to.  Update the advertised values so
         that process_manifest can verify the manifest against them. */
      FD_TEST( sz==sizeof(fd_ssctrl_meta_t) );
      fd_ssctrl_meta_t const * meta = fd_chunk_to_laddr_const( ctx->in[ in_idx ].wksp, chunk );
      if( meta->resolved_slot!=ULONG_MAX ) {
        ctx->lead.advertised_slot = meta->resolved_slot;
        fd_memcpy( ctx->lead.advertised_hash, meta->resolved_hash, FD_HASH_FOOTPRINT );
      }
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
      if( FD_UNLIKELY( writer_flush( ctx ) ) ) {
        transition_malformed( ctx, stem );
        forward_msg = 0;
        break;
      }

      fd_accdb_flush_metrics( ctx->accdb );

      /* Add this tile's totals before the FINI ack. */
      FD_ATOMIC_FETCH_AND_ADD( &ctx->shmem->totals.loaded,             ctx->worker.loaded             );
      FD_ATOMIC_FETCH_AND_ADD( &ctx->shmem->totals.duplicates,         ctx->worker.duplicates         );
      FD_ATOMIC_FETCH_AND_ADD( &ctx->shmem->totals.input_lamports,     ctx->worker.input_lamports     );
      FD_ATOMIC_FETCH_AND_ADD( &ctx->shmem->totals.duplicate_lamports, ctx->worker.duplicate_lamports );
      FD_COMPILER_MFENCE(); /* publish before ack */

      /* Keep per-tile gauges. Dashboards sum them. */
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_NEXT: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_FINISHING );
      ctx->state = FD_SNAPSHOT_STATE_IDLE;

      /* Backup metric counters */
      ctx->metrics.full_accounts_loaded   = ctx->metrics.accounts_loaded;
      ctx->metrics.full_accounts_replaced = ctx->metrics.accounts_replaced;
      ctx->metrics.full_accounts_ignored  = ctx->metrics.accounts_ignored;

      /* Tile 0 only. */
      if( FD_LIKELY( !is_lead( ctx ) ) ) break;

      /* FINI acks make shared data stable. */
      if( FD_UNLIKELY( verify_slot_deltas_with_slot_history( ctx ) ) ) {
        FD_LOG_WARNING(( "slot deltas verification failed for full snapshot" ));
        transition_malformed( ctx, stem );
        forward_msg = 0;
        break;
      }

      if( FD_UNLIKELY( validate_capitalization( ctx )!=0 ) ) {
        transition_malformed( ctx, stem );
        forward_msg = 0;
        break;
      }

      ctx->lead.account_counts.loaded     += ctx->shmem->totals.loaded;
      ctx->lead.account_counts.duplicates += ctx->shmem->totals.duplicates;
      ctx->lead.recovery.capitalization    = ctx->lead.manifest_capitalization;
      fd_accdb_snapshot_save_whead( ctx->accdb, &ctx->lead.recovery.accdb_metadata );
      ctx->lead.init_completed = 0;
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_DONE: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_FINISHING );
      ctx->state = FD_SNAPSHOT_STATE_IDLE;
      if( FD_LIKELY( !is_lead( ctx ) ) ) break;

      if( FD_UNLIKELY( verify_slot_deltas_with_slot_history( ctx ) ) ) {
        if( ctx->full ) FD_LOG_WARNING(( "slot deltas verification failed for full snapshot" ));
        else            FD_LOG_WARNING(( "slot deltas verification failed for incremental snapshot" ));
        transition_malformed( ctx, stem );
        forward_msg = 0;
        break;
      }

      if( FD_UNLIKELY( validate_capitalization( ctx )!=0 ) ) {
        transition_malformed( ctx, stem );
        forward_msg = 0;
        break;
      }

      ctx->lead.account_counts.loaded     += ctx->shmem->totals.loaded;
      ctx->lead.account_counts.duplicates += ctx->shmem->totals.duplicates;
      if( !ctx->full ) {
        fd_accdb_snapshot_recover_delta( ctx->accdb, ctx->lead.accdb_incr_fork_id );
        /* ensure that snapin tile sees all delta changes before rooting */
        __atomic_thread_fence( __ATOMIC_SEQ_CST );
        fd_accdb_advance_root( ctx->accdb, ctx->lead.accdb_incr_fork_id );
        ctx->lead.accdb_root_fork_id = ctx->lead.accdb_incr_fork_id;
        ctx->lead.accdb_incr_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
      }

      fd_accdb_snapshot_load_end( ctx->accdb );

      /* TODO: Pass in tile_idx and tile_cnt when parallelizing snapin */
      fd_features_restore_chunk( &ctx->lead.bank->f.features, ctx->accdb, ctx->lead.accdb_root_fork_id, ctx->lead.bank_slot, &ctx->lead.epoch_schedule, 0UL, 1UL );

      /* Notify replay when snapshot is fully loaded and verified. */
      fd_stem_publish( stem, ctx->lead.manifest_out.idx, fd_ssmsg_sig( FD_SSMSG_DONE ), 0UL, 0UL, 0UL, 0UL, 0UL );
      ctx->lead.init_completed = 0;
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_ERROR: {
      FD_TEST( ctx->state!=FD_SNAPSHOT_STATE_SHUTDOWN );
      ctx->state = FD_SNAPSHOT_STATE_ERROR;
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_FAIL: {
      FD_TEST( ctx->state!=FD_SNAPSHOT_STATE_SHUTDOWN );
      fd_accdb_flush_metrics( ctx->accdb );

      FD_COMPILER_MFENCE();

      /* Reset the worker state for this full/incr loading attempt */
      reset_attempt_state( ctx );

      /* Defer rollback until the next INIT, which is triggered after
         all workers have sent their FAIL acks. */
      if( FD_UNLIKELY( is_lead( ctx ) ) ) {
        /* Only a completed INIT has valid state to roll back. */
        if( FD_LIKELY( ctx->lead.init_completed ) ) {
          ctx->lead.rollback.pending = 1;
          ctx->lead.rollback.full    = ctx->full;
          ctx->lead.rollback.fork    = ctx->lead.accdb_incr_fork_id;
          if( ctx->full ) ctx->lead.accdb_root_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
          ctx->lead.accdb_incr_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
        }
        ctx->lead.init_completed = 0;
      }

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

    if( FD_UNLIKELY( ctx->waiting_for_tile0 ) ) {
      if( FD_UNLIKELY( FD_VOLATILE_CONST( ctx->shmem->attempt.number )!=ctx->attempt_number ) ) {
        return -1;
      }

      start_processing_attempt( ctx );
    }
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
      ctx->attempt_number++;
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
  if( FD_UNLIKELY( out_fds_cnt<4UL ) ) FD_LOG_ERR(( "invalid out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2UL; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) {
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  }
  out_fds[ out_cnt++ ] = FD_ACCDB_FD_RW; /* accounts db */
  out_fds[ out_cnt++ ] = FD_STAKE_DELEGATIONS_FD; /* stake delegation disk spill */

  return out_cnt;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo; (void)tile;
  populate_sock_filter_policy_fd_snapin_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), FD_ACCDB_FD_RW, FD_STAKE_DELEGATIONS_FD );
  return sock_filter_policy_fd_snapin_tile_instr_cnt;
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  fd_snapin_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( ctx, 0, sizeof(fd_snapin_tile_t) );
  FD_TEST( fd_rng_secure( &ctx->lead.seed, 8UL ) );
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
  if( FD_UNLIKELY( ctx->tile_idx>=FD_TOPO_MAX_TILE_IN_LINKS ) ) FD_LOG_ERR(( "tile `" NAME "` has unsupported kind id %lu", tile->kind_id ));

  ctx->full            = 1;
  ctx->state           = FD_SNAPSHOT_STATE_IDLE;
  ctx->lane_cnt        = tile->in_cnt;
  ctx->attempt_number  = 0UL;
  clear_control_barrier( ctx );
  fd_memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  void * _accdb_shmem = fd_topo_obj_laddr( topo, tile->snapin.accdb_obj_id );
  fd_accdb_shmem_t * accdb_shmem = fd_accdb_shmem_join( _accdb_shmem );
  FD_TEST( accdb_shmem );

  ctx->accdb = fd_accdb_join( fd_accdb_new( _accdb, accdb_shmem, FD_ACCDB_FD_RW, 0UL, NULL ) );
  FD_TEST( ctx->accdb );

  ctx->shmem = fd_topo_obj_laddr( topo, tile->snapin.shmem_obj_id );

  /* Every tile updates stakes. Only tile 0 owns the bank. */
  fd_banks_t * banks = fd_banks_join( fd_topo_obj_laddr( topo, tile->snapin.banks_obj_id ) );
  FD_TEST( banks );
  ctx->stake_delegations = fd_banks_stake_delegations_root_query( banks );
  FD_TEST( ctx->stake_delegations );

  ctx->ct_out = out1( topo, tile, "snapin_ct", ctx->tile_idx );
  if( FD_UNLIKELY( ctx->ct_out.idx==ULONG_MAX ) ) FD_LOG_ERR(( "tile `" NAME ":%lu` missing required out link `snapin_ct`", ctx->tile_idx ));

  ctx->gui_out = out1( topo, tile, "snapin_gui", ctx->tile_idx );

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

  reset_attempt_state( ctx );
  if( FD_LIKELY( !is_lead( ctx ) ) ) return;

  /* Tile 0 state. */
  ctx->lead.init_completed = 0;
  ctx->lead.txncache_max_groups_per_slot = tile->snapin.max_txn_per_slot;
  ctx->lead.txncache_max_entries_per_slot = 2UL*tile->snapin.max_txn_per_slot;

  void * _txncache           = FD_SCRATCH_ALLOC_APPEND( l, fd_txncache_align(),               fd_txncache_footprint( tile->snapin.max_live_slots ) );
  void * _manifest_parser    = FD_SCRATCH_ALLOC_APPEND( l, fd_ssmanifest_parser_align(),      fd_ssmanifest_parser_footprint()                             );
  void * _sd_parser          = FD_SCRATCH_ALLOC_APPEND( l, fd_slot_delta_parser_align(),      fd_slot_delta_parser_footprint()                             );
  ctx->lead.recent_groups    = FD_SCRATCH_ALLOC_APPEND( l, alignof(recent_blockhash_group_t), sizeof(recent_blockhash_group_t)*FD_SNAPIN_MAX_RECENT_GROUPS );
  ctx->lead.txncache_entries = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sstxncache_hash_t),     sizeof(fd_sstxncache_hash_t)*FD_TXNCACHE_MAX_SLOT_DELTAS*2UL*tile->snapin.max_txn_per_slot );

  void * _txncache_shmem = fd_topo_obj_laddr( topo, tile->snapin.txncache_obj_id );
  fd_txncache_shmem_t * txncache_shmem = fd_txncache_shmem_join( _txncache_shmem );
  FD_TEST( txncache_shmem );
  ctx->lead.txncache = fd_txncache_join( fd_txncache_new( _txncache, txncache_shmem ) );
  FD_TEST( ctx->lead.txncache );

  ctx->lead.blockhash_groups = NULL;
  txncache_staging_reset( ctx );

  ctx->lead.bank = fd_banks_init_bank( banks );
  FD_TEST( ctx->lead.bank );
  FD_TEST( ctx->lead.bank->idx==0UL );

  ctx->lead.manifest_parser = fd_ssmanifest_parser_join( fd_ssmanifest_parser_new( _manifest_parser ) );
  FD_TEST( ctx->lead.manifest_parser );

  ctx->lead.slot_delta_parser = fd_slot_delta_parser_join( fd_slot_delta_parser_new( _sd_parser ) );
  FD_TEST( ctx->lead.slot_delta_parser );

  ctx->lead.manifest_out = out1( topo, tile, "snapin_manif", 0UL );
  if( FD_UNLIKELY( ctx->lead.manifest_out.idx==ULONG_MAX ) ) FD_LOG_ERR(( "tile `" NAME "` missing required out link `snapin_manif`" ));

  fd_ssmanifest_parser_init( ctx->lead.manifest_parser, fd_chunk_to_laddr( ctx->lead.manifest_out.mem, ctx->lead.manifest_out.chunk ) );
  fd_slot_delta_parser_init( ctx->lead.slot_delta_parser );

  ctx->lead.advertised_slot = 0UL;
  ctx->lead.bank_slot       = 0UL;
  ctx->lead.epoch           = 0UL;
  ctx->lead.full_genesis_creation_time_seconds = 0UL;
  ctx->lead.manifest_capitalization            = 0UL;
  ctx->lead.recovery.capitalization            = 0UL;
  fd_memset( &ctx->lead.account_counts, 0, sizeof(ctx->lead.account_counts) );
  ctx->lead.accdb_root_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  ctx->lead.accdb_incr_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  fd_memset( &ctx->lead.recovery.accdb_metadata, 0, sizeof(ctx->lead.recovery.accdb_metadata) );
  fd_memset( &ctx->lead.flags, 0, sizeof(ctx->lead.flags) );
  ctx->lead.boot_timestamp = fd_log_wallclock();
}

/* There are 3 output links that affect the calculation of STEM_BURST:
    1. snapin_ct    - worst case: 1 message (ack or unsolicited ERROR)
    2. snapin_manif - worst case: 1 message (tile 0 only)
    3. snapin_gui   - worst case: 1 message (config program account)
   The STEM_BURST is the max value across these 3 links (not the sum).
   Note that snapin_txn is excluded from this calculation, since it is
   an unreliable link, working as a dcache place holder. */
#define STEM_BURST 1UL

#define STEM_LAZY  (128L*3000L)

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

static ulong
snapin_shmem_footprint( fd_topo_t const *     topo FD_PARAM_UNUSED,
                        fd_topo_obj_t const * obj  FD_PARAM_UNUSED ) {
  return sizeof(fd_snapin_shmem_t);
}

static ulong
snapin_shmem_align( fd_topo_t const *     topo FD_PARAM_UNUSED,
                    fd_topo_obj_t const * obj  FD_PARAM_UNUSED ) {
  return alignof(fd_snapin_shmem_t);
}

static void
snapin_shmem_new( fd_topo_t const *     topo,
                  fd_topo_obj_t const * obj ) {
  fd_memset( fd_topo_obj_laddr( topo, obj->id ), 0, sizeof(fd_snapin_shmem_t) );
}

fd_topo_obj_callbacks_t fd_obj_cb_snapin_shmem = {
  .name      = "snapin_shmem",
  .footprint = snapin_shmem_footprint,
  .align     = snapin_shmem_align,
  .new       = snapin_shmem_new,
};

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

#include "utils/fd_ssctrl.h"
#include "utils/fd_snapshot_parser.h"
#include "utils/fd_ssmsg.h"

#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../flamenco/types/fd_types.h"
#include "../../funk/fd_funk.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_slot_history.h"

#define NAME "snapin"

/* The snapin tile is a state machine that parses and loads a full
   and optionally an incremental snapshot.  It is currently responsible
   for loading accounts into an in-memory database, though this may
   change. */

#define FD_SNAPIN_STATE_LOADING   (0) /* We are inserting accounts from a snapshot */
#define FD_SNAPIN_STATE_DONE      (1) /* We are done inserting accounts from a snapshot */
#define FD_SNAPIN_STATE_MALFORMED (2) /* The snapshot is malformed, we are waiting for a reset notification */
#define FD_SNAPIN_STATE_SHUTDOWN  (3) /* The tile is done, been told to shut down, and has likely already exited */

/* 300 here is from status_cache.rs::MAX_CACHE_ENTRIES which is the most
   root slots Agave could possibly serve in a snapshot. */
#define FD_SNAPIN_TXNCACHE_MAX_ENTRIES (300UL*FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT)

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
#define MAP_KEY_HASH(key,seed)             (fd_hash((seed),(key),sizeof(fd_hash_t)))
#define MAP_PREV                           map.prev
#define MAP_NEXT                           map.next
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

struct blockhash_group {
  uchar blockhash[ 32UL ];
  ulong txnhash_offset;
};

typedef struct blockhash_group blockhash_group_t;

struct fd_snapin_tile {
  int full;
  int state;

  ulong seed;
  long boot_timestamp;

  fd_funk_t       funk[1];
  fd_txncache_t * txncache;
  uchar *         acc_data;

  fd_funk_txn_xid_t xid[1]; /* txn XID */

  fd_stem_context_t *    stem;
  fd_snapshot_parser_t * ssparse;
  ulong                  bank_slot;

  ulong blockhash_offsets_len;
  blockhash_group_t * blockhash_offsets;

  ulong txncache_entries_len;
  fd_sstxncache_entry_t * txncache_entries;

  fd_txncache_fork_id_t txncache_root_fork_id;

  struct {
    ulong full_bytes_read;
    ulong incremental_bytes_read;
    ulong accounts_inserted;
  } metrics;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  } in;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       chunk;
    ulong       mtu;
  } manifest_out;
};

typedef struct fd_snapin_tile fd_snapin_tile_t;

static inline int
should_shutdown( fd_snapin_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->state==FD_SNAPIN_STATE_SHUTDOWN ) ) {
    FD_LOG_NOTICE(( "loaded %.1fM accounts from snapshot in %.1f seconds", (double)ctx->metrics.accounts_inserted/1e6, (double)(fd_log_wallclock()-ctx->boot_timestamp)/1e9 ));
  }
  return ctx->state==FD_SNAPIN_STATE_SHUTDOWN;
}

static ulong
scratch_align( void ) {
  return 128UL;
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapin_tile_t),  sizeof(fd_snapin_tile_t)                             );
  l = FD_LAYOUT_APPEND( l, fd_snapshot_parser_align(), fd_snapshot_parser_footprint( 1UL<<24UL )            );
  if( FD_LIKELY( tile->snapin.txncache_obj_id!=ULONG_MAX ) ) {
    l = FD_LAYOUT_APPEND( l, fd_txncache_align(),      fd_txncache_footprint( tile->snapin.max_live_slots ) );
  }
  l = FD_LAYOUT_APPEND( l, alignof(fd_sstxncache_entry_t), sizeof(fd_sstxncache_entry_t)*FD_SNAPIN_TXNCACHE_MAX_ENTRIES );
  l = FD_LAYOUT_APPEND( l, alignof(blockhash_group_t),     sizeof(blockhash_group_t)*FD_SNAPIN_MAX_SLOT_DELTA_GROUPS );
  return FD_LAYOUT_FINI( l, alignof(fd_snapin_tile_t) );
}

static void
metrics_write( fd_snapin_tile_t * ctx ) {
  // FD_MGAUGE_SET( SNAPIN, FULL_BYTES_READ, ctx->metrics.full_bytes_read );
  // FD_MGAUGE_SET( SNAPIN, INCREMENTAL_BYTES_READ, ctx->metrics.incremental_bytes_read );

  FD_MGAUGE_SET( SNAPIN, ACCOUNTS_INSERTED, ctx->metrics.accounts_inserted );
  FD_MGAUGE_SET( SNAPIN, STATE, (ulong)ctx->state );
}

static int
verify_slot_deltas_with_slot_history( fd_snapin_tile_t *         ctx,
                                      fd_slot_history_global_t * slot_history ) {

  for( ulong i=0UL; i<ctx->txncache_entries_len; i++ ) {
    fd_sstxncache_entry_t const * entry = &ctx->txncache_entries[i];
    if( FD_UNLIKELY( fd_sysvar_slot_history_find_slot( slot_history, entry->slot, NULL )!=FD_SLOT_HISTORY_SLOT_FOUND ) ) return -1;
  }
  return 0;
}

static int
verify_slot_deltas_with_bank_slot( fd_snapin_tile_t * ctx,
                                   ulong              bank_slot ) {
  for( ulong i=0UL; i<ctx->txncache_entries_len; i++ ) {
    fd_sstxncache_entry_t const * entry = &ctx->txncache_entries[i];
    if( FD_UNLIKELY( entry->slot>bank_slot ) ) return -1;
  }
  return 0;
}

static void
transition_malformed( fd_snapin_tile_t * ctx,
                     fd_stem_context_t * stem ) {
  ctx->state = FD_SNAPIN_STATE_MALFORMED;
  fd_stem_publish( stem, 1UL, FD_SNAPSHOT_MSG_CTRL_MALFORMED, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static int
populate_txncache( fd_snapin_tile_t *                     ctx,
                   fd_snapshot_manifest_blockhash_t const blockhashes[ static 301UL ],
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
     BLOCKHASH_QUEUE array in the manifest.  This array is unfortuantely
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
    entries are collected by referece blockhash, not executed slot.

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

  FD_TEST( blockhashes_len<=301UL );
  FD_TEST( blockhashes_len>0UL );

  ulong seq_min = ULONG_MAX;
  for( ulong i=0UL; i<blockhashes_len; i++ ) seq_min = fd_ulong_min( seq_min, blockhashes[ i ].hash_index );

  ulong seq_max;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( seq_min, blockhashes_len, &seq_max ) ) ) {
    FD_LOG_WARNING(( "corrupt snapshot: blockhash queue sequence number wraparound (seq_min=%lu age_cnt=%lu)", seq_min, blockhashes_len ));
    transition_malformed( ctx, ctx->stem );
    return 1;
  }

  /* First let's construct the chain array as described above.  But
     index 0 will be the root, index 1 the root's parent, etc. */

  struct {
    int exists;
    uchar blockhash[ 32UL ];
    fd_txncache_fork_id_t fork_id;
    ulong txnhash_offset;
  } banks[ 301UL ] = {0};

  for( ulong i=0UL; i<blockhashes_len; i++ ) {
    fd_snapshot_manifest_blockhash_t const * elem = &blockhashes[ i ];
    ulong idx;
    if( FD_UNLIKELY( __builtin_usubl_overflow( elem->hash_index, seq_min, &idx ) ) ) {
      FD_LOG_WARNING(( "corrupt snapshot: gap in blockhash queue (seq=[%lu,%lu) idx=%lu)", seq_min, seq_max, blockhashes[ i ].hash_index ));
      transition_malformed( ctx, ctx->stem );
      return 1;
    }

    if( FD_UNLIKELY( idx>=blockhashes_len ) ) {
      FD_LOG_WARNING(( "corrupt snapshot: blockhash queue index out of range (seq_min=%lu age_cnt=%lu idx=%lu)", seq_min, blockhashes_len, idx ));
      transition_malformed( ctx, ctx->stem );
      return 1;
    }

    if( FD_UNLIKELY( banks[ blockhashes_len-1UL-idx ].exists ) ) {
      FD_LOG_WARNING(( "corrupt snapshot: duplicate blockhash hash_index %lu", elem->hash_index ));
      transition_malformed( ctx, ctx->stem );
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

  uchar * _map = fd_alloca_check( alignof(blockhash_map_t), blockhash_map_footprint( 1024UL ) );
  blockhash_map_t * blockhash_map = blockhash_map_join( blockhash_map_new( _map, 1024UL, ctx->seed ) );
  FD_TEST( blockhash_map );

  fd_blockhash_entry_t blockhash_pool[ 151UL ];
  for( ulong i=0UL; i<chain_len; i++ ) {
    fd_memcpy( blockhash_pool[ i ].blockhash.uc, banks[ i ].blockhash, 32UL );

    if( FD_UNLIKELY( blockhash_map_ele_query_const( blockhash_map, &blockhash_pool[ i ].blockhash, NULL, blockhash_pool ) ) ) {
      FD_LOG_WARNING(( "corrupt snapshot: duplicate blockhash %s in 151 most recent blockhashes", FD_BASE58_ENC_32_ALLOCA( banks[ i ].blockhash ) ));
      transition_malformed( ctx, ctx->stem );
      return 1;
    }

    blockhash_map_ele_insert( blockhash_map, &blockhash_pool[ i ], blockhash_pool );
  }

  /* Now load the blockhash offsets for these blockhashes ... */
  FD_TEST( ctx->blockhash_offsets_len ); /* Must be at least one else nothing would be rooted */
  for( ulong i=0UL; i<ctx->blockhash_offsets_len; i++ ) {
    fd_hash_t key;
    fd_memcpy( key.uc, ctx->blockhash_offsets[ i ].blockhash, 32UL );
    fd_blockhash_entry_t * entry = blockhash_map_ele_query( blockhash_map, &key, NULL, blockhash_pool );
    if( FD_UNLIKELY( !entry ) ) continue; /* Not in the most recent 151 blockhashes */

    ulong chain_idx = (ulong)(entry - blockhash_pool);

    if( FD_UNLIKELY( banks[ chain_idx ].txnhash_offset!=ULONG_MAX && banks[ chain_idx ].txnhash_offset!=ctx->blockhash_offsets[ i ].txnhash_offset ) ) {
      FD_LOG_WARNING(( "corrupt snapshot: conflicting txnhash offsets for blockhash %s", FD_BASE58_ENC_32_ALLOCA( entry->blockhash.uc ) ));
      transition_malformed( ctx, ctx->stem );
      return 1;
    }

    banks[ chain_idx ].txnhash_offset = ctx->blockhash_offsets[ i ].txnhash_offset;
  }

  /* Construct the linear fork chain in the txncache. */

  fd_txncache_fork_id_t parent = { .val = USHORT_MAX };
  for( ulong i=0UL; i<chain_len; i++ ) banks[ chain_len-1UL-i ].fork_id = parent = fd_txncache_attach_child( ctx->txncache, parent );
  for( ulong i=0UL; i<chain_len; i++ ) fd_txncache_attach_blockhash( ctx->txncache, banks[ i ].fork_id, banks[ i ].blockhash );

  /* Now insert all transactions as if they executed at the current
     root, per above. */

  ulong insert_cnt = 0UL;
  for( ulong i=0UL; i<ctx->txncache_entries_len; i++ ) {
    fd_sstxncache_entry_t const * entry = &ctx->txncache_entries[ i ];
    fd_hash_t key;
    fd_memcpy( key.uc, entry->blockhash, 32UL );
    if( FD_UNLIKELY( !blockhash_map_ele_query_const( blockhash_map, &key, NULL, blockhash_pool ) ) ) continue;

    insert_cnt++;
    fd_txncache_insert( ctx->txncache, banks[ 0UL ].fork_id, entry->blockhash, entry->txnhash );
  }

  FD_LOG_INFO(( "inserted %lu/%lu transactions into the txncache", insert_cnt, ctx->txncache_entries_len ));

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
manifest_cb( void * _ctx ) {
  fd_snapin_tile_t * ctx = (fd_snapin_tile_t*)_ctx;

  fd_snapshot_manifest_t * manifest = fd_chunk_to_laddr( ctx->manifest_out.wksp, ctx->manifest_out.chunk );
  ulong bank_slot = ctx->bank_slot = manifest->slot;
  if( FD_UNLIKELY( verify_slot_deltas_with_bank_slot( ctx, bank_slot ) ) ) {
    FD_LOG_WARNING(( "slot deltas verification failed" ));
    transition_malformed( ctx, ctx->stem );
    return;
  }

  if( FD_UNLIKELY( populate_txncache( ctx, manifest->blockhashes, manifest->blockhashes_len ) ) ) return;
  manifest->txncache_fork_id = ctx->txncache_root_fork_id.val;

  ulong sig = ctx->full ? fd_ssmsg_sig( FD_SSMSG_MANIFEST_FULL ) :
                          fd_ssmsg_sig( FD_SSMSG_MANIFEST_INCREMENTAL );
  fd_stem_publish( ctx->stem, 0UL, sig, ctx->manifest_out.chunk, sizeof(fd_snapshot_manifest_t), 0UL, 0UL, 0UL );
  ctx->manifest_out.chunk = fd_dcache_compact_next( ctx->manifest_out.chunk, sizeof(fd_snapshot_manifest_t), ctx->manifest_out.chunk0, ctx->manifest_out.wmark );
}

static void
status_cache_group_cb( void *        _ctx,
                       uchar const * blockhash,
                       ulong         txnhash_offset ) {
  fd_snapin_tile_t * ctx = (fd_snapin_tile_t*)_ctx;

  if( FD_UNLIKELY( ctx->blockhash_offsets_len>=FD_SNAPIN_MAX_SLOT_DELTA_GROUPS ) ) FD_LOG_ERR(( "blockhash offsets overflow, max is %lu", FD_SNAPIN_MAX_SLOT_DELTA_GROUPS ));

  memcpy( ctx->blockhash_offsets[ ctx->blockhash_offsets_len ].blockhash, blockhash, 32UL );
  ctx->blockhash_offsets[ ctx->blockhash_offsets_len ].txnhash_offset = txnhash_offset;
  ctx->blockhash_offsets_len++;
}

static void
status_cache_entry_cb( void *                        _ctx,
                       fd_sstxncache_entry_t const * entry ) {
  fd_snapin_tile_t * ctx = (fd_snapin_tile_t*)_ctx;

  if( FD_UNLIKELY( ctx->txncache_entries_len>=FD_SNAPIN_TXNCACHE_MAX_ENTRIES ) ) FD_LOG_ERR(( "txncache entries overflow, max is %lu", FD_SNAPIN_TXNCACHE_MAX_ENTRIES ));

  ctx->txncache_entries[ ctx->txncache_entries_len++ ] = *entry;
}

static void
account_cb( void *                          _ctx,
            fd_solana_account_hdr_t const * hdr ) {
  fd_snapin_tile_t * ctx = (fd_snapin_tile_t*)_ctx;

  fd_funk_rec_key_t id = fd_funk_acc_key( (fd_pubkey_t*)hdr->meta.pubkey );
  fd_funk_rec_query_t query[1];
  fd_funk_rec_t const * rec = fd_funk_rec_query_try( ctx->funk, ctx->xid, &id, query );

  int should_publish = 0;
  fd_funk_rec_prepare_t prepare[1];
  if( FD_LIKELY( !rec ) ) {
    should_publish = 1;
    rec = fd_funk_rec_prepare( ctx->funk, ctx->xid, &id, prepare, NULL );
    FD_TEST( rec );
  }

  fd_account_meta_t * meta = fd_funk_val( rec, ctx->funk->wksp );
  if( FD_UNLIKELY( meta ) ) {
    if( FD_LIKELY( meta->slot>ctx->ssparse->accv_slot ) ) {
      ctx->acc_data = NULL;
      return;
    }

    /* TODO: Reaching here means the existing value is a duplicate
       account.  We need to hash the existing account and subtract that
       hash from the running lthash. */
  }

  if( FD_LIKELY( rec->val_sz<sizeof(fd_account_meta_t)+hdr->meta.data_len ) ) {
    meta = fd_funk_val_truncate( (fd_funk_rec_t*)rec, ctx->funk->alloc, ctx->funk->wksp, 0UL, sizeof(fd_account_meta_t)+hdr->meta.data_len, NULL );
    FD_TEST( meta );
  }

  meta->dlen       = (uint)hdr->meta.data_len;
  meta->slot       = ctx->ssparse->accv_slot;
  memcpy( meta->owner, hdr->info.owner, sizeof(fd_pubkey_t) );
  meta->lamports   = hdr->info.lamports;
  meta->executable = hdr->info.executable;

  ctx->acc_data = (uchar*)meta + sizeof(fd_account_meta_t);
  ctx->metrics.accounts_inserted++;

  if( FD_LIKELY( should_publish ) ) fd_funk_rec_publish( ctx->funk, prepare );
}

static void
account_data_cb( void *        _ctx,
                 uchar const * buf,
                 ulong         data_sz ) {
  fd_snapin_tile_t * ctx = (fd_snapin_tile_t*)_ctx;
  if( FD_UNLIKELY( !ctx->acc_data ) ) return;

  fd_memcpy( ctx->acc_data, buf, data_sz );
  ctx->acc_data += data_sz;
}

static void
handle_data_frag( fd_snapin_tile_t *  ctx,
                  ulong               chunk,
                  ulong               sz,
                  fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( ctx->state==FD_SNAPIN_STATE_MALFORMED ) ) return;

  FD_TEST( ctx->state==FD_SNAPIN_STATE_LOADING || ctx->state==FD_SNAPIN_STATE_DONE );
  FD_TEST( chunk>=ctx->in.chunk0 && chunk<=ctx->in.wmark && sz<=ctx->in.mtu );

  if( FD_UNLIKELY( ctx->state==FD_SNAPIN_STATE_DONE ) ) {
    FD_LOG_WARNING(( "received data fragment while in done state" ));
    transition_malformed( ctx, stem );
    return;
  }

  uchar const * const chunk_start = fd_chunk_to_laddr_const( ctx->in.wksp, chunk );
  uchar const * const chunk_end = chunk_start + sz;
  uchar const *       cur       = chunk_start;

  for(;;) {
    if( FD_UNLIKELY( cur>=chunk_end ) ) {
      break;
    }

    cur = fd_snapshot_parser_process_chunk( ctx->ssparse, cur, (ulong)( chunk_end-cur ) );
    if( FD_UNLIKELY( ctx->ssparse->flags ) ) {
      if( FD_UNLIKELY( ctx->ssparse->flags & SNAP_FLAG_FAILED ) ) {
        transition_malformed( ctx, stem );
        return;
      }
    }
  }

  if( FD_UNLIKELY( ctx->ssparse->flags & SNAP_FLAG_DONE ) ) ctx->state = FD_SNAPIN_STATE_DONE;

  if( FD_LIKELY( ctx->full ) ) ctx->metrics.full_bytes_read += sz;
  else                         ctx->metrics.incremental_bytes_read += sz;
}

static void
handle_control_frag( fd_snapin_tile_t *  ctx,
                     fd_stem_context_t * stem,
                     ulong               sig ) {
  switch( sig ) {
    case FD_SNAPSHOT_MSG_CTRL_RESET_FULL:
      ctx->full = 1;
      ctx->txncache_entries_len = 0UL;
      ctx->blockhash_offsets_len = 0UL;
      fd_txncache_reset( ctx->txncache );
      fd_snapshot_parser_reset( ctx->ssparse, fd_chunk_to_laddr( ctx->manifest_out.wksp, ctx->manifest_out.chunk ), ctx->manifest_out.mtu );
      fd_funk_txn_remove_published( ctx->funk );
      ctx->state = FD_SNAPIN_STATE_LOADING;
      break;
    case FD_SNAPSHOT_MSG_CTRL_RESET_INCREMENTAL:
      ctx->full = 0;
      ctx->txncache_entries_len = 0UL;
      ctx->blockhash_offsets_len = 0UL;
      fd_txncache_reset( ctx->txncache );
      fd_snapshot_parser_reset( ctx->ssparse, fd_chunk_to_laddr( ctx->manifest_out.wksp, ctx->manifest_out.chunk ), ctx->manifest_out.mtu );
      fd_funk_txn_cancel( ctx->funk, ctx->xid );
      fd_funk_txn_xid_copy( ctx->xid, fd_funk_last_publish( ctx->funk ) );
      ctx->state = FD_SNAPIN_STATE_LOADING;
      break;
    case FD_SNAPSHOT_MSG_CTRL_EOF_FULL:
      FD_TEST( ctx->full );
      if( FD_UNLIKELY( ctx->state!=FD_SNAPIN_STATE_DONE ) ) {
        FD_LOG_WARNING(( "unexpected end of snapshot when not done parsing" ));
        transition_malformed( ctx, stem );
        break;
      }

      ctx->txncache_entries_len = 0UL;
      ctx->blockhash_offsets_len = 0UL;
      fd_txncache_reset( ctx->txncache );
      fd_snapshot_parser_reset( ctx->ssparse, fd_chunk_to_laddr( ctx->manifest_out.wksp, ctx->manifest_out.chunk ), ctx->manifest_out.mtu );

      fd_funk_txn_xid_t incremental_xid = fd_funk_generate_xid();
      fd_funk_txn_prepare( ctx->funk, ctx->xid, &incremental_xid );
      fd_funk_txn_xid_copy( ctx->xid, &incremental_xid );

      ctx->full     = 0;
      ctx->state    = FD_SNAPIN_STATE_LOADING;
      break;
    case FD_SNAPSHOT_MSG_CTRL_DONE: {
      if( FD_UNLIKELY( ctx->state!=FD_SNAPIN_STATE_DONE ) ) {
        FD_LOG_WARNING(( "unexpected end of snapshot when not done parsing" ));
        transition_malformed( ctx, stem );
        break;
      }

      uchar slot_history_mem[ FD_SYSVAR_SLOT_HISTORY_FOOTPRINT ];
      fd_slot_history_global_t * slot_history = fd_sysvar_slot_history_read( ctx->funk, ctx->xid, slot_history_mem );
      if( FD_UNLIKELY( verify_slot_deltas_with_slot_history( ctx, slot_history ) ) ) {
        FD_LOG_WARNING(( "slot deltas verification failed" ));
        transition_malformed( ctx, stem );
        break;
      }

      /* Publish any remaining funk txn */
      if( FD_LIKELY( fd_funk_last_publish_is_frozen( ctx->funk ) ) ) {
        fd_funk_txn_publish_into_parent( ctx->funk, ctx->xid );
      }
      FD_TEST( !fd_funk_last_publish_is_frozen( ctx->funk ) );

      /* Make 'Last published' XID equal the restored slot number */
      fd_funk_txn_xid_t target_xid = { .ul = { ctx->bank_slot, ctx->bank_slot } };
      fd_funk_txn_prepare( ctx->funk, ctx->xid, &target_xid );
      fd_funk_txn_publish_into_parent( ctx->funk, &target_xid );
      fd_funk_txn_xid_copy( ctx->xid, &target_xid );

      fd_stem_publish( stem, 0UL, fd_ssmsg_sig( FD_SSMSG_DONE ), 0UL, 0UL, 0UL, 0UL, 0UL );
      break;
    }
    case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN:
      ctx->state = FD_SNAPIN_STATE_SHUTDOWN;
      metrics_write( ctx ); /* ensures that shutdown state is written to metrics workspace before the tile actually shuts down */
      break;
    default:
      FD_LOG_ERR(( "unexpected control sig %lu", sig ));
      return;
  }

  /* We must acknowledge after handling the control frag, because if it
     causes us to generate a malformed transition, that must be sent
     back to the snaprd controller before the acknowledgement. */
  fd_stem_publish( stem, 1UL, FD_SNAPSHOT_MSG_CTRL_ACK, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static inline int
returnable_frag( fd_snapin_tile_t *  ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)in_idx;
  (void)seq;
  (void)ctl;
  (void)tsorig;
  (void)tspub;

  ctx->stem = stem;

  FD_TEST( ctx->state!=FD_SNAPIN_STATE_SHUTDOWN );

  if( FD_UNLIKELY( sig==FD_SNAPSHOT_MSG_DATA ) ) handle_data_frag( ctx, chunk, sz, stem );
  else                                           handle_control_frag( ctx, stem, sig  );

  return 0;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapin_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapin_tile_t), sizeof(fd_snapin_tile_t) );

  FD_TEST( fd_rng_secure( &ctx->seed, 8UL ) );
}

FD_FN_UNUSED static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapin_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapin_tile_t),  sizeof(fd_snapin_tile_t)                  );
  void * _ssparse        = FD_SCRATCH_ALLOC_APPEND( l, fd_snapshot_parser_align(), fd_snapshot_parser_footprint( 1UL<<24UL ) );
  void * _txncache       = NULL;
  if( FD_LIKELY( tile->snapin.txncache_obj_id!=ULONG_MAX ) ) {
    _txncache            = FD_SCRATCH_ALLOC_APPEND( l, fd_txncache_align(),        fd_txncache_footprint( tile->snapin.max_live_slots ) );
  }
  ctx->txncache_entries  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sstxncache_entry_t), sizeof(fd_sstxncache_entry_t)*FD_SNAPIN_TXNCACHE_MAX_ENTRIES );
  ctx->blockhash_offsets = FD_SCRATCH_ALLOC_APPEND( l, alignof(blockhash_group_t),     sizeof(blockhash_group_t)*FD_SNAPIN_MAX_SLOT_DELTA_GROUPS );

  ctx->full = 1;
  ctx->state = FD_SNAPIN_STATE_LOADING;

  ctx->boot_timestamp = fd_log_wallclock();

  FD_TEST( fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, tile->snapin.funk_obj_id ) ) );
  fd_funk_txn_xid_set_root( ctx->xid );

  if( FD_LIKELY( tile->snapin.txncache_obj_id!=ULONG_MAX ) ) {
    void * _txncache_shmem = fd_topo_obj_laddr( topo, tile->snapin.txncache_obj_id );
    fd_txncache_shmem_t * txncache_shmem = fd_txncache_shmem_join( _txncache_shmem );
    FD_TEST( txncache_shmem );
    ctx->txncache = fd_txncache_join( fd_txncache_new( _txncache, txncache_shmem ) );
    FD_TEST( ctx->txncache );
  } else {
    ctx->txncache = NULL;
  }

  ctx->txncache_entries_len = 0UL;
  ctx->blockhash_offsets_len = 0UL;

  ctx->ssparse = fd_snapshot_parser_new( _ssparse, ctx, ctx->seed, 1UL<<24UL, manifest_cb, status_cache_group_cb, status_cache_entry_cb, account_cb, account_data_cb );
  FD_TEST( ctx->ssparse );

  fd_memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  if( FD_UNLIKELY( tile->kind_id ) ) FD_LOG_ERR(( "There can only be one `" NAME "` tile" ));
  if( FD_UNLIKELY( tile->in_cnt!=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 1",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=2UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 2",  tile->out_cnt  ));

  fd_topo_link_t * writer_link = &topo->links[ tile->out_link_id[ 0UL ] ];
  ctx->manifest_out.wksp    = topo->workspaces[ topo->objs[ writer_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->manifest_out.chunk0  = fd_dcache_compact_chunk0( fd_wksp_containing( writer_link->dcache ), writer_link->dcache );
  ctx->manifest_out.wmark   = fd_dcache_compact_wmark ( ctx->manifest_out.wksp, writer_link->dcache, writer_link->mtu );
  ctx->manifest_out.chunk   = ctx->manifest_out.chunk0;
  ctx->manifest_out.mtu     = writer_link->mtu;

  fd_snapshot_parser_reset( ctx->ssparse, fd_chunk_to_laddr( ctx->manifest_out.wksp, ctx->manifest_out.chunk ), ctx->manifest_out.mtu );

  fd_topo_link_t const * in_link = &topo->links[ tile->in_link_id[ 0UL ] ];
  fd_topo_wksp_t const * in_wksp = &topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ];
  ctx->in.wksp                   = in_wksp->wksp;;
  ctx->in.chunk0                 = fd_dcache_compact_chunk0( ctx->in.wksp, in_link->dcache );
  ctx->in.wmark                  = fd_dcache_compact_wmark( ctx->in.wksp, in_link->dcache, in_link->mtu );
  ctx->in.mtu                    = in_link->mtu;
}

#define STEM_BURST 2UL /* For control fragments, one acknowledgement, and one malformed message */
#define STEM_LAZY  1000L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snapin_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snapin_tile_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snapin = {
  .name              = NAME,
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .privileged_init   = privileged_init,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run,
};

#undef NAME

#include "fd_txncache_writer.h"
#include "../../flamenco/runtime/fd_txncache_private.h"
#include "../../util/fd_util.h"

/* Serialize the rooted contents of a txncache as a Solana status cache,
   a bincode Vec<(Slot, bool, HashMap<Hash, (usize, Vec<([u8;20], Result)>)>)>.

   Agave groups the entries of a slot delta by the blockhash the
   transaction referenced, and there is one slot delta per rooted slot.
   Our txncache is arranged the other way around: entries live in the
   blockcache of the blockhash they referenced, and only remember the
   fork they executed on.  Every rooted blockcache is therefore both one
   slot delta and a potential blockhash group of every slot delta, so
   the serialization walks the rooted list twice, once per axis. */

/* Mirror of blockcache_t and fd_txncache_private from fd_txncache.c.
   Needed to access the page index array and txnpages. */

struct fd_txncache_writer_blockcache {
  fd_txncache_blockcache_shmem_t * shmem;
  uint *           heads;
  ushort *         pages;
  descends_set_t * descends;
};

typedef struct fd_txncache_writer_blockcache fd_txncache_writer_blockcache_t;

struct fd_txncache_writer_tc {
  fd_txncache_shmem_t *                 shmem;
  fd_txncache_blockcache_shmem_t *      blockcache_shmem_pool;
  fd_txncache_writer_blockcache_t *     blockcache_pool;
  blockhash_map_t *                     blockhash_map;
  ushort *                              txnpages_free;
  fd_txncache_txnpage_t *               txnpages;
};

typedef struct fd_txncache_writer_tc fd_txncache_writer_tc_t;

FD_STATIC_ASSERT( FD_TXNCACHE_WRITER_MAX_ROOTS>=FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE, fd_txncache_writer_max_roots );

#define STATE_HEADER    1
#define STATE_EMPTY     2
#define STATE_SLOT      3
#define STATE_BLOCKHASH 4

/* Serialized sizes of each level of the Vec<SlotDelta> nesting. */

#define SZ_HEADER (8UL)       /* slot_deltas_len */
#define SZ_SLOT   (17UL)      /* slot, is_root, status_len */
#define SZ_GROUP  (48UL)      /* blockhash, txnhash_offset, entries_len */
#define SZ_ENTRY  (24UL)      /* txnhash[20], result */

static int
txncache_txn_on_snapshot_root( fd_txncache_writer_tc_t const *  tc,
                               ulong                            snapshot_root_idx,
                               fd_txncache_single_txn_t const * txn ) {
  if( FD_UNLIKELY( snapshot_root_idx>=tc->shmem->active_slots_max ) ) return 0;
  if( FD_UNLIKELY( txn->fork_id.val>=tc->shmem->active_slots_max ) ) return 0;

  fd_txncache_blockcache_shmem_t const * txn_fork = &tc->blockcache_shmem_pool[ txn->fork_id.val ];
  if( FD_UNLIKELY( txn_fork->frozen<0 || txn_fork->generation!=txn->generation ) ) return 0;

  return txn->fork_id.val==snapshot_root_idx ||
         descends_set_test( tc->blockcache_pool[ snapshot_root_idx ].descends, txn->fork_id.val );
}

/* txncache_root_pos returns the position of blockcache bc_idx in the
   rooted list, or ULONG_MAX if it is not rooted. */

FD_FN_PURE static ulong
txncache_root_pos( fd_txncache_writer_t const * writer,
                   ulong                        bc_idx ) {
  ulong lo = 0UL;
  ulong hi = writer->root_cnt;
  while( lo<hi ) {
    ulong mid = lo+(hi-lo)/2UL;
    ulong pos = writer->root_ord[ mid ];
    if(      writer->root_bc[ pos ]<bc_idx ) lo = mid+1UL;
    else if( writer->root_bc[ pos ]>bc_idx ) hi = mid;
    else                                     return pos;
  }
  return ULONG_MAX;
}

fd_txncache_writer_t *
fd_txncache_writer_init( fd_txncache_writer_t *         writer,
                         fd_txncache_t *                tc,
                         fd_slot_history_view_t const * slot_history ) {
  fd_txncache_writer_tc_t const * ltc = (fd_txncache_writer_tc_t const *)tc;

  writer->state             = STATE_HEADER;
  writer->tc                = tc;
  writer->empty_pos         = 0UL;
  writer->exec_pos          = 0UL;
  writer->hash_pos          = 0UL;
  writer->snapshot_root_idx = root_slist_is_empty( ltc->shmem->root_ll, ltc->blockcache_shmem_pool ) ?
                              ULONG_MAX :
                              root_slist_idx_peek_tail( ltc->shmem->root_ll, ltc->blockcache_shmem_pool );

  /* Collect the rooted blockcaches, oldest first.  fd_txncache_advance_root
     evicts the head once there are more than FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE
     of them, so this cannot overflow. */

  ulong root_cnt = 0UL;
  for( ulong it = root_slist_iter_init( ltc->shmem->root_ll, ltc->blockcache_shmem_pool );
       !root_slist_iter_done( it, ltc->shmem->root_ll, ltc->blockcache_shmem_pool );
       it = root_slist_iter_next( it, ltc->shmem->root_ll, ltc->blockcache_shmem_pool ) ) {
    FD_TEST( root_cnt<FD_TXNCACHE_WRITER_MAX_ROOTS );
    ulong bc_idx = root_slist_iter_idx( it, ltc->shmem->root_ll, ltc->blockcache_shmem_pool );
    writer->root_bc  [ root_cnt ] = (ushort)bc_idx;
    writer->root_slot[ root_cnt ] = ltc->blockcache_shmem_pool[ bc_idx ].slot;
    root_cnt++;
  }
  writer->root_cnt = root_cnt;

  /* A snapshot load can leave the older banks of the chain it rebuilds
     without a slot, because the status cache it loaded did not go back
     far enough.  Those banks hold no transactions of their own, so they
     are skipped as slot deltas, but they still appear as blockhash
     groups.  They age out of the cache within
     FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE roots of booting. */

  ulong oldest_slot = ULONG_MAX;
  writer->delta_cnt = 0UL;
  for( ulong i=0UL; i<root_cnt; i++ ) {
    if( FD_UNLIKELY( writer->root_slot[ i ]==ULONG_MAX ) ) continue;
    oldest_slot = fd_ulong_min( oldest_slot, writer->root_slot[ i ] );
    writer->delta_cnt++;
  }

  /* Order the positions by blockcache index so a transaction's fork can
     be mapped back to the slot delta it belongs in. */

  for( ulong i=0UL; i<root_cnt; i++ ) { /* insertion sort */
    ushort pos = (ushort)i;
    ulong  j   = i;
    for( ; j && writer->root_bc[ writer->root_ord[ j-1UL ] ]>writer->root_bc[ pos ]; j-- ) writer->root_ord[ j ] = writer->root_ord[ j-1UL ];
    writer->root_ord[ j ] = pos;
  }

  /* Pad back to FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS rooted slots with
     empty slot deltas, so that Agave accepts the snapshot.  Walk the
     slot history backwards from the oldest slot we still hold, skipping
     the slots that were never rooted. */

  writer->empty_cnt = 0UL;
  if( FD_LIKELY( slot_history && writer->delta_cnt && writer->delta_cnt<FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS ) ) {
    ulong want = FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS-writer->delta_cnt;
    /* next_slot is one past the newest slot in the history, so this
       never walks slots the history does not cover yet. */
    ulong oldest = fd_ulong_min( oldest_slot, slot_history->next_slot );
    for( ulong slot=oldest; slot && writer->empty_cnt<want; ) {
      slot--;
      int found = fd_sysvar_slot_history_find_slot( slot_history, slot );
      if( FD_UNLIKELY( found==FD_SLOT_HISTORY_SLOT_TOO_OLD ) ) break;
      if( FD_LIKELY( found!=FD_SLOT_HISTORY_SLOT_FOUND ) ) continue;
      writer->empty_slot[ writer->empty_cnt++ ] = slot;
    }
    /* Collected newest first, but slot deltas are written oldest first. */
    for( ulong i=0UL; i<writer->empty_cnt/2UL; i++ ) {
      ulong j = writer->empty_cnt-1UL-i;
      ulong t = writer->empty_slot[ i ];
      writer->empty_slot[ i ] = writer->empty_slot[ j ];
      writer->empty_slot[ j ] = t;
    }
  }

  /* Tally the entries of every (executed in, referenced) pair. */

  memset( writer->txn_cnt,   0, sizeof(writer->txn_cnt)   );
  memset( writer->group_cnt, 0, sizeof(writer->group_cnt) );

  ulong entry_cnt = 0UL;
  for( ulong hash_pos=0UL; hash_pos<root_cnt; hash_pos++ ) {
    ulong bc_idx = writer->root_bc[ hash_pos ];
    fd_txncache_blockcache_shmem_t const *  bc_shmem = &ltc->blockcache_shmem_pool[ bc_idx ];
    fd_txncache_writer_blockcache_t const * bc       = &ltc->blockcache_pool[ bc_idx ];

    for( ushort page=0; page<bc_shmem->pages_cnt; page++ ) {
      fd_txncache_txnpage_t const * txnpage = &ltc->txnpages[ bc->pages[ page ] ];
      ulong txns_in_page = FD_TXNCACHE_TXNS_PER_PAGE - (ulong)txnpage->free;
      for( ulong i=0UL; i<txns_in_page; i++ ) {
        fd_txncache_single_txn_t const * txn = txnpage->txns[ i ];
        if( FD_UNLIKELY( !txncache_txn_on_snapshot_root( ltc, writer->snapshot_root_idx, txn ) ) ) continue;

        ulong exec_pos = txncache_root_pos( writer, txn->fork_id.val );
        if( FD_UNLIKELY( exec_pos==ULONG_MAX ) ) continue;                      /* executed on an unrooted fork */
        if( FD_UNLIKELY( writer->root_slot[ exec_pos ]==ULONG_MAX ) ) continue; /* executed in an unknown slot */

        writer->group_cnt[ exec_pos ] += !writer->txn_cnt[ exec_pos ][ hash_pos ];
        writer->txn_cnt[ exec_pos ][ hash_pos ]++;
        entry_cnt++;
      }
    }
  }

  ulong group_cnt = 0UL;
  for( ulong i=0UL; i<root_cnt; i++ ) group_cnt += writer->group_cnt[ i ];
  writer->serialized_sz = SZ_HEADER + (writer->delta_cnt+writer->empty_cnt)*SZ_SLOT + group_cnt*SZ_GROUP + entry_cnt*SZ_ENTRY;

  return writer;
}

FD_FN_PURE ulong
fd_txncache_writer_serialized_sz( fd_txncache_writer_t const * writer ) {
  return writer->serialized_sz;
}

__attribute__((cold,noreturn)) static void
fail( fd_txncache_writer_t const * writer,
      ulong                        buf_sz ) {
  FD_LOG_ERR(( "buffer overflow (state=%u, buf_sz=%lu, exec_pos=%lu, hash_pos=%lu)",
               writer->state, buf_sz, writer->exec_pos, writer->hash_pos ));
}

#define PUSH_VAL( t, v ) do { FD_STORE( t, p, (v) ); p += sizeof(t); } while(0)

ulong
fd_txncache_writer_serialize( fd_txncache_writer_t * writer,
                              uchar                  out_buf[ FD_TXNCACHE_WRITER_BUF_MIN ],
                              ulong                  buf_sz ) {
  fd_txncache_writer_tc_t const * tc = (fd_txncache_writer_tc_t const *)writer->tc;
  FD_TEST( buf_sz>=FD_TXNCACHE_WRITER_BUF_MIN );

  uchar * p  = out_buf;
  uchar * p1 = out_buf+buf_sz;

  if( FD_UNLIKELY( writer->state==STATE_HEADER ) ) {
    PUSH_VAL( ulong, writer->delta_cnt+writer->empty_cnt );
    writer->state = STATE_EMPTY;
  }

  while( writer->empty_pos<writer->empty_cnt ) {
    if( FD_UNLIKELY( p+SZ_SLOT>p1 ) ) return (ulong)( p-out_buf );
    PUSH_VAL( ulong, writer->empty_slot[ writer->empty_pos++ ] );
    PUSH_VAL( uchar, 1   ); /* is_root */
    PUSH_VAL( ulong, 0UL ); /* status_len */
  }
  writer->state = fd_uint_if( writer->state==STATE_EMPTY, STATE_SLOT, writer->state );

  while( writer->exec_pos<writer->root_cnt ) {
    if( FD_UNLIKELY( writer->state==STATE_SLOT ) ) {
      if( FD_UNLIKELY( writer->root_slot[ writer->exec_pos ]==ULONG_MAX ) ) {
        writer->exec_pos++;
        continue;
      }
      if( FD_UNLIKELY( p+SZ_SLOT>p1 ) ) break;
      PUSH_VAL( ulong, writer->root_slot[ writer->exec_pos ] );
      PUSH_VAL( uchar, 1                                     ); /* is_root */
      PUSH_VAL( ulong, writer->group_cnt[ writer->exec_pos ] );
      writer->hash_pos = 0UL;
      writer->state    = STATE_BLOCKHASH;
    }

    for( ; writer->hash_pos<writer->root_cnt; writer->hash_pos++ ) {
      ulong entry_cnt = writer->txn_cnt[ writer->exec_pos ][ writer->hash_pos ];
      if( FD_LIKELY( !entry_cnt ) ) continue;

      /* A group is emitted whole, so the caller must always offer a
         buffer that can hold the largest one. */
      if( FD_UNLIKELY( p+SZ_GROUP+SZ_ENTRY*entry_cnt>p1 ) ) {
        if( FD_UNLIKELY( p==out_buf ) ) fail( writer, buf_sz );
        return (ulong)( p-out_buf );
      }

      ulong bc_idx = writer->root_bc[ writer->hash_pos ];
      fd_txncache_blockcache_shmem_t const *  bc_shmem = &tc->blockcache_shmem_pool[ bc_idx ];
      fd_txncache_writer_blockcache_t const * bc       = &tc->blockcache_pool[ bc_idx ];

      PUSH_VAL( fd_hash_t, bc_shmem->blockhash      );
      PUSH_VAL( ulong,     bc_shmem->txnhash_offset );
      PUSH_VAL( ulong,     entry_cnt                );

      ulong emitted = 0UL;
      for( ushort page=0; page<bc_shmem->pages_cnt; page++ ) {
        fd_txncache_txnpage_t const * txnpage = &tc->txnpages[ bc->pages[ page ] ];
        ulong txns_in_page = FD_TXNCACHE_TXNS_PER_PAGE - (ulong)txnpage->free;
        for( ulong i=0UL; i<txns_in_page; i++ ) {
          fd_txncache_single_txn_t const * txn = txnpage->txns[ i ];
          if( FD_UNLIKELY( !txncache_txn_on_snapshot_root( tc, writer->snapshot_root_idx, txn ) ) ) continue;
          if( FD_LIKELY( txncache_root_pos( writer, txn->fork_id.val )!=writer->exec_pos ) ) continue;

          fd_txnhash_20_t h;
          memcpy( h.b, txn->txnhash, 20UL );
          PUSH_VAL( fd_txnhash_20_t, h  );
          PUSH_VAL( uint,            0U ); /* result = Ok */
          emitted++;
        }
      }
      FD_TEST( emitted==entry_cnt ); /* txncache mutated during serialization? */
    }

    writer->exec_pos++;
    writer->state = STATE_SLOT;
  }

  return (ulong)( p-out_buf );
}

#undef PUSH_VAL

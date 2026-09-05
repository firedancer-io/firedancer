#include "fd_txncache_writer.h"
#include "../../flamenco/runtime/fd_txncache_private.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_slot_history.h"
#include "../../util/fd_util.h"

/* Mirror of blockcache_t and fd_txncache_private from fd_txncache.c.
   Needed to access the hash chain heads, the descends sets and the
   txnpages. */

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

#define STATE_HEADER      1
#define STATE_SLOT_DELTA  2
#define STATE_GROUP_HDR   3 /* placeholder */
#define STATE_GROUP_TXNS  4
#define STATE_GROUP_FIXUP 5 /* patch */
#define STATE_DONE        6
#define STATE_INIT STATE_HEADER

/* Wire sizes */

#define HEADER_SZ     (8UL)          /* slot_deltas_len */
#define SLOT_DELTA_SZ (8UL+1UL+8UL)  /* slot, is_root, status_len */
#define GROUP_HDR_SZ  (32UL+8UL+8UL) /* blockhash, txnhash_offset, txn_cnt */
#define TXN_SZ        (20UL+4UL)     /* txnhash, result */

/* Reads under the txncache read lock.  Everything below that touches
   the txncache assumes the caller holds it. */

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

/* txncache_chain_head loads the head of a bucket's chain.  Acquire
   pairs with the release of the publishing CAS in
   fd_txncache_insert_txn, which orders the transaction's fields and
   chain link before the head. */

static inline uint
txncache_chain_head( fd_txncache_writer_tc_t const * tc,
                     ulong                           bc_idx,
                     ulong                           bucket ) {
  return __atomic_load_n( &tc->blockcache_pool[ bc_idx ].heads[ bucket ], __ATOMIC_ACQUIRE );
}

static inline fd_txncache_single_txn_t const *
txncache_chain_txn( fd_txncache_writer_tc_t const * tc,
                    uint                            idx ) {
  return tc->txnpages[ idx/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ idx%FD_TXNCACHE_TXNS_PER_PAGE ];
}

/* txncache_group_check verifies that the txncache root list still looks
   like it did at init: the snapshot root is still the newest root and
   the group's blockcache is still the same rooted blockcache.  Replay
   guarantees this by not advancing the root during a snapshot. */

static void
txncache_group_check( fd_txncache_writer_t const *         writer,
                      fd_txncache_writer_tc_t const *      tc,
                      fd_txncache_writer_group_t const *   group ) {
  fd_txncache_blockcache_shmem_t const * root = &tc->blockcache_shmem_pool[ writer->snapshot_root_idx ];
  if( FD_UNLIKELY( root->frozen!=2 || root->generation!=writer->snapshot_root_generation ) ) {
    FD_LOG_ERR(( "txncache snapshot root %lu changed while snapshot of slot %lu was in progress (frozen=%d generation=%u expected=%u)",
                 writer->snapshot_root_idx, writer->slot, root->frozen, root->generation, writer->snapshot_root_generation ));
  }
  if( FD_UNLIKELY( root_slist_is_empty( tc->shmem->root_ll, tc->blockcache_shmem_pool ) ||
                   root_slist_idx_peek_tail( tc->shmem->root_ll, tc->blockcache_shmem_pool )!=writer->snapshot_root_idx ) ) {
    FD_LOG_ERR(( "txncache root advanced while snapshot of slot %lu was in progress", writer->slot ));
  }
  fd_txncache_blockcache_shmem_t const * bc = &tc->blockcache_shmem_pool[ group->bc_idx ];
  if( FD_UNLIKELY( bc->frozen!=2 || bc->generation!=group->generation ) ) {
    FD_LOG_ERR(( "txncache rooted blockcache %lu changed while snapshot of slot %lu was in progress (frozen=%d generation=%u expected=%u)",
                 group->bc_idx, writer->slot, bc->frozen, bc->generation, group->generation ));
  }
}

static void
writer_slots_init( fd_txncache_writer_t * writer,
                   uchar const *          slot_history,
                   ulong                  slot_history_sz ) {
  writer->slot_idx = 0UL;

  /* Agave's verify_slot_history rejects a snapshot whose SlotHistory is
     not exactly MAX_ENTRIES bits ending at the bank's slot. */

  fd_slot_history_view_t view[1];
  if( FD_UNLIKELY( !fd_sysvar_slot_history_view( view, slot_history, slot_history_sz ) ) ) {
    FD_LOG_CRIT(( "malformed SlotHistory sysvar at slot %lu", writer->slot ));
  }
  if( FD_UNLIKELY( view->bits_len!=FD_SLOT_HISTORY_MAX_ENTRIES            ||
                   view->blocks_len*64UL!=FD_SLOT_HISTORY_MAX_ENTRIES     ||
                   view->next_slot>writer->slot+1UL ) ) {
    FD_LOG_CRIT(( "malformed SlotHistory sysvar at slot %lu (bits_len %lu blocks_len %lu next_slot %lu)",
                  writer->slot, view->bits_len, view->blocks_len, view->next_slot ));
  }

  /* SlotHistory from sysvar cache it is missing the bit for the
     snapshot slot itself, which this function works around. */

  ulong scan_cnt = fd_ulong_min( writer->slot+1UL, FD_SLOT_HISTORY_MAX_ENTRIES );
  ulong cnt      = 0UL;
  for( ulong i=0UL; i<scan_cnt && cnt<FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS; i++ ) {
    ulong slot = writer->slot-i;
    if( slot!=writer->slot &&
        fd_sysvar_slot_history_find_slot( view, slot )!=FD_SLOT_HISTORY_SLOT_FOUND ) continue;
    writer->slots[ FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS-1UL-cnt ] = slot; /* fill from the back to get ascending order */
    cnt++;
  }
  FD_TEST( cnt ); /* i==0 always counts */

  memmove( writer->slots, writer->slots+FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS-cnt, cnt*sizeof(ulong) );
  writer->slot_cnt = cnt;
}

fd_txncache_writer_t *
fd_txncache_writer_init( fd_txncache_writer_t * writer,
                         fd_txncache_t *        tc,
                         fd_txncache_fork_id_t  fork_id,
                         ulong                  slot,
                         uchar const *          slot_history,
                         ulong                  slot_history_sz ) {
  fd_txncache_writer_tc_t const * ltc = (fd_txncache_writer_tc_t const *)tc;
  fd_rwlock_t * lock = ltc->shmem->lock;

  writer->state         = STATE_INIT;
  writer->tc            = tc;
  writer->slot          = slot;
  writer->group_cnt     = 0UL;
  writer->group_idx     = 0UL;
  writer->bucket_idx    = 0UL;
  writer->group_emitted = 0UL;

  writer_slots_init( writer, slot_history, slot_history_sz );

  /* Snapshot the root list.  The snapshot root must be the newest root. */

  fd_rwlock_read( lock );
  if( FD_UNLIKELY( fork_id.val>=ltc->shmem->active_slots_max                                           ||
                   root_slist_is_empty( ltc->shmem->root_ll, ltc->blockcache_shmem_pool )              ||
                   root_slist_idx_peek_tail( ltc->shmem->root_ll, ltc->blockcache_shmem_pool )!=fork_id.val ||
                   ltc->blockcache_shmem_pool[ fork_id.val ].frozen!=2 ) ) {
    fd_rwlock_unread( lock );
    return NULL;
  }
  writer->snapshot_root_idx        = fork_id.val;
  writer->snapshot_root_generation = ltc->blockcache_shmem_pool[ fork_id.val ].generation;

  ulong group_cnt = 0UL;
  for( ulong it = root_slist_iter_init( ltc->shmem->root_ll, ltc->blockcache_shmem_pool );
       !root_slist_iter_done( it, ltc->shmem->root_ll, ltc->blockcache_shmem_pool );
       it = root_slist_iter_next( it, ltc->shmem->root_ll, ltc->blockcache_shmem_pool ) ) {
    ulong bc_idx = root_slist_iter_idx( it, ltc->shmem->root_ll, ltc->blockcache_shmem_pool );
    if( FD_UNLIKELY( group_cnt>=FD_TXNCACHE_WRITER_MAX_GROUPS ) ) {
      FD_LOG_CRIT(( "txncache has more than %lu roots", FD_TXNCACHE_WRITER_MAX_GROUPS ));
    }
    writer->groups[ group_cnt ].bc_idx     = bc_idx;
    writer->groups[ group_cnt ].generation = ltc->blockcache_shmem_pool[ bc_idx ].generation;
    group_cnt++;
  }
  fd_rwlock_unread( lock );
  writer->group_cnt = group_cnt;

  return writer;
}

/* Serialization */

/* serialize_group_hdr writes the header of group to p, which has room
   for GROUP_HDR_SZ bytes, with transaction count txn_cnt. */

static void
serialize_group_hdr( fd_txncache_writer_t *             writer,
                     fd_txncache_writer_group_t const * group,
                     ulong                              txn_cnt,
                     uchar *                            p ) {
  fd_txncache_writer_tc_t const * tc = (fd_txncache_writer_tc_t const *)writer->tc;
  fd_rwlock_read( tc->shmem->lock );
  txncache_group_check( writer, tc, group );
  fd_txncache_blockcache_shmem_t const * bc_shmem = &tc->blockcache_shmem_pool[ group->bc_idx ];
  memcpy( p, bc_shmem->blockhash.uc, 32UL );  p += 32UL;
  FD_STORE( ulong, p, bc_shmem->txnhash_offset ); p +=  8UL;
  FD_STORE( ulong, p, txn_cnt                  ); p +=  8UL;
  fd_rwlock_unread( tc->shmem->lock );
}

/* serialize_group_txns emits the transactions of group into [p,p1),
   whole buckets at a time, resuming at writer->bucket_idx.  Returns the
   new p.  Sets *done to 1 if the group is complete, 0 if the next
   bucket did not fit and the caller should come back with more room. */

static uchar *
serialize_group_txns( fd_txncache_writer_t *             writer,
                      fd_txncache_writer_group_t const * group,
                      uchar *                            out_buf,
                      uchar *                            p,
                      uchar *                            p1,
                      int *                              done ) {
  fd_txncache_writer_tc_t const * tc = (fd_txncache_writer_tc_t const *)writer->tc;
  ulong bucket_cnt = tc->shmem->bucket_cnt;

  fd_rwlock_read( tc->shmem->lock );
  txncache_group_check( writer, tc, group );
  uchar * hold_start = p;

  while( writer->bucket_idx<bucket_cnt ) {
    uchar * bucket_start = p;
    ulong   bucket_cnt_  = 0UL;
    for( uint head=txncache_chain_head( tc, group->bc_idx, writer->bucket_idx ); head!=UINT_MAX; ) {
      fd_txncache_single_txn_t const * txn = txncache_chain_txn( tc, head );
      if( FD_LIKELY( txncache_txn_on_snapshot_root( tc, writer->snapshot_root_idx, txn ) ) ) {
        if( FD_UNLIKELY( p+TXN_SZ>p1 ) ) {
          /* Bucket does not fit.  Roll it back and retry it next call
             with more room; whole buckets only, since a position inside
             a chain would not survive compaction between calls. */
          fd_rwlock_unread( tc->shmem->lock );
          if( FD_UNLIKELY( bucket_start==out_buf ) ) {
            FD_LOG_ERR(( "status cache bucket %lu of blockcache %lu holds more than %lu transactions, exceeding the %lu byte output buffer",
                         writer->bucket_idx, group->bc_idx, (ulong)(p1-out_buf)/TXN_SZ, (ulong)(p1-out_buf) ));
          }
          *done = 0;
          return bucket_start;
        }
        memcpy( p, txn->txnhash, 20UL ); p += 20UL;
        FD_STORE( uint, p, 0U );         p +=  4UL; /* result = Ok */
        bucket_cnt_++;
      }
      head = txn->blockcache_next;
    }
    writer->group_emitted += bucket_cnt_;
    writer->bucket_idx++;

    if( FD_UNLIKELY( (ulong)(p-hold_start)>=FD_TXNCACHE_WRITER_HOLD_MAX ) ) {
      fd_rwlock_unread( tc->shmem->lock );
      fd_rwlock_read( tc->shmem->lock );
      txncache_group_check( writer, tc, group );
      hold_start = p;
    }
  }
  fd_rwlock_unread( tc->shmem->lock );

  *done = 1;
  return p;
}

ulong
fd_txncache_writer_serialize( fd_txncache_writer_t * writer,
                              uchar *                out_buf,
                              ulong                  buf_sz,
                              int *                  out_kind ) {
  if( FD_UNLIKELY( buf_sz<FD_TXNCACHE_WRITER_BUF_MIN ) ) {
    FD_LOG_CRIT(( "buffer too small (%lu bytes, need at least %lu)", buf_sz, FD_TXNCACHE_WRITER_BUF_MIN ));
  }
  uchar * p  = out_buf;
  uchar * p1 = out_buf+buf_sz;
  *out_kind  = FD_TXNCACHE_WRITER_CHUNK_DATA;

  for(;;) {
    switch( writer->state ) {

    case STATE_HEADER: {
      if( FD_UNLIKELY( p+HEADER_SZ>p1 ) ) goto done;
      FD_STORE( ulong, p, writer->slot_cnt ); p += 8UL; /* slot_deltas_len */
      writer->slot_idx = 0UL;
      writer->state    = writer->slot_cnt ? STATE_SLOT_DELTA : STATE_DONE;
      break;
    }

    case STATE_SLOT_DELTA: {
      if( FD_UNLIKELY( p+SLOT_DELTA_SZ>p1 ) ) goto done;
      ulong slot       = writer->slots[ writer->slot_idx++ ];
      int   is_snap    = slot==writer->slot;
      ulong status_len = is_snap ? writer->group_cnt : 0UL;

      FD_STORE( ulong, p, slot       ); p += 8UL; /* slot       */
      FD_STORE( uchar, p, 1          ); p += 1UL; /* is_root    */
      FD_STORE( ulong, p, status_len ); p += 8UL; /* status_len */

      if( status_len ) {
        writer->group_idx = 0UL;
        writer->state     = STATE_GROUP_HDR;
      } else if( writer->slot_idx>=writer->slot_cnt ) {
        writer->state = STATE_DONE;
      }
      break;
    }

    case STATE_GROUP_HDR: {
      /* The group's transaction count is not known until its buckets
         were walked, so the header goes out as a placeholder, alone in
         its chunk, and is patched in STATE_GROUP_FIXUP. */
      if( FD_UNLIKELY( p!=out_buf ) ) goto done;
      serialize_group_hdr( writer, &writer->groups[ writer->group_idx ], 0UL, p );
      p += GROUP_HDR_SZ;
      writer->bucket_idx    = 0UL;
      writer->group_emitted = 0UL;
      writer->state         = STATE_GROUP_TXNS;
      *out_kind = FD_TXNCACHE_WRITER_CHUNK_PLACEHOLDER;
      goto done;
    }

    case STATE_GROUP_TXNS: {
      int group_done;
      p = serialize_group_txns( writer, &writer->groups[ writer->group_idx ], out_buf, p, p1, &group_done );
      if( !group_done ) goto done;
      writer->state = STATE_GROUP_FIXUP;
      break;
    }

    case STATE_GROUP_FIXUP: {
      if( FD_UNLIKELY( p!=out_buf ) ) goto done;
      serialize_group_hdr( writer, &writer->groups[ writer->group_idx ], writer->group_emitted, p );
      p += GROUP_HDR_SZ;
      writer->group_idx++;
      if( writer->group_idx<writer->group_cnt ) {
        writer->state = STATE_GROUP_HDR;
      } else {
        writer->state = writer->slot_idx<writer->slot_cnt ? STATE_SLOT_DELTA : STATE_DONE;
      }
      *out_kind = FD_TXNCACHE_WRITER_CHUNK_PATCH;
      goto done;
    }

    case STATE_DONE:
      goto done;

    default:
      FD_LOG_CRIT(( "invalid state reached (%u)", writer->state ));
    }
  }

done:
  return (ulong)( p-out_buf );
}

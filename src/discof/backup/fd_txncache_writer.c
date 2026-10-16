#include "fd_txncache_writer.h"
#include "../../flamenco/runtime/fd_txncache_private.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_slot_history.h"
#include "../../util/fd_util.h"

#define STATE_HEADER  1
#define STATE_SLOT    2
#define STATE_GROUP   3
#define STATE_ENTRIES 4
#define STATE_DONE    5

/* Wire sizes */

#define HEADER_SZ     (8UL)                      /* slot_deltas_len */
#define SLOT_DELTA_SZ (8UL+1UL+8UL)              /* slot, is_root, status_len */
#define GROUP_HDR_SZ  (32UL+8UL+8UL)             /* blockhash, txnhash_offset, txn_cnt */
#define TXN_SZ        (sizeof(fd_txnhash_t)+4UL) /* txnhash, result */

#define FD_TXNCACHE_WRITER_ARENA_MIN (64UL<<20)

#define WALK_COUNT 0
#define WALK_FILL  1

FD_STATIC_ASSERT( FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS<=USHORT_MAX, group_slot_i      );
FD_STATIC_ASSERT( FD_TXNCACHE_WRITER_MAX_BLOCKHASHES<=USHORT_MAX, group_blockhash_i );
FD_STATIC_ASSERT( FD_TXNCACHE_MAX_ROOTS<=FD_TXNCACHE_WRITER_MAX_BLOCKHASHES, roots );

static inline ulong
group_key( ulong slot_i, ulong blockhash_i ) {
  return slot_i*FD_TXNCACHE_WRITER_MAX_BLOCKHASHES+blockhash_i;
}

FD_FN_CONST ulong
fd_txncache_writer_arena_align( void ) {
  return 64UL;
}

FD_FN_CONST ulong
fd_txncache_writer_arena_sz( ulong max_txn_per_slot ) {
  /* Write at least 2 slots at once, and have at least 64 MiB. */
  return fd_ulong_max( FD_TXNCACHE_WRITER_ARENA_MIN, 2UL*2UL*max_txn_per_slot*sizeof(fd_txnhash_t) );
}

/* Returns the captured rooted descriptor of the fork the txn executed
   on, or NULL if that fork is not in the captured rooted set, either
   because it is unrooted or because it is a cancelled fork whose pool
   slot has since been reused. */

static inline fd_txncache_writer_blockhash_desc_t const *
writer_exec_desc( fd_txncache_writer_t const *     writer,
                  fd_txncache_single_txn_t const * txn ) {
  ulong desc_i = writer->fork_id_to_blockhash_i[ txn->fork_id.val ];
  if( FD_UNLIKELY( desc_i==USHORT_MAX ) ) return NULL;
  fd_txncache_writer_blockhash_desc_t const * desc = &writer->blockhash_descs[ desc_i ];
  return txn->generation==desc->generation ? desc : NULL;
}

static void
writer_slots_init( fd_txncache_writer_t * writer,
                   uchar const *          slot_history,
                   ulong                  slot_history_sz ) {
  /* Agave's verify_slot_history rejects a snapshot whose SlotHistory is
     not exactly MAX_ENTRIES bits ending at the bank's slot. */

  fd_slot_history_view_t view[1];
  if( FD_UNLIKELY( !fd_sysvar_slot_history_view( view, slot_history, slot_history_sz ) ) ) {
    FD_LOG_CRIT(( "malformed SlotHistory sysvar at slot %lu", writer->snapshot_slot ));
  }
  if( FD_UNLIKELY( view->bits_len!=FD_SLOT_HISTORY_MAX_ENTRIES            ||
                   view->blocks_len*64UL!=FD_SLOT_HISTORY_MAX_ENTRIES     ||
                   view->next_slot>writer->snapshot_slot+1UL ) ) {
    FD_LOG_CRIT(( "malformed SlotHistory sysvar at slot %lu (bits_len %lu blocks_len %lu next_slot %lu)",
                  writer->snapshot_slot, view->bits_len, view->blocks_len, view->next_slot ));
  }

  /* The SlotHistory in the bank's sysvar cache is one slot stale: it
     is missing the bit for the snapshot slot itself, so the loop below
     forces that slot in. */

  ulong scan_cnt = fd_ulong_min( writer->snapshot_slot+1UL, FD_SLOT_HISTORY_MAX_ENTRIES );
  ulong cnt      = 0UL;
  for( ulong i=0UL; i<scan_cnt && cnt<FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS; i++ ) {
    ulong slot = writer->snapshot_slot-i;
    if( slot!=writer->snapshot_slot && fd_sysvar_slot_history_find_slot( view, slot )!=FD_SLOT_HISTORY_SLOT_FOUND ) continue;
    writer->slots[ FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS-1UL-cnt ] = slot; /* fill from the back to get ascending order */
    cnt++;
  }
  FD_TEST( cnt ); /* i==0 always counts */

  memmove( writer->slots, writer->slots+FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS-cnt, cnt*sizeof(ulong) );
  writer->slot_cnt = cnt;
}

/* Pairs rooted blockcache descriptors with execution slots by rank from
   the newest end.  Every rooted block registered exactly one blockhash
   and set exactly one SlotHistory bit, and both sequences end at the
   snapshot slot.  The initial genesis descriptor may precede the named
   execution slots; it remains usable as a referenced blockhash but has
   no execution slot mapping. */
static void
writer_map_execution_slots( fd_txncache_writer_t * writer ) {
  ulong blockhash_cnt = writer->blockhash_cnt;
  ulong slot_cnt      = writer->slot_cnt;
  if( FD_UNLIKELY( blockhash_cnt>slot_cnt+1UL ) ) {
    FD_LOG_CRIT(( "txncache has %lu rooted blockhash descriptors but SlotHistory names only %lu execution slots", blockhash_cnt, slot_cnt ));
  }

  memset( writer->fork_id_to_blockhash_i, 0xFF, sizeof(writer->fork_id_to_blockhash_i) );
  for( ulong blockhash_i=0UL; blockhash_i<blockhash_cnt; blockhash_i++ ) {
    fd_txncache_writer_blockhash_desc_t * desc = &writer->blockhash_descs[ blockhash_i ];
    desc->slot_i = USHORT_MAX;
    writer->fork_id_to_blockhash_i[ desc->blockcache_idx ] = (ushort)blockhash_i;
  }

  ulong mapped_cnt   = fd_ulong_min( blockhash_cnt, slot_cnt );
  ulong blockhash_i0 = blockhash_cnt-mapped_cnt;
  ulong slot_i0      = slot_cnt     -mapped_cnt;
  for( ulong pair_i=0UL; pair_i<mapped_cnt; pair_i++ ) {
    ulong blockhash_i = blockhash_i0+pair_i;
    ulong slot_i      = slot_i0     +pair_i;
    writer->blockhash_descs[ blockhash_i ].slot_i = (ushort)slot_i;
  }
}

static void
writer_walk_blockhash( fd_txncache_writer_t * writer,
                       ulong                  blockhash_idx,
                       int                    mode ) {

  fd_txncache_blockcache_iter_t iter[1];
  for( fd_txncache_blockcache_iter_init( iter, writer->tc, writer->blockhash_descs[ blockhash_idx ].blockcache_idx );
       !fd_txncache_blockcache_iter_done( iter );
       fd_txncache_blockcache_iter_next( iter ) ) {
    fd_txncache_single_txn_t const * txn = fd_txncache_blockcache_iter_ele( iter );

    fd_txncache_writer_blockhash_desc_t const * exec_desc = writer_exec_desc( writer, txn );
    if( FD_UNLIKELY( !exec_desc ) ) continue;

    ushort slot_i = exec_desc->slot_i;
    if( FD_UNLIKELY( slot_i==USHORT_MAX ) ) {
      FD_LOG_CRIT(( "txncache transaction on captured fork %lu (descriptor %ld) has no execution slot", exec_desc->blockcache_idx, (long)(exec_desc-writer->blockhash_descs) ));
    }
    ulong key = group_key( slot_i, blockhash_idx );
    if( mode==WALK_COUNT ) {
      writer->entry_cnt_by_key[ key ]++;
      continue;
    }

    ulong group_i = writer->group_i_by_key[ key ];
    if( group_i<writer->group_i || group_i>=writer->batch_hi ) continue;
    fd_txncache_writer_group_t * group = &writer->groups[ group_i ];
    if( FD_UNLIKELY( group->filled_entry_cnt>=group->entry_cnt ) ) {
      FD_LOG_CRIT(( "txncache group in blockcache %lu exceeds its counted transaction count while snapshot of slot %lu is in progress", writer->blockhash_descs[ blockhash_idx ].blockcache_idx, writer->snapshot_slot ));
    }
    memcpy( writer->arena[ group->arena_entry_off+group->filled_entry_cnt ], txn->txnhash, sizeof(writer->arena[0]) );
    group->filled_entry_cnt++;
  }
  fd_txncache_blockcache_iter_fini( iter );
}

/* Walks every rooted blockcache once to count the transactions of each
   group, then lays the non-empty groups out in wire order: slot delta
   ascending, then wire group in blockhash descriptor order (oldest
   rooted blockcache first). */

static void
writer_groups_init( fd_txncache_writer_t * writer ) {
  memset( writer->entry_cnt_by_key, 0, sizeof(writer->entry_cnt_by_key) );
  for( ulong blockhash_i=0UL; blockhash_i<writer->blockhash_cnt; blockhash_i++ ) {
    writer_walk_blockhash( writer, blockhash_i, WALK_COUNT );
  }

  ulong group_cnt = 0UL;
  ulong entry_cnt = 0UL;
  for( ulong slot_i=0UL; slot_i<writer->slot_cnt; slot_i++ ) {
    writer->group_cnt_by_slot_i[ slot_i ] = 0UL;
    for( ulong blockhash_i=0UL; blockhash_i<writer->blockhash_cnt; blockhash_i++ ) {
      ulong key             = group_key( slot_i, blockhash_i );
      uint  group_entry_cnt = writer->entry_cnt_by_key[ key ];
      if( !group_entry_cnt ) continue;
      fd_txncache_writer_group_t * group = &writer->groups[ group_cnt ];
      group->slot_i           = (ushort)slot_i;
      group->blockhash_i      = (ushort)blockhash_i;
      group->entry_cnt        = group_entry_cnt;
      group->arena_entry_off  = 0U;
      group->filled_entry_cnt = 0U;
      writer->group_i_by_key[ key ] = (uint)group_cnt;
      writer->group_cnt_by_slot_i[ slot_i ]++;
      group_cnt++;
      entry_cnt += group_entry_cnt;
    }
  }
  writer->group_cnt = group_cnt;
  writer->entry_cnt = entry_cnt;
}

/* Writes groups [group_i,batch_hi) into the arena, with batch_hi as far
   as the arena reaches.  Walks each rooted blockcache that has a group
   in the batch once. */
static void
writer_fill_batch( fd_txncache_writer_t * writer ) {
  ulong group_i0 = writer->group_i;
  fd_txncache_writer_group_t * first = &writer->groups[ group_i0 ];
  if( FD_UNLIKELY( (ulong)first->entry_cnt>writer->arena_entry_cnt_max ) ) {
    FD_BASE58_ENCODE_32_BYTES( writer->blockhash_descs[ first->blockhash_i ].blockhash, blockhash_b58 );
    FD_LOG_CRIT(( "status cache group of slot %lu under blockhash %s holds %u transactions, exceeding the %lu entry arena", writer->slots[ first->slot_i ], blockhash_b58, first->entry_cnt, writer->arena_entry_cnt_max ));
  }

  uchar blockhash_in_batch[ FD_TXNCACHE_WRITER_MAX_BLOCKHASHES ] = {0};
  ulong arena_entry_off = 0UL;
  ulong batch_hi        = group_i0;
  while( batch_hi<writer->group_cnt && arena_entry_off+(ulong)writer->groups[ batch_hi ].entry_cnt<=writer->arena_entry_cnt_max ) {
    fd_txncache_writer_group_t * group = &writer->groups[ batch_hi ];
    group->arena_entry_off  = (uint)arena_entry_off;
    group->filled_entry_cnt = 0U;
    blockhash_in_batch[ group->blockhash_i ] = 1;
    arena_entry_off += group->entry_cnt;
    batch_hi++;
  }
  writer->batch_hi = batch_hi;

  for( ulong blockhash_i=0UL; blockhash_i<writer->blockhash_cnt; blockhash_i++ ) {
    if( blockhash_in_batch[ blockhash_i ] ) writer_walk_blockhash( writer, blockhash_i, WALK_FILL );
  }

  for( ulong group_i=group_i0; group_i<batch_hi; group_i++ ) {
    fd_txncache_writer_group_t const * group = &writer->groups[ group_i ];
    if( FD_UNLIKELY( group->filled_entry_cnt!=group->entry_cnt ) ) {
      FD_LOG_CRIT(( "txncache group %u of slot %lu has %u transactions, expected %u while snapshot of slot %lu is in progress", group->blockhash_i, writer->slots[ group->slot_i ], group->filled_entry_cnt, group->entry_cnt, writer->snapshot_slot ));
    }
  }
}

fd_txncache_writer_t *
fd_txncache_writer_init( fd_txncache_writer_t * writer,
                         fd_txncache_t *        tc,
                         ulong                  snapshot_slot,
                         uchar const *          slot_history,
                         ulong                  slot_history_sz,
                         void *                 arena,
                         ulong                  arena_sz ) {
  if( FD_UNLIKELY( !arena || !fd_ulong_is_aligned( (ulong)arena, fd_txncache_writer_arena_align() ) || arena_sz<2UL*2UL*sizeof(fd_txnhash_t) ) ) {
    FD_LOG_CRIT(( "invalid txncache writer arena (%p, %lu bytes)", arena, arena_sz ));
  }

  ulong arena_entry_cnt_max = arena_sz/sizeof(fd_txnhash_t);
  FD_CHECK_CRIT( arena_entry_cnt_max<=UINT_MAX, "txncache writer arena has too many entries" ); /* arena_entry_off is uint */

  writer->state               = STATE_HEADER;
  writer->tc                  = tc;
  writer->snapshot_slot       = snapshot_slot;
  writer->arena               = arena;
  writer->arena_entry_cnt_max = arena_entry_cnt_max;
  writer->batch_hi            = 0UL;
  writer->slot_i              = 0UL;
  writer->group_i             = 0UL;
  writer->entry_i             = 0UL;

  writer_slots_init( writer, slot_history, slot_history_sz );

  /* Snapshot the root list.  The snapshot root is the newest root. */

  fd_txncache_root_t roots[ FD_TXNCACHE_MAX_ROOTS ];
  ulong root_cnt = fd_txncache_snapshot_roots( tc, roots );
  for( ulong i=0UL; i<root_cnt; i++ ) {
    fd_txncache_writer_blockhash_desc_t * blockhash_desc = &writer->blockhash_descs[ i ];
    blockhash_desc->blockcache_idx = roots[ i ].blockcache_idx;
    blockhash_desc->generation     = roots[ i ].generation;
    blockhash_desc->txnhash_offset = roots[ i ].txnhash_offset;
    memcpy( blockhash_desc->blockhash, roots[ i ].blockhash, 32UL );
  }
  writer->blockhash_cnt = root_cnt;

  writer_map_execution_slots( writer );
  writer_groups_init( writer );

  return writer;
}

FD_FN_PURE ulong
fd_txncache_writer_serialized_sz( fd_txncache_writer_t const * writer ) {
  return HEADER_SZ+writer->slot_cnt*SLOT_DELTA_SZ+writer->group_cnt*GROUP_HDR_SZ+writer->entry_cnt*TXN_SZ;
}

ulong
fd_txncache_writer_serialize( fd_txncache_writer_t * writer,
                              uchar *                out_buf,
                              ulong                  buf_sz ) {
  if( FD_UNLIKELY( buf_sz<FD_TXNCACHE_WRITER_BUF_MIN ) ) {
    FD_LOG_CRIT(( "buffer too small (%lu bytes, need at least %lu)", buf_sz, FD_TXNCACHE_WRITER_BUF_MIN ));
  }
  uchar * p  = out_buf;
  uchar * p1 = out_buf+buf_sz;

  for(;;) {
    switch( writer->state ) {

    case STATE_HEADER: {
      if( FD_UNLIKELY( p+HEADER_SZ>p1 ) ) goto done;
      FD_STORE( ulong, p, writer->slot_cnt ); p += 8UL; /* slot_deltas_len */
      writer->slot_i  = 0UL;
      writer->group_i = 0UL;
      writer->state   = writer->slot_cnt ? STATE_SLOT : STATE_DONE;
      break;
    }

    case STATE_SLOT: {
      if( FD_UNLIKELY( p+SLOT_DELTA_SZ>p1 ) ) goto done;
      ulong slot_i = writer->slot_i;
      FD_STORE( ulong, p, writer->slots[ slot_i ]               ); p += 8UL; /* slot       */
      FD_STORE( uchar, p, 1                                     ); p += 1UL; /* is_root    */
      FD_STORE( ulong, p, writer->group_cnt_by_slot_i[ slot_i ] ); p += 8UL; /* status_len */
      if( writer->group_cnt_by_slot_i[ slot_i ] ) {
        writer->state = STATE_GROUP;
      } else {
        writer->slot_i++;
        if( writer->slot_i>=writer->slot_cnt ) writer->state = STATE_DONE;
      }
      break;
    }

    case STATE_GROUP: {
      fd_txncache_writer_group_t const * group = &writer->groups[ writer->group_i ];
      FD_TEST( group->slot_i==writer->slot_i );
      if( FD_UNLIKELY( writer->group_i>=writer->batch_hi ) ) writer_fill_batch( writer );
      if( FD_UNLIKELY( p+GROUP_HDR_SZ>p1 ) ) goto done;
      fd_txncache_writer_blockhash_desc_t const * blockhash_desc = &writer->blockhash_descs[ group->blockhash_i ];
      memcpy( p, blockhash_desc->blockhash, 32UL );          p += 32UL;
      FD_STORE( ulong, p, blockhash_desc->txnhash_offset );  p +=  8UL;
      FD_STORE( ulong, p, (ulong)group->entry_cnt         ); p +=  8UL;
      writer->entry_i = 0UL;
      writer->state   = STATE_ENTRIES;
      break;
    }

    case STATE_ENTRIES: {
      fd_txncache_writer_group_t const * group = &writer->groups[ writer->group_i ];
      while( writer->entry_i<group->entry_cnt ) {
        if( FD_UNLIKELY( p+TXN_SZ>p1 ) ) goto done;
        memcpy( p, writer->arena[ group->arena_entry_off+writer->entry_i ], sizeof(writer->arena[0]) ); p += sizeof(writer->arena[0]);
        FD_STORE( uint, p, 0U );                                                                        p +=  4UL; /* result = Ok */
        writer->entry_i++;
      }
      writer->group_i++;
      if( writer->group_i<writer->group_cnt && writer->groups[ writer->group_i ].slot_i==writer->slot_i ) {
        writer->state = STATE_GROUP;
      } else {
        writer->slot_i++;
        writer->state = writer->slot_i<writer->slot_cnt ? STATE_SLOT : STATE_DONE;
      }
      break;
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

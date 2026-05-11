#include "fd_txncache_writer.h"
#include "../../util/fd_util.h"

#define STATE_HEADER    1
#define STATE_SLOT      2
#define STATE_BLOCKHASH 3
#define STATE_TXNS      4
#define STATE_DONE      5
#define STATE_INIT STATE_HEADER

fd_txncache_writer_t *
fd_txncache_writer_init( fd_txncache_writer_t *         writer,
                         fd_txncache_t *                tc,
                         ulong                          slot,
                         fd_slot_history_view_t const * slot_history ) {
  writer->state     = STATE_INIT;
  writer->tc        = tc;
  writer->slot      = slot;
  writer->slot_cnt  = 0UL;
  writer->slot_idx  = 0UL;
  writer->group_cnt = 0UL;
  writer->group_idx = 0UL;
  writer->txn_idx   = 0UL;
  writer->txn_iter_active = 0;

  if( FD_LIKELY( slot_history && slot_history->next_slot && slot_history->next_slot-1UL==slot ) ) {
    ulong oldest_slot = fd_ulong_sat_sub( slot_history->next_slot, FD_SLOT_HISTORY_MAX_ENTRIES );
    for( ulong curr=slot; writer->slot_cnt<FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS && curr>=oldest_slot; curr-- ) {
      if( FD_LIKELY( fd_sysvar_slot_history_find_slot( slot_history, curr )==FD_SLOT_HISTORY_SLOT_FOUND ) ) {
        writer->slot_delta[ writer->slot_cnt++ ] = curr;
      }
      if( FD_UNLIKELY( !curr || curr==oldest_slot ) ) break;
    }
  }
  if( FD_UNLIKELY( !writer->slot_cnt ) ) writer->slot_delta[ writer->slot_cnt++ ] = slot;

  fd_txncache_root_iter_t root_iter[ 1 ];
  for( fd_txncache_root_iter_init( tc, root_iter );
       !fd_txncache_root_iter_done( root_iter );
       fd_txncache_root_iter_next( root_iter ) ) {
    fd_txncache_root_iter_ele_t const * ele = fd_txncache_root_iter_ele( root_iter );

    if( FD_UNLIKELY( writer->group_cnt>=FD_TXNCACHE_WRITER_MAX_GROUPS ) ) {
      FD_LOG_ERR(( "too many txncache blockhash groups to serialize" ));
    }

    fd_txncache_writer_group_t * group = &writer->group[ writer->group_cnt++ ];
    group->blockhash_fork_id = ele->fork_id;
    memcpy( group->blockhash, ele->blockhash, 32UL );
    group->txnhash_offset = ele->txnhash_offset;
    group->txn_cnt = 0UL;
  }
  fd_txncache_root_iter_fini( root_iter );

  for( ulong group_idx=0UL; group_idx<writer->group_cnt; group_idx++ ) {
    fd_txncache_iter_t iter[ 1 ];
    for( fd_txncache_iter_init( tc, iter, writer->group[ group_idx ].blockhash_fork_id );
         !fd_txncache_iter_done( iter );
         fd_txncache_iter_next( iter ) ) {
      writer->group[ group_idx ].txn_cnt++;
    }
    fd_txncache_iter_fini( iter );
  }

  return writer;
}

/* Helper for serialize macros */
struct fd_txnhash_20 { uchar b[ 20UL ]; };
typedef struct fd_txnhash_20 fd_txnhash_20_t;

/* Size estimate */

#define ENCODE_FN     static ulong txncache_estimate( fd_txncache_writer_t * enc )
#define PREP          ulong sz = 0UL;
#define PUSH_VAL(t,n) do { sz += sizeof(t); (void)(n); } while(0)
#define CAN_PUSH(sz)  (1)
#define RET_EXPR      sz
#include "fd_txncache_encoder.c"

ulong
fd_txncache_writer_serialized_sz( fd_txncache_writer_t const * writer ) {
  fd_txncache_writer_t estimate[1];
  memcpy( estimate, writer, sizeof(fd_txncache_writer_t) );

  ulong sz = 0UL;
  for(;;) {
    ulong chunk = txncache_estimate( estimate );
    if( FD_UNLIKELY( !chunk ) ) break;
    sz += chunk;
  }
  return sz;
}

__attribute__((cold,noreturn,unused))
static void fail( fd_txncache_writer_t const * enc,
                  ulong buf_sz,
                  ulong line_nr ) {
  FD_LOG_ERR(( "buffer overflow (state=%u, buf_sz=%lu, line_nr=%lu)", enc->state, buf_sz, line_nr ));
}

#define ENCODE_FN                                                            \
  ulong                                                                      \
  fd_txncache_writer_serialize( fd_txncache_writer_t * enc,                  \
                                uchar out_buf[ FD_TXNCACHE_WRITER_BUF_MIN ], \
                                ulong buf_sz )
#define PREP                                                              \
  uchar * p  = out_buf;                                                   \
  uchar * p1 __attribute__((unused)) = out_buf+buf_sz;
#define PUSH_VAL( t, n )                                                  \
  FD_STORE( t, __extension__({                                            \
    if( FD_UNLIKELY( p+sizeof(t) > p1 ) ) fail( enc, buf_sz, __LINE__ );  \
    uchar * ret = p;                                                      \
    p += sizeof(t);                                                       \
    ret;                                                                  \
  }), (n) )
#define CAN_PUSH(sz) ( p+(sz) <= p1 )
#define RET_EXPR (ulong)( p - out_buf )
#include "fd_txncache_encoder.c"

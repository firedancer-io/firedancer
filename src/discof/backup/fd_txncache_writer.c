#include "fd_txncache_writer.h"
#include "../../flamenco/runtime/fd_txncache_private.h"
#include "../../util/fd_util.h"

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

#define STATE_HEADER    1
#define STATE_BLOCKHASH 2
#define STATE_TXNS      3
#define STATE_DONE      4
#define STATE_INIT STATE_HEADER

static int
txncache_txn_on_snapshot_root( fd_txncache_writer_tc_t const * tc,
                               ulong                           snapshot_root_idx,
                               fd_txncache_single_txn_t const * txn ) {
  if( FD_UNLIKELY( snapshot_root_idx>=tc->shmem->active_slots_max ) ) return 0;
  if( FD_UNLIKELY( txn->fork_id.val>=tc->shmem->active_slots_max ) ) return 0;

  fd_txncache_blockcache_shmem_t const * txn_fork = &tc->blockcache_shmem_pool[ txn->fork_id.val ];
  if( FD_UNLIKELY( txn_fork->frozen<0 || txn_fork->generation!=txn->generation ) ) return 0;

  return txn->fork_id.val==snapshot_root_idx ||
         descends_set_test( tc->blockcache_pool[ snapshot_root_idx ].descends, txn->fork_id.val );
}

static ulong
txncache_count_txns( fd_txncache_writer_tc_t const * tc,
                     ulong                           snapshot_root_idx,
                     ulong                           bc_idx ) {
  fd_txncache_blockcache_shmem_t const * bc_shmem = &tc->blockcache_shmem_pool[ bc_idx ];
  fd_txncache_writer_blockcache_t const * bc      = &tc->blockcache_pool[ bc_idx ];
  ulong cnt = 0UL;
  for( ushort p=0; p<bc_shmem->pages_cnt; p++ ) {
    fd_txncache_txnpage_t const * page = &tc->txnpages[ bc->pages[ p ] ];
    ulong txns_in_page = FD_TXNCACHE_TXNS_PER_PAGE - (ulong)page->free;
    for( ulong t=0UL; t<txns_in_page; t++ ) {
      fd_txncache_single_txn_t const * txn = page->txns[ t ];
      if( FD_LIKELY( txncache_txn_on_snapshot_root( tc, snapshot_root_idx, txn ) ) ) cnt++;
    }
  }
  return cnt;
}

fd_txncache_writer_t *
fd_txncache_writer_init( fd_txncache_writer_t * writer,
                         fd_txncache_t *        tc,
                         ulong                  slot ) {
  fd_txncache_writer_tc_t const * ltc = (fd_txncache_writer_tc_t const *)tc;
  writer->state      = STATE_INIT;
  writer->tc         = tc;
  writer->slot       = slot;
  writer->snapshot_root_idx = root_slist_is_empty( ltc->shmem->root_ll, ltc->blockcache_shmem_pool ) ?
                              ULONG_MAX :
                              root_slist_idx_peek_tail( ltc->shmem->root_ll, ltc->blockcache_shmem_pool );
  writer->root_iter  = root_slist_iter_init( ltc->shmem->root_ll, ltc->blockcache_shmem_pool );
  writer->page_idx   = 0UL;
  writer->txn_idx    = 0UL;
  writer->txns_in_page = 0UL;
  return writer;
}

/* Size estimate */

#define ENCODE_FN     static ulong txncache_estimate( fd_txncache_writer_t * enc )
#define PREP          ulong sz = 0UL;
#define PUSH_VAL(t,n) do { sz += sizeof(t); (void)(n); } while(0)
#define RET_EXPR      sz
#include "fd_txncache_encoder.c"

ulong
fd_txncache_writer_serialized_sz( fd_txncache_t * tc,
                                  ulong           slot ) {
  fd_txncache_writer_t writer[1];
  fd_txncache_writer_init( writer, tc, slot );
  ulong sz = 0UL;
  for(;;) {
    ulong chunk = txncache_estimate( writer );
    if( FD_UNLIKELY( !chunk ) ) break;
    sz += chunk;
  }
  return sz;
}

/* Actual encoder */

__attribute__((cold,noreturn,unused))
static void fail( fd_txncache_writer_t const * enc,
                  ulong buf_sz,
                  ulong line_nr ) {
  FD_LOG_ERR(( "buffer overflow (state=%u, buf_sz=%lu, line_nr=%lu)", enc->state, buf_sz, line_nr ));
}

#define ENCODE_FN                                                         \
  ulong                                                                   \
  fd_txncache_writer_serialize( fd_txncache_writer_t * enc,               \
                                uchar out_buf[ FD_TXNCACHE_WRITER_BUF_MIN ], \
                                ulong buf_sz )
#define PREP                                                              \
  uchar * p  = out_buf;                                                   \
  uchar * p1 __attribute__((unused)) = out_buf+buf_sz;
#define PUSH_VAL( t, n )                                                  \
  FD_STORE( t, __extension__({                                            \
    if( FD_UNLIKELY( p+sizeof(t) > p1 ) ) fail( enc, buf_sz, __LINE__ ); \
    uchar * ret = p;                                                      \
    p += sizeof(t);                                                       \
    ret;                                                                  \
  }), (n) )
#define RET_EXPR (ulong)( p - out_buf )
#include "fd_txncache_encoder.c"

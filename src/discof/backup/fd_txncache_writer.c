#include "fd_txncache_writer.h"
#include "../../util/fd_util.h"

#define STATE_SLOT_DELTA 1
#define STATE_DONE       2
#define STATE_INIT STATE_SLOT_DELTA

fd_txncache_writer_t *
fd_txncache_writer_init( fd_txncache_writer_t * writer,
                         fd_txncache_t *        tc,
                         ulong                  slot ) {
  writer->state = STATE_INIT;
  writer->tc    = tc;
  writer->slot  = slot;
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
    /* compile time bounds check elide */                                 \
    if( FD_UNLIKELY( p+sizeof(t) > p1 ) ) fail( enc, buf_sz, __LINE__ ); \
    uchar * ret = p;                                                      \
    p += sizeof(t);                                                       \
    ret;                                                                  \
  }), (n) )
#define RET_EXPR (ulong)( p - out_buf )
#include "fd_txncache_encoder.c"
